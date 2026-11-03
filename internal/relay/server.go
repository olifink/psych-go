package relay

import (
	"context"
	_ "embed"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"psych/internal/protocol"
)

//go:embed static/install.sh
var embeddedInstallScript []byte

//go:embed static/index.html
var embeddedIndexHTML []byte

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 10 * 1024 * 1024 // 10MB max message size for file frames
	sendBufferSize = 64
)

type peerMsg struct {
	msgType int
	data    []byte
}

// Peer represents an active WebSocket client connected to a room.
type Peer struct {
	conn     *websocket.Conn
	send     chan peerMsg
	done     chan struct{}
	onceDone sync.Once
}

func newPeer(conn *websocket.Conn) *Peer {
	return &Peer{
		conn: conn,
		send: make(chan peerMsg, sendBufferSize),
		done: make(chan struct{}),
	}
}

func (p *Peer) close() {
	p.onceDone.Do(func() {
		close(p.done)
		_ = p.conn.Close()
	})
}

// Room represents an ephemeral message relay room identified strictly by session ID.
type Room struct {
	mu              sync.Mutex
	sid             string
	peers           []*Peer
	handshakeBuffer *peerMsg // Buffers up to 1 handshake message when 1 peer connected
	server          *Server
}

// Server is an in-memory, zero-knowledge blind WebSocket relay.
type Server struct {
	mu       sync.RWMutex
	rooms    map[string]*Room
	upgrader websocket.Upgrader
	server   *http.Server
	listener net.Listener
}

// NewServer initializes a new RelayServer instance.
func NewServer() *Server {
	s := &Server{
		rooms: make(map[string]*Room),
	}
	s.upgrader = websocket.Upgrader{
		ReadBufferSize:  64 * 1024,
		WriteBufferSize: 64 * 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins for zero-knowledge CLI/reverse proxy pairing
		},
	}
	return s
}

// Handler returns the HTTP handler exposing /, /install.sh, /healthz, and /ws.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/ws", s.handleWebSocket)
	mux.HandleFunc("/install.sh", s.handleInstallScript)
	mux.HandleFunc("/install", s.handleInstallScript)
	mux.HandleFunc("/", s.handleIndex)
	return mux
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Determine host and scheme (supporting reverse proxy headers like X-Forwarded-Proto)
	host := r.Host
	scheme := "https"
	wsScheme := "wss"

	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "http" || (proto == "" && r.TLS == nil && (strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "127.0.0.1"))) {
		scheme = "http"
		wsScheme = "ws"
	}

	baseURL := fmt.Sprintf("%s://%s", scheme, host)
	relayURL := fmt.Sprintf("%s://%s/ws", wsScheme, host)

	page := strings.ReplaceAll(string(embeddedIndexHTML), "{{.BaseURL}}", baseURL)
	page = strings.ReplaceAll(page, "{{.RelayURL}}", relayURL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(page))
}

func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(embeddedInstallScript)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK\n"))
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("sid")
	if sid == "" || protocol.ValidateSessionID(sid) != nil {
		http.Error(w, "Invalid or missing 'sid' query parameter", http.StatusBadRequest)
		return
	}

	// Rule 2: A room MAY contain at most 2 active WebSocket connections.
	// Reject with HTTP 409 Conflict if room already full.
	s.mu.Lock()
	room, exists := s.rooms[sid]
	if exists {
		room.mu.Lock()
		if len(room.peers) >= 2 {
			room.mu.Unlock()
			s.mu.Unlock()
			http.Error(w, "Room Full", http.StatusConflict)
			return
		}
		room.mu.Unlock()
	} else {
		room = &Room{
			sid:    sid,
			peers:  make([]*Peer, 0, 2),
			server: s,
		}
		s.rooms[sid] = room
	}
	s.mu.Unlock()

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	peer := newPeer(conn)

	// Register peer into the room
	room.mu.Lock()
	if len(room.peers) >= 2 {
		// Rare race condition: reject with WS status 4003 Room Full
		room.mu.Unlock()
		closeMsg := websocket.FormatCloseMessage(4003, "Room Full")
		_ = conn.WriteControl(websocket.CloseMessage, closeMsg, time.Now().Add(time.Second))
		_ = conn.Close()
		return
	}

	room.peers = append(room.peers, peer)

	// If a handshake message was buffered waiting for this peer, flush it immediately!
	if room.handshakeBuffer != nil && len(room.peers) == 2 {
		buffered := *room.handshakeBuffer
		room.handshakeBuffer = nil
		select {
		case peer.send <- buffered:
		default:
		}
	}
	room.mu.Unlock()

	// Start write pump in background goroutine
	go s.writePump(peer)

	// Run read pump in current goroutine
	s.readPump(room, peer)
}

func (s *Server) writePump(peer *Peer) {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		peer.close()
	}()

	for {
		select {
		case <-peer.done:
			return
		case msg, ok := <-peer.send:
			if !ok {
				_ = peer.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			_ = peer.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := peer.conn.WriteMessage(msg.msgType, msg.data); err != nil {
				return
			}
		case <-ticker.C:
			_ = peer.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := peer.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (s *Server) readPump(room *Room, peer *Peer) {
	defer func() {
		peer.close()
		s.removePeer(room, peer)
	}()

	peer.conn.SetReadLimit(maxMessageSize)
	_ = peer.conn.SetReadDeadline(time.Now().Add(pongWait))
	peer.conn.SetPongHandler(func(string) error {
		_ = peer.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		msgType, data, err := peer.conn.ReadMessage()
		if err != nil {
			break
		}

		room.mu.Lock()
		// Find recipient (the other peer in room)
		var recipient *Peer
		for _, p := range room.peers {
			if p != peer {
				recipient = p
				break
			}
		}

		if recipient != nil {
			// Rule 4: Relay forwards frame unchanged to the other peer
			select {
			case recipient.send <- peerMsg{msgType: msgType, data: data}:
			default:
				// If recipient buffer is full, drop frame
			}
		} else {
			// Rule 5: If only one peer is connected, the relay MAY buffer up to 1 handshake message;
			// all other non-handshake frames arriving before peer arrival SHOULD be discarded.
			if protocol.IsHandshakeFrame(data) || protocol.IsPAKEInitFrame(data) {
				room.handshakeBuffer = &peerMsg{msgType: msgType, data: data}
			}
		}
		room.mu.Unlock()
	}
}

func (s *Server) removePeer(room *Room, peer *Peer) {
	room.mu.Lock()
	newPeers := make([]*Peer, 0, len(room.peers))
	for _, p := range room.peers {
		if p != peer {
			newPeers = append(newPeers, p)
		}
	}
	room.peers = newPeers
	remaining := len(room.peers)
	room.mu.Unlock()

	// Rule 6: When both peers disconnect, the room and all ephemeral state MUST be deleted immediately.
	if remaining == 0 {
		s.mu.Lock()
		if r, ok := s.rooms[room.sid]; ok {
			r.mu.Lock()
			if len(r.peers) == 0 {
				delete(s.rooms, room.sid)
			}
			r.mu.Unlock()
		}
		s.mu.Unlock()
	}
}

// RoomCount returns the current number of active rooms.
func (s *Server) RoomCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.rooms)
}

// Start starts the HTTP/WebSocket server listening on host:port.
func (s *Server) Start(host string, port int) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = listener

	s.server = &http.Server{
		Handler:      s.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	return s.server.Serve(listener)
}

// Addr returns the network listener address, useful when using port 0.
func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}

// Close gracefully stops the relay server.
func (s *Server) Close() error {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.server.Shutdown(ctx)
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.mu.Lock()
	for _, room := range s.rooms {
		room.mu.Lock()
		for _, peer := range room.peers {
			peer.close()
		}
		room.mu.Unlock()
	}
	s.rooms = make(map[string]*Room)
	s.mu.Unlock()
	return nil
}
