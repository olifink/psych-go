package relay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"psych/internal/protocol"
)

func TestHealthz(t *testing.T) {
	srv := NewServer()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "OK") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestRelayRoomLimitAndRejection(t *testing.T) {
	srv := NewServer()
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http") + "/ws?sid=0123456789abcdef0123456789abcdef"

	// Connect Peer 1
	c1, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("peer 1 dial failed: %v", err)
	}
	defer c1.Close()

	// Connect Peer 2
	c2, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("peer 2 dial failed: %v", err)
	}
	defer c2.Close()

	// Attempt to connect Peer 3 - must be rejected with HTTP 409 Conflict
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("expected peer 3 connection to be rejected, but it succeeded")
	}
	if resp != nil && resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected HTTP 409 Conflict for peer 3, got %d", resp.StatusCode)
	}
}

func TestRelayMessageForwarding(t *testing.T) {
	srv := NewServer()
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http") + "/ws?sid=aabbccddeeff00112233445566778899"

	c1, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("peer 1 dial: %v", err)
	}
	defer c1.Close()

	c2, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("peer 2 dial: %v", err)
	}
	defer c2.Close()

	testMsg := "hello from peer 1"
	if err := c1.WriteMessage(websocket.TextMessage, []byte(testMsg)); err != nil {
		t.Fatalf("peer 1 write: %v", err)
	}

	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	msgType, data, err := c2.ReadMessage()
	if err != nil {
		t.Fatalf("peer 2 read: %v", err)
	}
	if msgType != websocket.TextMessage || string(data) != testMsg {
		t.Fatalf("unexpected message received: got %q, want %q", string(data), testMsg)
	}
}

func TestRelayHandshakeBuffering(t *testing.T) {
	srv := NewServer()
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http") + "/ws?sid=11223344556677889900aabbccddeeff"

	// Connect Peer 1
	c1, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("peer 1 dial: %v", err)
	}
	defer c1.Close()

	// Peer 1 sends handshake message while Peer 2 is not yet connected
	hs := protocol.NewHandshakeMessage("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	hsBytes, _ := json.Marshal(hs)

	if err := c1.WriteMessage(websocket.TextMessage, hsBytes); err != nil {
		t.Fatalf("peer 1 write handshake: %v", err)
	}

	// Give server brief moment to buffer
	time.Sleep(50 * time.Millisecond)

	// Now Peer 2 connects
	c2, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("peer 2 dial: %v", err)
	}
	defer c2.Close()

	// Peer 2 should immediately receive the buffered handshake message
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, data, err := c2.ReadMessage()
	if err != nil {
		t.Fatalf("peer 2 read buffered handshake: %v", err)
	}

	var received protocol.HandshakeMessage
	if err := json.Unmarshal(data, &received); err != nil {
		t.Fatalf("unmarshal received handshake: %v", err)
	}
	if received.Pub != hs.Pub {
		t.Fatalf("buffered handshake pub mismatch: got %s, want %s", received.Pub, hs.Pub)
	}
}

func TestRelayRoomCleanupOnDisconnect(t *testing.T) {
	srv := NewServer()
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http") + "/ws?sid=deadbeefdeadbeefdeadbeefdeadbeef"

	c1, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("peer 1 dial: %v", err)
	}
	c2, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("peer 2 dial: %v", err)
	}

	if srv.RoomCount() != 1 {
		t.Fatalf("expected 1 active room, got %d", srv.RoomCount())
	}

	// Close both peers
	_ = c1.Close()
	_ = c2.Close()

	// Wait for cleanup
	time.Sleep(100 * time.Millisecond)

	if srv.RoomCount() != 0 {
		t.Fatalf("expected 0 active rooms after both disconnected, got %d", srv.RoomCount())
	}
}

func TestLandingPageServing(t *testing.T) {
	srv := NewServer()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "psych.lemonslice.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d", rec.Code)
	}
	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Fatalf("expected text/html, got %s", contentType)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "PSYCH") {
		t.Fatalf("expected body to contain 'PSYCH'")
	}
	if !strings.Contains(body, "https://psych.lemonslice.com/install.sh") {
		t.Fatalf("expected body to contain replaced BaseURL, got:\n%s", body)
	}
	if !strings.Contains(body, "wss://psych.lemonslice.com/ws") {
		t.Fatalf("expected body to contain replaced RelayURL, got:\n%s", body)
	}
}

func TestInstallScriptServing(t *testing.T) {
	srv := NewServer()

	for _, path := range []string{"/install.sh", "/install"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()

		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("path %s: expected status 200 OK, got %d", path, rec.Code)
		}
		contentType := rec.Header().Get("Content-Type")
		if !strings.Contains(contentType, "text/x-shellscript") {
			t.Fatalf("path %s: expected text/x-shellscript, got %s", path, contentType)
		}
		if !strings.Contains(rec.Body.String(), "PSYCH installer script") {
			t.Fatalf("path %s: expected body to contain installer header", path)
		}
	}
}

func TestNotFound(t *testing.T) {
	srv := NewServer()
	req := httptest.NewRequest(http.MethodGet, "/unknown-page", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status 404 Not Found, got %d", rec.Code)
	}
}

func TestEmbeddedInstallScriptMatchesRoot(t *testing.T) {
	rootScript, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Skipf("cannot read ../../install.sh: %v", err)
	}
	if !bytes.Equal(rootScript, embeddedInstallScript) {
		t.Fatalf("embedded static/install.sh does not match root install.sh")
	}
}
