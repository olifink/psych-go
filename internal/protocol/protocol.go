package protocol

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	ProtocolVersion = "1"
	PairingScheme   = "psych"
	PairingHost     = "pair"

	TypeHandshake = "handshake"
	TypeText      = "text"
	TypeFile      = "file"
	TypeOAuthReq  = "oauth_req"
	TypeOAuthResp = "oauth_resp"
	TypePing      = "ping"
	TypePong      = "pong"
)

var (
	ErrInvalidPairingURI    = errors.New("invalid pairing URI")
	ErrUnsupportedVersion   = errors.New("unsupported protocol version")
	ErrInvalidSessionID     = errors.New("invalid session ID (must be 32 hex chars)")
	ErrInvalidPublicKey     = errors.New("invalid public key (must be 64 hex chars)")
	ErrMissingRelayEndpoint = errors.New("missing relay endpoint URL")
	ErrInvalidEnvelope      = errors.New("invalid wire envelope")
	ErrInvalidPayload       = errors.New("invalid inner payload")
)

// PairingInfo encapsulates the parameters required to connect and establish a session.
type PairingInfo struct {
	Version      string `json:"v"`
	SessionID    string `json:"sid"`
	RelayURL     string `json:"relay"`
	InitiatorPub string `json:"pub"`
}

// BuildPairingURI formats a pairing URI matching Section 2 of PROTOCOL.md.
func BuildPairingURI(sid string, relayURL string, initiatorPubHex string) string {
	q := url.Values{}
	q.Set("v", ProtocolVersion)
	q.Set("sid", strings.ToLower(sid))
	q.Set("relay", relayURL)
	q.Set("pub", strings.ToLower(initiatorPubHex))

	return fmt.Sprintf("%s://%s?%s", PairingScheme, PairingHost, q.Encode())
}

// ParsePairingURI parses and validates a psych://pair?... URI.
func ParsePairingURI(rawURI string) (*PairingInfo, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPairingURI, err)
	}

	if u.Scheme != PairingScheme {
		return nil, fmt.Errorf("%w: unexpected scheme %q, expected %q", ErrInvalidPairingURI, u.Scheme, PairingScheme)
	}
	if u.Host != PairingHost && u.Opaque != PairingHost {
		return nil, fmt.Errorf("%w: unexpected host/target %q", ErrInvalidPairingURI, u.Host)
	}

	q := u.Query()
	v := q.Get("v")
	sid := strings.ToLower(q.Get("sid"))
	relayURL := q.Get("relay")
	pub := strings.ToLower(q.Get("pub"))

	// Detect if parameters were truncated because of unquoted '&' in shell
	if v == "" || sid == "" || relayURL == "" || pub == "" {
		if !strings.Contains(rawURI, "&") {
			return nil, fmt.Errorf("%w: URI appears truncated. In bash/zsh, unquoted '&' runs commands in the background. Enclose the URI in quotes:\n  psych join '%s'", ErrInvalidPairingURI, rawURI)
		}
	}

	if v != ProtocolVersion {
		return nil, fmt.Errorf("%w: got %q, expected %q", ErrUnsupportedVersion, v, ProtocolVersion)
	}

	if err := ValidateSessionID(sid); err != nil {
		return nil, err
	}

	if relayURL == "" {
		return nil, ErrMissingRelayEndpoint
	}

	if err := ValidatePublicKeyHex(pub); err != nil {
		return nil, err
	}

	return &PairingInfo{
		Version:      v,
		SessionID:    sid,
		RelayURL:     relayURL,
		InitiatorPub: pub,
	}, nil
}

// ResolvePairingTarget parses either a full pairing URI or a raw session ID with flag fallbacks.
func ResolvePairingTarget(target string, defaultRelay string, pubFlag string) (*PairingInfo, error) {
	trimmed := strings.TrimSpace(target)
	trimmed = strings.Trim(trimmed, "'\"")
	if strings.HasPrefix(trimmed, "psych://") || strings.HasPrefix(trimmed, "psych:") {
		info, err := ParsePairingURI(trimmed)
		if err != nil {
			return nil, err
		}
		// Allow flags to override if explicitly passed
		if pubFlag != "" {
			if err := ValidatePublicKeyHex(pubFlag); err != nil {
				return nil, err
			}
			info.InitiatorPub = strings.ToLower(pubFlag)
		}
		if defaultRelay != "" && info.RelayURL == "" {
			info.RelayURL = defaultRelay
		}
		return info, nil
	}

	// Treat as raw sid
	sid := strings.ToLower(trimmed)
	if err := ValidateSessionID(sid); err != nil {
		return nil, fmt.Errorf("%w: target is neither a valid psych:// URI nor a 32-character hex SID", err)
	}

	pub := strings.ToLower(strings.TrimSpace(pubFlag))
	if err := ValidatePublicKeyHex(pub); err != nil {
		return nil, fmt.Errorf("initiator public key must be provided via --pub flag when using raw SID: %w", err)
	}

	relay := strings.TrimSpace(defaultRelay)
	if relay == "" {
		return nil, ErrMissingRelayEndpoint
	}

	return &PairingInfo{
		Version:      ProtocolVersion,
		SessionID:    sid,
		RelayURL:     relay,
		InitiatorPub: pub,
	}, nil
}

// ValidateSessionID checks if sid is a 32-character lowercase hex string (16 raw bytes).
func ValidateSessionID(sid string) error {
	if len(sid) != 32 {
		return fmt.Errorf("%w: got length %d", ErrInvalidSessionID, len(sid))
	}
	b, err := hex.DecodeString(sid)
	if err != nil || len(b) != 16 {
		return ErrInvalidSessionID
	}
	return nil
}

// ValidatePublicKeyHex checks if pub is a 64-character lowercase hex string (32 raw bytes).
func ValidatePublicKeyHex(pub string) error {
	if len(pub) != 64 {
		return fmt.Errorf("%w: got length %d", ErrInvalidPublicKey, len(pub))
	}
	b, err := hex.DecodeString(pub)
	if err != nil || len(b) != 32 {
		return ErrInvalidPublicKey
	}
	return nil
}

// HandshakeMessage represents the unencrypted handshake JSON frame sent by Joiner to Initiator.
type HandshakeMessage struct {
	Type string `json:"type"`
	Pub  string `json:"pub"`
}

// NewHandshakeMessage constructs a HandshakeMessage with the joiner's hex-encoded public key.
func NewHandshakeMessage(pubHex string) *HandshakeMessage {
	return &HandshakeMessage{
		Type: TypeHandshake,
		Pub:  strings.ToLower(pubHex),
	}
}

// IsHandshakeFrame inspects raw JSON bytes to check if it's a handshake frame.
func IsHandshakeFrame(data []byte) bool {
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &probe); err == nil && probe.Type == TypeHandshake {
		return true
	}
	return false
}

// WireEnvelope represents the JSON envelope for all post-handshake encrypted communication.
type WireEnvelope struct {
	Seq        uint64 `json:"seq"`
	Nonce      string `json:"nonce"`      // Base64-encoded 12-byte nonce
	Ciphertext string `json:"ciphertext"` // Base64-encoded ciphertext + 16-byte Poly1305 tag
}

// NewWireEnvelope builds a WireEnvelope from sequence number, raw nonce bytes, and raw ciphertext+tag bytes.
func NewWireEnvelope(seq uint64, nonce []byte, ciphertextWithTag []byte) *WireEnvelope {
	return &WireEnvelope{
		Seq:        seq,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertextWithTag),
	}
}

// DecodeComponents returns the decoded raw nonce bytes and ciphertext bytes.
func (e *WireEnvelope) DecodeComponents() ([]byte, []byte, error) {
	nonce, err := base64.StdEncoding.DecodeString(e.Nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid base64 nonce: %v", ErrInvalidEnvelope, err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(e.Ciphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid base64 ciphertext: %v", ErrInvalidEnvelope, err)
	}
	return nonce, ciphertext, nil
}

// InnerPayload represents the decrypted UTF-8 JSON message content.
type InnerPayload struct {
	ID   string                 `json:"id"`
	TS   int64                  `json:"ts"`
	Type string                 `json:"type"`
	Body string                 `json:"body"`
	Meta map[string]interface{} `json:"meta"`
}

// generateUUIDv4 produces a standard UUIDv4 string.
func generateUUIDv4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// NewInnerPayload creates an InnerPayload with auto-generated UUIDv4 and current timestamp.
func NewInnerPayload(msgType string, body string, meta map[string]interface{}) *InnerPayload {
	if meta == nil {
		meta = make(map[string]interface{})
	}
	return &InnerPayload{
		ID:   generateUUIDv4(),
		TS:   time.Now().Unix(),
		Type: msgType,
		Body: body,
		Meta: meta,
	}
}

// NewTextMessage creates a text inner payload.
func NewTextMessage(text string) *InnerPayload {
	return NewInnerPayload(TypeText, text, nil)
}

// NewPingMessage creates a ping probe payload.
func NewPingMessage() *InnerPayload {
	return NewInnerPayload(TypePing, "", nil)
}

// NewPongMessage creates a pong probe payload.
func NewPongMessage() *InnerPayload {
	return NewInnerPayload(TypePong, "", nil)
}

// NewFileMessage creates a file data inner payload.
func NewFileMessage(filename string, mimeType string, data []byte) *InnerPayload {
	meta := map[string]interface{}{
		"filename": filename,
		"size":     len(data),
		"mime":     mimeType,
	}
	return NewInnerPayload(TypeFile, base64.StdEncoding.EncodeToString(data), meta)
}
