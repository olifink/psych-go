package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildAndParsePairingURI(t *testing.T) {
	sid := "a1b2c3d4e5f60718293a4b5c6d7e8f90"
	relay := "ws://127.0.0.1:8080/ws"
	pub := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	uri := BuildPairingURI(sid, relay, pub)
	if !strings.HasPrefix(uri, "psych://pair?") {
		t.Fatalf("unexpected URI prefix: %s", uri)
	}

	info, err := ParsePairingURI(uri)
	if err != nil {
		t.Fatalf("failed to parse URI: %v", err)
	}

	if info.Version != "1" {
		t.Errorf("version mismatch: got %s, want 1", info.Version)
	}
	if info.SessionID != sid {
		t.Errorf("sid mismatch: got %s, want %s", info.SessionID, sid)
	}
	if info.RelayURL != relay {
		t.Errorf("relay mismatch: got %s, want %s", info.RelayURL, relay)
	}
	if info.InitiatorPub != pub {
		t.Errorf("pub mismatch: got %s, want %s", info.InitiatorPub, pub)
	}
}

func TestParsePairingURIInvalid(t *testing.T) {
	cases := []struct {
		name string
		uri  string
	}{
		{"wrong scheme", "http://pair?v=1&sid=a1b2c3d4e5f60718293a4b5c6d7e8f90&relay=ws://x&pub=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{"wrong version", "psych://pair?v=2&sid=a1b2c3d4e5f60718293a4b5c6d7e8f90&relay=ws://x&pub=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{"short sid", "psych://pair?v=1&sid=short&relay=ws://x&pub=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{"short pub", "psych://pair?v=1&sid=a1b2c3d4e5f60718293a4b5c6d7e8f90&relay=ws://x&pub=short"},
		{"missing relay", "psych://pair?v=1&sid=a1b2c3d4e5f60718293a4b5c6d7e8f90&pub=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePairingURI(tc.uri)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestResolvePairingTarget(t *testing.T) {
	sid := "a1b2c3d4e5f60718293a4b5c6d7e8f90"
	pub := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	relay := "ws://localhost:8080/ws"

	// From raw sid and flags
	info, err := ResolvePairingTarget(sid, relay, pub)
	if err != nil {
		t.Fatalf("resolve target failed: %v", err)
	}
	if info.SessionID != sid || info.InitiatorPub != pub || info.RelayURL != relay {
		t.Errorf("resolved mismatch: %+v", info)
	}

	// From full URI
	uri := BuildPairingURI(sid, relay, pub)
	info2, err := ResolvePairingTarget(uri, "", "")
	if err != nil {
		t.Fatalf("resolve URI target failed: %v", err)
	}
	if info2.SessionID != sid || info2.InitiatorPub != pub || info2.RelayURL != relay {
		t.Errorf("resolved URI mismatch: %+v", info2)
	}
}

func TestWireEnvelopeJSON(t *testing.T) {
	nonce := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	cipher := []byte("encrypted-data-with-tag")
	env := NewWireEnvelope(1, nonce, cipher)

	data, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	var parsed WireEnvelope
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	decNonce, decCipher, err := parsed.DecodeComponents()
	if err != nil {
		t.Fatal(err)
	}
	if string(decNonce) != string(nonce) {
		t.Fatalf("nonce mismatch")
	}
	if string(decCipher) != string(cipher) {
		t.Fatalf("ciphertext mismatch")
	}
}

func TestHandshakeProbe(t *testing.T) {
	hs := NewHandshakeMessage("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	data, _ := json.Marshal(hs)
	if !IsHandshakeFrame(data) {
		t.Fatal("expected IsHandshakeFrame to return true")
	}

	other := []byte(`{"type":"text","body":"hello"}`)
	if IsHandshakeFrame(other) {
		t.Fatal("expected IsHandshakeFrame to return false for text frame")
	}
}

func TestInnerPayloads(t *testing.T) {
	p := NewTextMessage("hello world")
	if p.Type != TypeText || p.Body != "hello world" || p.ID == "" || p.TS == 0 {
		t.Fatalf("invalid text payload: %+v", p)
	}

	f := NewFileMessage("test.txt", "text/plain", []byte("file-content"))
	if f.Type != TypeFile || f.Meta["filename"] != "test.txt" {
		t.Fatalf("invalid file payload: %+v", f)
	}
}
