package main

import (
	"bytes"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"psych/internal/client"
	"psych/internal/crypto"
	"psych/internal/protocol"
	"psych/internal/relay"
)

// TestE2EIntegration verifies the complete initiator-joiner lifecycle over a live ephemeral relay.
func TestE2EIntegration(t *testing.T) {
	// 1. Programmatically start an in-memory relay server
	relayServer := relay.NewServer()
	httpSrv := httptest.NewServer(relayServer.Handler())
	defer httpSrv.Close()

	relayURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http") + "/ws"

	// 2. Generate initiator parameters
	sid, err := crypto.GenerateSessionID()
	if err != nil {
		t.Fatalf("generate sid: %v", err)
	}

	initiatorPriv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate initiator keypair: %v", err)
	}
	initiatorPubHex := hex.EncodeToString(initiatorPriv.PublicKey().Bytes())

	// Build pairing URI
	pairingURI := protocol.BuildPairingURI(sid, relayURL, initiatorPubHex)

	joinerPriv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate joiner keypair: %v", err)
	}

	var (
		initClient *client.Client
		joinClient *client.Client
		initErr    error
		joinErr    error
		wg         sync.WaitGroup
	)

	wg.Add(2)

	// Goroutine 1: Initiator connects and awaits peer handshake
	go func() {
		defer wg.Done()
		initClient, initErr = client.ConnectInitiator(relayURL, sid, initiatorPriv)
	}()

	// Brief sleep to simulate real-world sequence where initiator starts first
	time.Sleep(50 * time.Millisecond)

	// Goroutine 2: Joiner connects and performs handshake
	go func() {
		defer wg.Done()
		joinClient, joinErr = client.ConnectJoiner(relayURL, sid, initiatorPubHex, joinerPriv)
	}()

	wg.Wait()

	if initErr != nil {
		t.Fatalf("initiator connect/handshake failed: %v", initErr)
	}
	if joinErr != nil {
		t.Fatalf("joiner connect/handshake failed: %v", joinErr)
	}
	defer initClient.Close()
	defer joinClient.Close()

	// 3. Bidirectional Encrypted Message Exchange
	// Initiator -> Joiner
	msg1 := "Hello from Initiator! This is end-to-end encrypted."
	if err := initClient.SendText(msg1); err != nil {
		t.Fatalf("initiator send failed: %v", err)
	}

	recv1, err := joinClient.ReadPayload()
	if err != nil {
		t.Fatalf("joiner read failed: %v", err)
	}
	if recv1.Body != msg1 {
		t.Fatalf("joiner received body mismatch: got %q, want %q", recv1.Body, msg1)
	}
	if recv1.Type != protocol.TypeText {
		t.Fatalf("unexpected message type: %s", recv1.Type)
	}

	// Joiner -> Initiator
	msg2 := "Acknowledged from Joiner. Zero-knowledge channel active."
	if err := joinClient.SendText(msg2); err != nil {
		t.Fatalf("joiner send failed: %v", err)
	}

	recv2, err := initClient.ReadPayload()
	if err != nil {
		t.Fatalf("initiator read failed: %v", err)
	}
	if recv2.Body != msg2 {
		t.Fatalf("initiator received body mismatch: got %q, want %q", recv2.Body, msg2)
	}

	// Exchange multiple messages to verify sequence counter increments
	for i := 0; i < 5; i++ {
		text := "Ping pong test message"
		if err := initClient.SendText(text); err != nil {
			t.Fatalf("send iteration %d failed: %v", i, err)
		}
		got, err := joinClient.ReadPayload()
		if err != nil {
			t.Fatalf("read iteration %d failed: %v", i, err)
		}
		if got.Body != text {
			t.Fatalf("iteration %d text mismatch", i)
		}
	}

	// 4. Verify clean closure
	_ = initClient.Close()
	_ = joinClient.Close()

	// Allow relay to process disconnections
	time.Sleep(100 * time.Millisecond)

	if relayServer.RoomCount() != 0 {
		t.Fatalf("expected 0 rooms after peer closure, got %d", relayServer.RoomCount())
	}

	_ = pairingURI
}

// TestE2EOneShotPiping verifies the scripting send/recv pipe modes.
func TestE2EOneShotPiping(t *testing.T) {
	relayServer := relay.NewServer()
	httpSrv := httptest.NewServer(relayServer.Handler())
	defer httpSrv.Close()

	relayURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http") + "/ws"

	secretPayload := "SUPER_SECRET_AUTHENTICATION_TOKEN_42\n"

	var outBuf bytes.Buffer
	var errBuf bytes.Buffer

	recvDone := make(chan error, 1)

	// Run receiver in background goroutine
	go func() {
		recvDone <- client.RunRecv(relayURL, &outBuf, &errBuf)
	}()

	// Wait until pairing prompt is printed to errBuf to extract pairing URI
	var uri string
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		content := errBuf.String()
		if idx := strings.Index(content, "psych://pair?"); idx != -1 {
			endIdx := strings.IndexAny(content[idx:], " \r\n\t")
			if endIdx != -1 {
				uri = content[idx : idx+endIdx]
			} else {
				uri = content[idx:]
			}
			break
		}
	}

	if uri == "" {
		t.Fatalf("timed out waiting for receiver to render pairing URI. Output: %s", errBuf.String())
	}

	// Sender pipes secretPayload into RunSend
	inBuf := bytes.NewBufferString(secretPayload)
	if err := client.RunSend(uri, relayURL, "", inBuf); err != nil {
		t.Fatalf("RunSend failed: %v", err)
	}

	// Wait for receiver to finish
	select {
	case err := <-recvDone:
		if err != nil {
			t.Fatalf("RunRecv failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for RunRecv to finish")
	}

	// Verify exact plaintext received on stdout buffer
	if outBuf.String() != secretPayload {
		t.Fatalf("received stdout mismatch: got %q, want %q", outBuf.String(), secretPayload)
	}
}
