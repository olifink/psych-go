package client

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"psych/internal/crypto"
	"psych/internal/protocol"
	"psych/internal/terminal"
	"strings"
	"time"
)

// StartInitiatorSession runs an interactive initiator session.
func StartInitiatorSession(relayURL string, in io.Reader, out io.Writer, errOut io.Writer) error {
	sid, err := crypto.GenerateSessionID()
	if err != nil {
		return fmt.Errorf("failed to generate session ID: %w", err)
	}

	privKey, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}
	pubHex := hex.EncodeToString(privKey.PublicKey().Bytes())

	uri := protocol.BuildPairingURI(sid, relayURL, pubHex)
	terminal.PrintPairingPrompt(errOut, uri)

	client, err := ConnectInitiator(relayURL, sid, privKey)
	if err != nil {
		return fmt.Errorf("initiator connection error: %w", err)
	}
	defer client.Close()

	fmt.Fprintln(errOut, "[+] Peer paired successfully! Entering secure E2EE chat mode. (Ctrl+D to exit)")
	return RunChat(client, in, out, errOut)
}

// StartJoinerSession runs an interactive joiner session.
func StartJoinerSession(pairingTarget string, defaultRelay string, pubFlag string, in io.Reader, out io.Writer, errOut io.Writer) error {
	info, err := protocol.ResolvePairingTarget(pairingTarget, defaultRelay, pubFlag)
	if err != nil {
		return err
	}

	privKey, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}

	fmt.Fprintf(errOut, "Connecting to relay %s for session %s...\n", info.RelayURL, info.SessionID)

	client, err := ConnectJoiner(info.RelayURL, info.SessionID, info.InitiatorPub, privKey)
	if err != nil {
		return fmt.Errorf("joiner connection error: %w", err)
	}
	defer client.Close()

	fmt.Fprintln(errOut, "[+] Connected to peer! Entering secure E2EE chat mode. (Ctrl+D to exit)")
	return RunChat(client, in, out, errOut)
}

// RunSend implements the one-shot scripting sender mode.
func RunSend(pairingTarget string, defaultRelay string, pubFlag string, in io.Reader) error {
	info, err := protocol.ResolvePairingTarget(pairingTarget, defaultRelay, pubFlag)
	if err != nil {
		return err
	}

	data, err := io.ReadAll(in)
	if err != nil {
		return fmt.Errorf("failed to read from input: %w", err)
	}

	privKey, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}

	client, err := ConnectJoiner(info.RelayURL, info.SessionID, info.InitiatorPub, privKey)
	if err != nil {
		return fmt.Errorf("send connection error: %w", err)
	}
	defer client.Close()

	if err := client.SendText(string(data)); err != nil {
		return fmt.Errorf("failed to send payload: %w", err)
	}

	// Brief pause to allow relay to deliver frame before closing
	time.Sleep(100 * time.Millisecond)
	return nil
}

// RunRecv implements the one-shot scripting receiver mode.
func RunRecv(relayURL string, out io.Writer, errOut io.Writer) error {
	sid, err := crypto.GenerateSessionID()
	if err != nil {
		return fmt.Errorf("failed to generate session ID: %w", err)
	}

	privKey, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}
	pubHex := hex.EncodeToString(privKey.PublicKey().Bytes())

	uri := protocol.BuildPairingURI(sid, relayURL, pubHex)
	terminal.PrintPairingPrompt(errOut, uri)

	client, err := ConnectInitiator(relayURL, sid, privKey)
	if err != nil {
		return fmt.Errorf("recv connection error: %w", err)
	}
	defer client.Close()

	payload, err := client.ReadPayload()
	if err != nil {
		return fmt.Errorf("failed to receive payload: %w", err)
	}

	// Output payload body to stdout
	if strings.HasSuffix(payload.Body, "\n") {
		fmt.Fprint(out, payload.Body)
	} else {
		fmt.Fprintln(out, payload.Body)
	}
	return nil
}

// RunChat runs a bidirectional chat loop between local reader/writer and the remote peer.
func RunChat(client *Client, in io.Reader, out io.Writer, errOut io.Writer) error {
	readErrCh := make(chan error, 1)

	// Background reader for remote messages
	go func() {
		for {
			payload, err := client.ReadPayload()
			if err != nil {
				readErrCh <- err
				return
			}

			switch payload.Type {
			case protocol.TypeText:
				fmt.Fprintf(out, "[Peer] %s\n", payload.Body)
			case protocol.TypePing:
				_ = client.SendPayload(protocol.NewPongMessage())
			case protocol.TypePong:
				// Keepalive received
			default:
				fmt.Fprintf(out, "[Peer (%s)] %s\n", payload.Type, payload.Body)
			}
		}
	}()

	// Foreground scanner for local input
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		text := scanner.Text()
		if err := client.SendText(text); err != nil {
			return fmt.Errorf("send message failed: %w", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("input read error: %w", err)
	}

	return nil
}
