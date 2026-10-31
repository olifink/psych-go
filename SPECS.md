# Agent Implementation Brief: `psych`

## 1. Objective
Implement `psych`, a zero-dependency (outside standard vetted libraries) CLI utility and relay server written in Go. The tool facilitates end-to-end encrypted (E2EE) data transfer between headless terminal environments and external clients (such as Android or another CLI instance).

This phase focuses on the **Go unified binary**, enabling local and remote manual testing and automated integration verification without an Android client.

---

## 2. Deliverable Architecture
The single Go binary (`psych`) must provide two primary operational modes:
1. **Server Mode (`psych server`)**: An ephemeral, blind WebSocket relay.
2. **Client Modes**: Initiating sessions, pairing, sending text/clips, and continuous chat/listen loops.

Refer to `PROTOCOL.md` for all wire protocol rules, cryptographic primitives, and handshake definitions.

---

## 3. CLI Command Structure

The agent has freedom in internal package structuring, but the binary CLI interface must support the following surface:

### 3.1 Relay Server
```bash
psych server [--port 8080] [--host 0.0.0.0]
```

 * Starts an in-memory WebSocket relay matching Section 3 of PROTOCOL.md.
 * Provides an HTTP endpoint /healthz returning 200 OK.
 * Can be run locally or deployed directly into Google Cloud Run / Docker.


### 3.2 Initiator (Listen / Receive Session)

```bash
psych session [--relay ws://localhost:8080/ws]
```

 * Generates an ephemeral X25519 keypair and random sid.
 * Renders an ANSI UTF-8 block QR code to standard error/terminal using psych://pair?... URI format.
 * Prints the raw pairing URI string as a text fallback.
 * Connects to the relay and blocks until a peer joins.
 * Enters interactive bidirectional chat/message mode once the handshake completes.

### 3.3 Joiner (Connect to an Existing Session)

```bash
psych join <pairing-uri-or-sid> [--pub <initiator-pubkey>] [--relay <relay-url>]
```

 * Connects to the relay as the secondary peer.
 * Performs handshake, derives shared key, and enters interactive chat/message mode.


### 3.4 Pipe / One-Shot Modes (Scripting Friendly)

The agent should support stdin/stdout piping for non-interactive automation:

* Sender piping data to an established or ephemeral session

```bash
echo "secret token" | psych send <pairing-uri-or-sid>
```

* Receiver dumping incoming payload to stdout and exiting

```bash
psych recv [--relay ws://...]
```

## 4. Key Implementation Constraints & Guidance

### 4.1 Cryptography

 * Use Go's standard or well-maintained extended libraries:
   * crypto/ecdh (Go standard library crypto/ecdh.X25519() is preferred).
   * golang.org/x/crypto/hkdf.
   * golang.org/x/crypto/chacha20poly1305.
 * Avoid bloated dependencies or external CGO bindings. Must compile statically with CGO_ENABLED=0.

### 4.2 Terminal QR Code Rendering
 * Use an established Go QR library capable of rendering half-block Unicode characters (▀, ▄) so the QR code fits neatly in standard 80x24 terminal windows (e.g., github.com/skip2/go-qrcode or similar).
4.3 Relay State Management
 * Relay state must be entirely in-memory: map[string]*Room protected by a sync.RWMutex.
 * Ensure proper cleanup and avoidance of memory leaks: when both sockets in a room close, remove the room from the map.
 * Handle sudden socket closures, network drops, and ping/pong keep-alives cleanly.

## 5. Verification & Testing Requirements
The agent must include comprehensive automated tests:
 * Unit Tests (crypto_test.go):
   * Verify ECDH key agreement matches known vector properties.
   * Verify ChaCha20-Poly1305 encryption, decryption, and authentication failure on tampered ciphertext.
   * Verify nonce generator monotonicity and directional prefix separation.
 * Integration Test (e2e_test.go):
   * Programmatically start a test psych server on an ephemeral port.
   * Instantiate an initiator client and a joiner client in separate goroutines.
   * Perform the handshake, send bidirectional encrypted messages, verify plaintext delivery, and cleanly close the connections.

## 6. Suggested File Layout (Discretionary)

```
├── PROTOCOL.md
├── SPEC.md
├── cmd/
│   └── psych/
│       └── main.go
├── internal/
│   ├── crypto/       # Key agreement, KDF, AEAD wrappers
│   ├── protocol/     # Envelope serialization, nonces, message types
│   ├── relay/        # WebSocket server & room management
│   └── terminal/     # QR rendering and console I/O
├── go.mod
└── go.sum
```
