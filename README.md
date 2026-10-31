# psych-go

End-to-End Encrypted (E2EE), zero-knowledge terminal pipe and blind WebSocket relay in Go.

## Overview

`psych` provides an ephemeral, zero-knowledge message pipe between two peer nodes (`initiator` and `joiner`) mediated by an untrusted blind relay server.

- **Cryptographic Primitives**:
  - Key Agreement: X25519 (ECDH over Curve25519)
  - Key Derivation: HKDF-SHA256 (`psych-v1-session-key`)
  - Authenticated Encryption: ChaCha20-Poly1305 (RFC 8439 / AEAD)
  - Nonces: 12-byte directional nonces with monotonic 64-bit sequence counters
- **Pairing**: `psych://pair?v=1&sid=...&relay=...&pub=...` encoded as an ANSI half-block terminal QR code.
- **Relay**: In-memory, zero-knowledge blind WebSocket relay with max 2 peers per room, automatic teardown, and `/healthz` health checks.
- **Piping**: Unix-pipe friendly `send` and `recv` modes for automated scripting.

## Installation

```bash
go build -o psych ./cmd/psych
```

## CLI Usage

### 1. Relay Server

Start an ephemeral blind WebSocket relay server:

```bash
psych server [--port 8080] [--host 0.0.0.0]
```

Health check:
```bash
curl http://localhost:8080/healthz
```

### 2. Interactive Session (Initiator)

Initiates a session, prints a compact terminal QR code and fallback URI, and enters encrypted chat mode:

```bash
psych session [--relay ws://localhost:8080/ws]
```

### 3. Join an Existing Session (Joiner)

Connects to a session using the pairing URI or SID:

```bash
psych join <pairing-uri-or-sid> [--pub <initiator-pubkey>] [--relay <relay-url>]
```

### 4. Non-Interactive Scripting / Piping

**Sender piping data into a session:**
```bash
echo "secret token" | psych send <pairing-uri-or-sid>
```

**Receiver dumping incoming payload to stdout:**
```bash
psych recv [--relay ws://...]
```

## Running Tests

Run the comprehensive test suite (including cryptographic vector verification and end-to-end integration tests) offline without external dependencies:

```bash
go test -v -count=1 ./...
```

## Specifications

- [PROTOCOL.md](PROTOCOL.md): Wire format, cryptography, nonces, and relay rules.
- [SPEC.md](SPEC.md): Deliverable architecture and CLI commands.
