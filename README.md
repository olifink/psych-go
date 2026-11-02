# psych-go

End-to-End Encrypted (E2EE), zero-knowledge terminal pipe and blind WebSocket relay in Go.

## Overview

`psych` provides an ephemeral, zero-knowledge message pipe between two peer nodes (`initiator` and `joiner`) mediated by an untrusted blind relay server.

- **Cryptographic Primitives**:
  - Key Agreement: X25519 (ECDH over Curve25519) & SPAKE2 (PAKE over Edwards25519)
  - Key Derivation: HKDF-SHA256 (`psych-v1-session-key`)
  - Authenticated Encryption: ChaCha20-Poly1305 (RFC 8439 / AEAD)
  - Nonces: 12-byte directional nonces with monotonic 64-bit sequence counters
- **Pairing Options**:
  - **Terminal QR Code**: `psych://pair?v=1&sid=...` rendered via ANSI Unicode half-blocks.
  - **Short Pairing Code**: 8-character human-friendly code (e.g. `7K4M-9P2X`, Crockford Base32) authenticated via SPAKE2 PAKE with offline attack immunity.
- **Relay**: In-memory, zero-knowledge blind WebSocket relay with max 2 peers per room, automatic teardown, and `/healthz` health checks.
- **Piping**: Unix-pipe friendly `send` and `recv` modes for automated scripting.

## Installation

### Quick Install (Linux & macOS)

Install the latest pre-compiled static binary via `curl`:

```bash
curl -fsSL https://raw.githubusercontent.com/olifink/psych-go/main/install.sh | sh
```

Or install a specific version to a custom directory:

```bash
VERSION=v1.0.0 BINDIR=$HOME/.local/bin curl -fsSL https://raw.githubusercontent.com/olifink/psych-go/main/install.sh | sh
```

### Pre-built Binaries

Pre-compiled static binaries for Linux, macOS, and Windows are available for each release on the [GitHub Releases](https://github.com/olifink/psych-go/releases) page.

### Build from Source

```bash
git clone https://github.com/olifink/psych-go.git
cd psych-go
CGO_ENABLED=0 go build -ldflags="-s -w" -o psych ./cmd/psych
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

Initiates a session, prints a compact terminal QR code and an 8-character pairing code:

```bash
psych session [--relay ws://localhost:8080/ws]
```

### 3. Join an Existing Session (Joiner)

Connect using either the **8-character short code** or full pairing URI:

```bash
# Using 8-character short code
psych join 7K4M-9P2X

# Or using full pairing URI (enclosed in quotes)
psych join 'psych://pair?v=1&sid=...&pub=...'
```

### 4. Non-Interactive Scripting / Piping

**Sender piping data into a session:**
```bash
# Pipe via 8-character code
echo "secret token" | psych send 7K4M-9P2X

# Or pipe via pairing URI
echo "secret token" | psych send 'psych://pair?...'
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
