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

Install the latest pre-compiled static binary via `curl` from GitHub or your self-hosted relay:

```bash
# From GitHub
curl -fsSL https://raw.githubusercontent.com/olifink/psych-go/main/install.sh | sh

# Or directly from your public relay server
curl -fsSL https://psych.lemonslice.com/install.sh | sh
```

Or install a specific version to a custom directory:

```bash
VERSION=v1.0.0 BINDIR=$HOME/.local/bin curl -fsSL https://psych.lemonslice.com/install.sh | sh
```

### Pre-built Binaries

Pre-compiled static binaries for Linux, macOS, and Windows are available for each release on the [GitHub Releases](https://github.com/olifink/psych-go/releases) page.

### Build from Source

```bash
git clone https://github.com/olifink/psych-go.git
cd psych-go
CGO_ENABLED=0 go build -ldflags="-s -w" -o psych ./cmd/psych
```

## Docker Deployment (Public Relay)

Pre-built multi-architecture container images (`linux/amd64` and `linux/arm64`) are automatically published to the **GitHub Container Registry (GHCR)** on every release tag.

### 1. Run directly from GHCR

```bash
# Pull and run the latest release image
docker run -d \
  --name psych-relay \
  -p 8080:8080 \
  --restart unless-stopped \
  ghcr.io/olifink/psych-go:latest
```

Or run a specific release version:

```bash
docker run -d \
  --name psych-relay \
  -p 8080:8080 \
  --restart unless-stopped \
  ghcr.io/olifink/psych-go:v1.0.0
```

> **Note on Private Repositories**: If your repository or packages are private, authenticate Docker with a GitHub token (`read:packages` scope) before pulling:
> ```bash
> echo "$GITHUB_TOKEN" | docker login ghcr.io -u <GITHUB_USERNAME> --password-stdin
> ```

### 2. Run with Docker Compose

```bash
# Runs the pre-built GHCR image (or builds locally if --build is passed)
docker compose up -d
```

### 3. Build Locally

```bash
docker build -t psych-relay .
docker run -d --name psych-relay -p 8080:8080 --restart unless-stopped psych-relay
```

### Reverse Proxy & HTTPS (`psych.lemonslice.com`)

The embedded server exposes a built-in web portal, installer endpoint, health check, and blind WebSocket relay:
- `GET /`: Modern responsive web portal with quick-copy install commands and specs
- `GET /install.sh`: Embedded installer script for the `psych` CLI
- `GET /healthz`: Health status endpoint (`200 OK`)
- `GET /ws?sid=<id>`: Bidirectional blind WebSocket relay

**Caddy configuration:**
```caddy
psych.lemonslice.com {
    reverse_proxy 127.0.0.1:8080
}
```

**Nginx configuration:**
```nginx
server {
    server_name psych.lemonslice.com;
    listen 443 ssl http2;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

## CLI Usage

### Default Relay Environment Variable

Set `PSYCH_RELAY` in your shell profile (`~/.bashrc` or `~/.zshrc`) to avoid passing `--relay` to each command:

```bash
export PSYCH_RELAY="wss://psych.lemonslice.com/ws"
```

### 1. Relay Server

Start an ephemeral blind WebSocket relay server locally:

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
