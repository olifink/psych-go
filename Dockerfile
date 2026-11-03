# Multi-stage Dockerfile for PSYCH Relay Server
# Produces a minimal, secure, non-root container image.

# --- Stage 1: Builder ---
FROM --platform=$BUILDPLATFORM golang:alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Leverage Go module caching
COPY go.mod go.sum ./
COPY vendor/ ./vendor/

# Copy full source tree
COPY . .

# Build static binary (supporting cross-compilation via Buildx TARGETOS / TARGETARCH)
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=1.0.0
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w -X main.version=v${VERSION}" \
    -o /bin/psych ./cmd/psych

# --- Stage 2: Minimal Runtime ---
FROM alpine:3.21

# Install ca-certificates and wget for health checks
RUN apk --no-cache add ca-certificates tzdata \
    && addgroup -g 10001 -S appgroup \
    && adduser -u 10001 -S appuser -G appgroup

COPY --from=builder /bin/psych /usr/local/bin/psych

# Use unprivileged user
USER 10001:10001

# Expose default HTTP/WebSocket port
EXPOSE 8080

# Environment defaults
ENV PORT=8080 \
    HOST=0.0.0.0

# Native health check against /healthz
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/psych"]
CMD ["server"]
