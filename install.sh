#!/bin/sh
# PSYCH installer script
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/olifink/psych-go/main/install.sh | sh
# Options via environment variables:
#   VERSION=v1.0.0   Specific release tag to install (defaults to latest)
#   BINDIR=/custom   Target directory for binary (defaults to /usr/local/bin or ~/.local/bin)

set -e

GITHUB_REPO="olifink/psych-go"
BINARY_NAME="psych"

# Colors for terminal output
setup_colors() {
  if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    RESET='\033[0m'
  else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    BOLD=''
    RESET=''
  fi
}

log_info() {
  printf "${BLUE}${BOLD}==>${RESET} %s\n" "$1"
}

log_success() {
  printf "${GREEN}${BOLD}==>${RESET} %s\n" "$1"
}

log_warn() {
  printf "${YELLOW}${BOLD}Warning:${RESET} %s\n" "$1"
}

log_error() {
  printf "${RED}${BOLD}Error:${RESET} %s\n" "$1" >&2
}

# Detect operating system
detect_os() {
  OS="$(uname -s)"
  case "$OS" in
    Linux*)   OS="linux" ;;
    Darwin*)  OS="darwin" ;;
    FreeBSD*) OS="freebsd" ;;
    *)
      log_error "Unsupported operating system '$OS'"
      exit 1
      ;;
  esac
}

# Detect architecture
detect_arch() {
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64 | amd64)
      ARCH="amd64"
      ;;
    aarch64 | arm64)
      ARCH="arm64"
      ;;
    armv7* | armhf)
      ARCH="armv7"
      ;;
    *)
      log_error "Unsupported CPU architecture '$ARCH'"
      exit 1
      ;;
  esac
}

# Determine download tool
has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

# Resolve GitHub authorization token if available (for private repos)
resolve_auth() {
  AUTH_TOKEN=""
  if [ -n "$GITHUB_TOKEN" ]; then
    AUTH_TOKEN="$GITHUB_TOKEN"
  elif [ -n "$GH_TOKEN" ]; then
    AUTH_TOKEN="$GH_TOKEN"
  elif has_cmd gh; then
    AUTH_TOKEN=$(gh auth token 2>/dev/null || true)
  fi
}

download_file() {
  url="$1"
  output="$2"
  auth_header=""
  [ -n "$AUTH_TOKEN" ] && auth_header="Authorization: Bearer $AUTH_TOKEN"

  if has_cmd curl; then
    if [ -n "$auth_header" ]; then
      curl -fsSL -H "$auth_header" "$url" -o "$output"
    else
      curl -fsSL "$url" -o "$output"
    fi
  elif has_cmd wget; then
    if [ -n "$auth_header" ]; then
      wget --header="$auth_header" -qO "$output" "$url"
    else
      wget -qO "$output" "$url"
    fi
  else
    log_error "Neither curl nor wget is available. Please install one of them."
    exit 1
  fi
}

fetch_text() {
  url="$1"
  auth_header=""
  [ -n "$AUTH_TOKEN" ] && auth_header="Authorization: Bearer $AUTH_TOKEN"

  if has_cmd curl; then
    if [ -n "$auth_header" ]; then
      curl -fsSL -H "$auth_header" "$url"
    else
      curl -fsSL "$url"
    fi
  elif has_cmd wget; then
    if [ -n "$auth_header" ]; then
      wget --header="$auth_header" -qO- "$url"
    else
      wget -qO- "$url"
    fi
  else
    log_error "Neither curl nor wget is available."
    exit 1
  fi
}

# Resolve release version
resolve_version() {
  if [ -n "$VERSION" ]; then
    TAG="$VERSION"
    case "$TAG" in
      v*) ;;
      *) TAG="v$TAG" ;;
    esac
    CLEAN_VERSION="${TAG#v}"
    return 0
  fi

  log_info "Finding latest release of ${GITHUB_REPO}..."

  # Attempt 1: GitHub API (works with or without AUTH_TOKEN)
  TAG=$(fetch_text "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" 2>/dev/null | grep '"tag_name":' | head -n 1 | sed -E 's/.*"([^"]+)".*/\1/' || true)

  # Attempt 2: gh CLI
  if [ -z "$TAG" ] && has_cmd gh; then
    TAG=$(gh release view --repo "${GITHUB_REPO}" --json tagName -q .tagName 2>/dev/null || true)
  fi

  # Attempt 3: HTTP redirect header (public repos)
  if [ -z "$TAG" ]; then
    if has_cmd curl; then
      REDIRECT_URL=$(curl -fsSI -o /dev/null -w "%{url_effective}" "https://github.com/${GITHUB_REPO}/releases/latest" 2>/dev/null || true)
      TAG="${REDIRECT_URL##*/}"
    fi
  fi

  if [ -z "$TAG" ] || [ "$TAG" = "latest" ]; then
    log_error "Failed to resolve latest release tag from GitHub. Specify a version manually: VERSION=v1.0.0 $0"
    if [ -z "$AUTH_TOKEN" ]; then
      log_warn "If ${GITHUB_REPO} is private, export GITHUB_TOKEN or authenticate via 'gh auth login'."
    fi
    exit 1
  fi

  case "$TAG" in
    v*) ;;
    *) TAG="v$TAG" ;;
  esac
  CLEAN_VERSION="${TAG#v}"
}

# Determine install destination directory
resolve_bindir() {
  if [ -n "$BINDIR" ]; then
    return 0
  fi

  if [ "$(id -u)" -eq 0 ] || [ -w "/usr/local/bin" ]; then
    BINDIR="/usr/local/bin"
  elif [ -d "$HOME/.local/bin" ] || [ -w "$HOME" ]; then
    BINDIR="$HOME/.local/bin"
  else
    BINDIR="/usr/local/bin"
  fi
}

# Verify checksum
verify_checksum() {
  archive_file="$1"
  expected_name="$2"
  checksum_file="$3"

  if [ ! -f "$checksum_file" ]; then
    return 0
  fi

  expected_hash=$(grep "${expected_name}" "${checksum_file}" | awk '{print $1}')
  if [ -z "$expected_hash" ]; then
    log_warn "Checksum for ${expected_name} not found in checksums.txt, skipping verification."
    return 0
  fi

  if has_cmd sha256sum; then
    actual_hash=$(sha256sum "${archive_file}" | awk '{print $1}')
  elif has_cmd shasum; then
    actual_hash=$(shasum -a 256 "${archive_file}" | awk '{print $1}')
  else
    log_warn "Neither sha256sum nor shasum found; skipping checksum verification."
    return 0
  fi

  if [ "$expected_hash" != "$actual_hash" ]; then
    log_error "Checksum verification failed!"
    log_error "Expected: ${expected_hash}"
    log_error "Actual:   ${actual_hash}"
    exit 1
  fi

  short_hash=$(printf "%s" "$actual_hash" | cut -c 1-16)
  log_info "Checksum verified (${short_hash}...)"
}

main() {
  setup_colors
  detect_os
  detect_arch
  resolve_auth
  resolve_version
  resolve_bindir

  ARCHIVE_NAME="psych_${CLEAN_VERSION}_${OS}_${ARCH}.tar.gz"
  DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${TAG}/${ARCHIVE_NAME}"
  CHECKSUM_URL="https://github.com/${GITHUB_REPO}/releases/download/${TAG}/checksums.txt"

  log_info "Installing ${BINARY_NAME} ${TAG} (${OS}/${ARCH})..."

  TMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'psych-install')
  trap 'rm -rf "$TMPDIR"' EXIT INT TERM

  DOWNLOAD_SUCCESS=0
  if has_cmd gh && [ -n "$AUTH_TOKEN" ]; then
    log_info "Downloading release assets via GitHub CLI..."
    if gh release download "$TAG" -p "$ARCHIVE_NAME" -p "checksums.txt" -D "$TMPDIR" --repo "$GITHUB_REPO" 2>/dev/null; then
      DOWNLOAD_SUCCESS=1
    fi
  fi

  if [ "$DOWNLOAD_SUCCESS" -eq 0 ]; then
    log_info "Downloading ${DOWNLOAD_URL}..."
    if ! download_file "$DOWNLOAD_URL" "$TMPDIR/$ARCHIVE_NAME"; then
      log_error "Failed to download release archive from ${DOWNLOAD_URL}"
      exit 1
    fi
    # Download checksums
    download_file "$CHECKSUM_URL" "$TMPDIR/checksums.txt" 2>/dev/null || true
  fi
  verify_checksum "$TMPDIR/$ARCHIVE_NAME" "$ARCHIVE_NAME" "$TMPDIR/checksums.txt"

  # Extract binary
  tar -xzf "$TMPDIR/$ARCHIVE_NAME" -C "$TMPDIR"
  if [ ! -f "$TMPDIR/$BINARY_NAME" ]; then
    log_error "Archive did not contain '${BINARY_NAME}' executable."
    exit 1
  fi

  # Create install directory if needed
  if [ ! -d "$BINDIR" ]; then
    mkdir -p "$BINDIR" 2>/dev/null || sudo mkdir -p "$BINDIR"
  fi

  # Copy binary to destination
  log_info "Installing binary to ${BINDIR}/${BINARY_NAME}..."
  if [ -w "$BINDIR" ]; then
    mv "$TMPDIR/$BINARY_NAME" "$BINDIR/$BINARY_NAME"
    chmod +x "$BINDIR/$BINARY_NAME"
  else
    if has_cmd sudo; then
      sudo mv "$TMPDIR/$BINARY_NAME" "$BINDIR/$BINARY_NAME"
      sudo chmod +x "$BINDIR/$BINARY_NAME"
    else
      log_error "Cannot write to ${BINDIR}. Please rerun as root or specify BINDIR: BINDIR=\$HOME/.local/bin $0"
      exit 1
    fi
  fi

  log_success "Successfully installed ${BINARY_NAME} to ${BINDIR}/${BINARY_NAME}!"

  # Check PATH
  case ":$PATH:" in
    *:"$BINDIR":*) ;;
    *)
      log_warn "'${BINDIR}' is not in your PATH."
      echo "  Add it to your profile (e.g. ~/.bashrc or ~/.zshrc):"
      echo "    export PATH=\"${BINDIR}:\$PATH\""
      echo ""
      ;;
  esac

  # Verify executable
  if has_cmd "$BINDIR/$BINARY_NAME"; then
    "$BINDIR/$BINARY_NAME" version || true
  fi
}

main "$@"
