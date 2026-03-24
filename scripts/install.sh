#!/usr/bin/env sh
# AgentOnRails installer
# Usage: curl -sf https://raw.githubusercontent.com/agentOnRails/agent-on-rails/main/scripts/install.sh | sh

set -e

REPO="agentOnRails/agent-on-rails"
BINARY="aor"
INSTALL_DIR="${AOR_INSTALL_DIR:-/usr/local/bin}"

# ── detect OS / arch ──────────────────────────────────────────────────────────

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

case "$OS" in
  linux|darwin) ;;
  *)
    echo "Unsupported OS: $OS" >&2
    echo "On Windows, download the binary from: https://github.com/$REPO/releases" >&2
    exit 1
    ;;
esac

# ── resolve version ───────────────────────────────────────────────────────────

if [ -z "$AOR_VERSION" ]; then
  AOR_VERSION="$(curl -sf "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
fi

if [ -z "$AOR_VERSION" ]; then
  echo "Could not determine latest version. Set AOR_VERSION=vX.Y.Z to install a specific version." >&2
  exit 1
fi

echo "Installing aor $AOR_VERSION ($OS/$ARCH) → $INSTALL_DIR/$BINARY"

# ── download ──────────────────────────────────────────────────────────────────

FILENAME="${BINARY}_${AOR_VERSION}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/$REPO/releases/download/$AOR_VERSION/$FILENAME"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$URL" -o "$TMP/$FILENAME"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$TMP/$FILENAME" "$URL"
else
  echo "curl or wget is required" >&2
  exit 1
fi

tar -xzf "$TMP/$FILENAME" -C "$TMP"

# ── install ───────────────────────────────────────────────────────────────────

if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP/$BINARY" "$INSTALL_DIR/$BINARY"
  chmod +x "$INSTALL_DIR/$BINARY"
else
  echo "Installing to $INSTALL_DIR requires elevated permissions..."
  sudo mv "$TMP/$BINARY" "$INSTALL_DIR/$BINARY"
  sudo chmod +x "$INSTALL_DIR/$BINARY"
fi

# ── verify ────────────────────────────────────────────────────────────────────

echo ""
"$INSTALL_DIR/$BINARY" version
echo ""
echo "Run 'aor init' to create your config directory."
