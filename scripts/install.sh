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

# GoReleaser names archive assets without the tag's leading "v" (e.g. tag
# v0.1.0 -> aor_0.1.0_linux_amd64.tar.gz) even though the release path
# itself uses the full tag — strip it here, not from AOR_VERSION, so the
# download path below still resolves.
ARCHIVE_VERSION="${AOR_VERSION#v}"
FILENAME="${BINARY}_${ARCHIVE_VERSION}_${OS}_${ARCH}.tar.gz"
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

# ── optional: aor-pro (commercial add-ons — identity, privacy, Dispatch) ──────
#
# aor-pro has no public binary release yet (unlike aor above, which
# GoReleaser publishes to this repo's own GitHub releases) — the private
# repo isn't public, so there's nothing to download by URL. The only way to
# get an aor-pro binary today is building it from that repo's source, which
# this step does IF AOR_PRO_SRC_DIR points at a local checkout AND you have
# a Pro license token to activate. Deliberately not guessed from the current
# directory: this script's documented usage is a curl-pipe-sh one-liner run
# from anywhere, so "look for a sibling directory" would be right only by
# coincidence. Neither set: nothing below runs, and everything above this
# line behaves exactly as it always has.
if [ -n "$AOR_PRO_LICENSE_TOKEN" ] || [ -f "${HOME}/.aor-pro/license.key" ]; then
  if [ -n "$AOR_PRO_SRC_DIR" ] && [ -d "$AOR_PRO_SRC_DIR" ] && command -v go >/dev/null 2>&1; then
    echo ""
    echo "Pro license detected — building aor-pro from $AOR_PRO_SRC_DIR ..."
    ( cd "$AOR_PRO_SRC_DIR" && go build -o "$INSTALL_DIR/aor-pro" ./cmd/aor-pro/ )

    # Both calls below are best-effort: activation can fail on a bad/expired
    # token and "show" has nothing to report on a fresh vault-dir, neither of
    # which should take down the rest of this installer under `set -e`.
    if [ -n "$AOR_PRO_LICENSE_TOKEN" ] && [ ! -f "${HOME}/.aor-pro/license.key" ]; then
      "$INSTALL_DIR/aor-pro" license activate "$AOR_PRO_LICENSE_TOKEN" || true
    fi

    echo ""
    "$INSTALL_DIR/aor-pro" license show || true
    echo ""
    echo "aor-pro installed. Run 'aor-pro onboard --agent <id>' for the guided path to a"
    echo "fully protected agent (wallet, Cargo privacy rail, Track identity), or"
    echo "'aor-pro doctor' to check an existing setup."
  else
    echo ""
    echo "A Pro license was detected, but aor-pro has no public binary download yet."
    echo "If you have access to the private repo, set AOR_PRO_SRC_DIR to your local"
    echo "checkout's path and re-run this installer."
  fi
fi
