#!/bin/sh
# skink-tunnel.sh — one-liner tunnel client deploy
# Usage: curl -s https://skink.sh/tunnel.sh | bash -s -- --server relay:9090
# Or:    wget -qO- https://skink.sh/tunnel.sh | bash -s -- --server relay:9090
#
# Downloads the latest Skink release from GitHub and runs `skink tunnel`
# with the given args. The binary is extracted to a temp dir and cleaned up.
set -e

if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
	echo "skink-tunnel.sh — one-liner tunnel client"
	echo ""
	echo "Downloads the latest Skink release and runs 'skink tunnel'."
	echo ""
	echo "Usage: curl -s https://skink.sh/tunnel.sh | bash -s -- [skink tunnel flags]"
	echo ""
	echo "Examples:"
	echo "  curl -s https://skink.sh/tunnel.sh | bash -s -- --server relay:9090"
	echo "  curl -s https://skink.sh/tunnel.sh | bash -s -- --server relay:9090 --local localhost:22"
	echo ""
	echo "Environment variables:"
	echo "  SKINK_VERSION    specific version to download (default: latest)"
	echo "  SKINK_DIR        download directory (default: /tmp/skink-tunnel)"
	exit 0
fi

# Determine latest version
if [ -z "$SKINK_VERSION" ]; then
	SKINK_VERSION=$(curl -sSfL "https://api.github.com/repos/octagono/skink/releases/latest" 2>/dev/null |
		grep '"tag_name"' | cut -d'"' -f4 2>/dev/null || echo "v1.0.0")
fi

# Detect OS and arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
x86_64 | amd64) ARCH="amd64" ;;
aarch64 | arm64) ARCH="arm64" ;;
*)
	echo "unsupported architecture: $ARCH"
	exit 1
	;;
esac

case "$OS" in
linux | darwin) ;;
mingw* | msys* | cygwin*) OS="windows" ;;
*)
	echo "unsupported OS: $OS (supported: linux, darwin, windows)"
	exit 1
	;;
esac

FILENAME="skink-${OS}-${ARCH}.tar.gz"
DOWNLOAD_DIR="${SKINK_DIR:-/tmp/skink-tunnel}"
mkdir -p "$DOWNLOAD_DIR"

# Cleanup on exit
trap 'rm -f "$DOWNLOAD_DIR/skink" "$DOWNLOAD_DIR/$FILENAME"' EXIT

# Download if not cached
if [ ! -f "$DOWNLOAD_DIR/skink" ]; then
	echo "downloading Skink ${SKINK_VERSION} for ${OS}/${ARCH}..." >&2
	URL="https://github.com/octagono/skink/releases/download/${SKINK_VERSION}/${FILENAME}"

	if command -v curl >/dev/null 2>&1; then
		curl -sSfL "$URL" -o "$DOWNLOAD_DIR/$FILENAME"
	elif command -v wget >/dev/null 2>&1; then
		wget -q "$URL" -O "$DOWNLOAD_DIR/$FILENAME"
	else
		echo "need curl or wget" >&2
		exit 1
	fi

	tar xzf "$DOWNLOAD_DIR/$FILENAME" -C "$DOWNLOAD_DIR" 2>/dev/null ||
		(cd "$DOWNLOAD_DIR" && tar xzf "$FILENAME")
fi

chmod +x "$DOWNLOAD_DIR/skink"
exec "$DOWNLOAD_DIR/skink" tunnel "$@"
