#!/bin/sh
set -e

REPO="sshloktiwarii/vouchproxy"
VERSION="${VOUCH_VERSION:-1.1.0}"
VERSION="${VERSION#v}"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64)
    ARCH="amd64"
    ;;
  arm64|aarch64)
    ARCH="arm64"
    ;;
  *)
    echo "Error: Unsupported architecture $ARCH" >&2
    exit 1
    ;;
esac

case "$OS" in
  darwin|linux)
    ;;
  *)
    echo "Error: Unsupported operating system $OS. Please use install.ps1 for Windows." >&2
    exit 1
    ;;
esac

ARCHIVE="vouchproxy_${VERSION}_${OS}_${ARCH}.tar.gz"
CHECKSUMS="checksums.txt"
BASE_URL="https://github.com/${REPO}/releases/download/v${VERSION}"

echo "Installing VouchProxy v${VERSION} (${OS}/${ARCH})..."

TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'vouchproxy')"
trap 'rm -rf "$TMP_DIR"' EXIT

CURL_AUTH=""
if [ -n "$GITHUB_TOKEN" ]; then
  CURL_AUTH="-H \"Authorization: token $GITHUB_TOKEN\""
elif [ -n "$GH_TOKEN" ]; then
  CURL_AUTH="-H \"Authorization: token $GH_TOKEN\""
fi

download_file() {
  url="$1"
  dest="$2"
  if [ -n "$CURL_AUTH" ]; then
    eval "curl -fsSL $CURL_AUTH \"$url\" -o \"$dest\""
  else
    curl -fsSL "$url" -o "$dest"
  fi
}

echo "Downloading ${ARCHIVE}..."
download_file "${BASE_URL}/${ARCHIVE}" "${TMP_DIR}/${ARCHIVE}"
download_file "${BASE_URL}/${CHECKSUMS}" "${TMP_DIR}/${CHECKSUMS}"

echo "Verifying SHA-256 checksum..."
cd "$TMP_DIR"
if command -v sha256sum >/dev/null 2>&1; then
  grep "$ARCHIVE" "$CHECKSUMS" | sha256sum -c -
elif command -v shasum >/dev/null 2>&1; then
  grep "$ARCHIVE" "$CHECKSUMS" | shasum -a 256 -c -
else
  echo "Warning: sha256sum/shasum not found, skipping checksum verification." >&2
fi

tar -xzf "$ARCHIVE"

INSTALL_DIR="/usr/local/bin"
if [ ! -w "$INSTALL_DIR" ]; then
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

mv vouchproxy "$INSTALL_DIR/vouchproxy"
chmod +x "$INSTALL_DIR/vouchproxy"

echo "✓ VouchProxy v${VERSION} successfully installed to $INSTALL_DIR/vouchproxy"

if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
  echo ""
  echo "Notice: $INSTALL_DIR is not in your \$PATH."
  echo "Add it to your profile: export PATH=\"$INSTALL_DIR:\$PATH\""
fi

echo ""
echo "Get started:"
echo "  vouchproxy init"
echo "  eval \"\$(vouchproxy env)\""
