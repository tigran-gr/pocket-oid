#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="$(tr -d '[:space:]' < "$SCRIPT_DIR/VERSION")"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Invalid OAuth2 Proxy version: $VERSION" >&2
    exit 1
fi

case "$(uname -s)" in
    Darwin) OS=darwin ;;
    Linux) OS=linux ;;
    *) echo "OAuth2 Proxy test helper supports macOS and Linux only" >&2; exit 1 ;;
esac
case "$(uname -m)" in
    arm64|aarch64) ARCH=arm64 ;;
    x86_64|amd64) ARCH=amd64 ;;
    *) echo "OAuth2 Proxy test helper supports ARM64 and AMD64 only" >&2; exit 1 ;;
esac

NAME="oauth2-proxy-v$VERSION.$OS-$ARCH"
INSTALL_DIR="$SCRIPT_DIR/dist/$NAME"
if [[ -x "$INSTALL_DIR/oauth2-proxy" ]]; then
    printf '%s\n' "$INSTALL_DIR/oauth2-proxy"
    exit 0
fi
if [[ -e "$INSTALL_DIR" ]]; then
    echo "Incomplete OAuth2 Proxy installation: $INSTALL_DIR" >&2
    exit 1
fi

mkdir -p "$SCRIPT_DIR/dist"
STAGING_DIR="$(mktemp -d "$SCRIPT_DIR/dist/download.XXXXXX")"
trap 'rm -rf "$STAGING_DIR"' EXIT
RELEASE_URL="https://github.com/oauth2-proxy/oauth2-proxy/releases/download/v$VERSION"
echo "Downloading OAuth2 Proxy $VERSION for $OS/$ARCH" >&2
curl --fail --location --silent --show-error --retry 3 --max-time 120 \
    --output "$STAGING_DIR/$NAME.tar.gz" "$RELEASE_URL/$NAME.tar.gz"
curl --fail --location --silent --show-error --retry 3 --max-time 30 \
    --output "$STAGING_DIR/checksum.txt" "$RELEASE_URL/$NAME.tar.gz-sha256sum.txt"

cd "$STAGING_DIR"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum --check checksum.txt >&2
else
    shasum -a 256 --check checksum.txt >&2
fi
tar -xzf "$NAME.tar.gz"
if [[ ! -x "$NAME/oauth2-proxy" ]]; then
    echo "Downloaded archive does not contain $NAME/oauth2-proxy" >&2
    exit 1
fi
mv "$NAME" "$INSTALL_DIR"
printf '%s\n' "$INSTALL_DIR/oauth2-proxy"
