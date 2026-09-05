#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION_FILE="$SCRIPT_DIR/VERSION"
VERSION="$(tr -d '[:space:]' < "$VERSION_FILE")"
ARCHIVE_DIR="$SCRIPT_DIR/archive"
DIST_DIR="$SCRIPT_DIR/dist"
ARCHIVE_PATH="$ARCHIVE_DIR/keycloak-$VERSION.zip"
INSTALL_DIR="$DIST_DIR/keycloak-$VERSION"
DOWNLOAD_URL="${POCKET_OID_KEYCLOAK_DOWNLOAD_URL:-https://github.com/keycloak/keycloak/releases/download/$VERSION/keycloak-$VERSION.zip}"

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Invalid Keycloak version in $VERSION_FILE: $VERSION" >&2
    exit 1
fi

if [[ -x "$INSTALL_DIR/bin/kc.sh" ]]; then
    printf '%s\n' "$INSTALL_DIR"
    exit 0
fi

if [[ -e "$INSTALL_DIR" ]]; then
    echo "Keycloak installation is incomplete: $INSTALL_DIR" >&2
    echo "Remove that directory and run this script again." >&2
    exit 1
fi

mkdir -p "$ARCHIVE_DIR" "$DIST_DIR"

if [[ ! -f "$ARCHIVE_PATH" ]]; then
    echo "Downloading Keycloak $VERSION from $DOWNLOAD_URL" >&2
    curl --fail --location --retry 3 --output "$ARCHIVE_PATH" "$DOWNLOAD_URL"
fi

EXTRACT_DIR="$(mktemp -d "$DIST_DIR/keycloak-extract.XXXXXX")"
trap 'rm -rf "$EXTRACT_DIR"' EXIT

unzip -q "$ARCHIVE_PATH" -d "$EXTRACT_DIR"
EXTRACTED_DIR="$EXTRACT_DIR/keycloak-$VERSION"

if [[ ! -x "$EXTRACTED_DIR/bin/kc.sh" ]]; then
    echo "Downloaded archive does not contain bin/kc.sh for Keycloak $VERSION" >&2
    exit 1
fi

mv "$EXTRACTED_DIR" "$INSTALL_DIR"
printf '%s\n' "$INSTALL_DIR"
