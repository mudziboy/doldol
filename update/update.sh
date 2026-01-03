#!/bin/bash
set -e

BASE_DIR="/opt/sellvpn"
BIN_DIR="$BASE_DIR/bin"
TMP_DIR="/tmp/sellvpn-update"
REPO_RAW="https://raw.githubusercontent.com/mudziboy/doldol/main"

echo "=== SELLVPN UPDATE START ==="

mkdir -p "$BIN_DIR"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

echo "[1/5] Download binary apitrial-zivpn.real"
curl -fsSL "$REPO_RAW/bin/apitrial-zivpn.real" -o "$TMP_DIR/apitrial-zivpn.real"

echo "[2/5] Install binary (safe replace)"
install -m 755 "$TMP_DIR/apitrial-zivpn.real" "$BIN_DIR/apitrial-zivpn.real"

echo "[3/5] Download self-test"
curl -fsSL "$REPO_RAW/update/selftest.sh" -o "$TMP_DIR/selftest.sh"
install -m 755 "$TMP_DIR/selftest.sh" "$BIN_DIR/selftest-zivpn"

echo "[4/5] Run self-test"
"$BIN_DIR/selftest-zivpn"

echo "[5/5] Cleanup"
rm -rf "$TMP_DIR"

echo "=== UPDATE SUCCESS ==="