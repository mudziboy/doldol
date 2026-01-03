#!/bin/bash

BIN="/opt/sellvpn/bin/apitrial-zivpn.real"

OUT="$($BIN 1 1 2>/dev/null)"

echo "$OUT" | jq . >/dev/null 2>&1 || {
  echo "SELFTEST FAILED: INVALID JSON"
  exit 1
}

SUCCESS=$(echo "$OUT" | jq -r '.success')

if [ "$SUCCESS" != "true" ]; then
  echo "SELFTEST FAILED: TRIAL ERROR"
  exit 1
fi

echo "SELFTEST OK: ZIVPN TRIAL READY"
exit 0