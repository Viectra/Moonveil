#!/usr/bin/env bash
set -euo pipefail

WITH_CAPS=false
for arg in "$@"; do
    case "$arg" in
        --caps) WITH_CAPS=true ;;
        *)
            echo "Usage: $0 [--caps]" >&2
            exit 1
            ;;
    esac
done

echo "[moonveil] Building release binaries..."
cargo build --release

echo "[moonveil] Installing moonveil and mvl to /usr/local/bin..."
sudo install -m 0755 target/release/moonveil /usr/local/bin/moonveil
sudo ln -sf /usr/local/bin/moonveil /usr/local/bin/mvl

if $WITH_CAPS; then
    if command -v setcap >/dev/null 2>&1; then
        echo "[moonveil] Granting CAP_NET_RAW for unprivileged ICMP/raw discovery..."
        sudo setcap cap_net_raw+ep /usr/local/bin/moonveil
    else
        echo "[moonveil] Warning: setcap not found; skipping capability grant." >&2
    fi
fi

echo "[moonveil] Done! Run 'moonveil' or 'mvl' (or 'mvl --demo')."
