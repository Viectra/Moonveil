#!/usr/bin/env bash
set -euo pipefail

echo "[moonveil] Removing /usr/local/bin/moonveil and /usr/local/bin/mvl..."
sudo rm -f /usr/local/bin/moonveil /usr/local/bin/mvl
echo "[moonveil] Uninstalled."
