#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${HOME}/.local/bin"
TARGET_BIN="${TARGET_DIR}/decktroy"

mkdir -p "${TARGET_DIR}"
cp "${ROOT_DIR}/bin/decktroy" "${TARGET_BIN}"
chmod +x "${TARGET_BIN}"

echo "Instalado: ${TARGET_BIN}"
echo "Asegura que ${TARGET_DIR} esté en tu PATH."
echo "Uso: decktroy startup -o decktroy_startup_status.json"
