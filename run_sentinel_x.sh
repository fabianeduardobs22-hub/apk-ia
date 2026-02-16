#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALLER="${ROOT_DIR}/packaging/install_sentinel_x.sh"
LAUNCHER="${HOME}/.local/bin/sentinel-x-app"

if [[ ! -x "${LAUNCHER}" ]]; then
  echo "[setup] Instalación local no detectada. Instalando..."
  bash "${INSTALLER}"
fi

exec "${LAUNCHER}" "$@"
