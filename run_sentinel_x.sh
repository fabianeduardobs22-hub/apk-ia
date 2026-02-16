#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALLER="${ROOT_DIR}/install_decktroy_linux.sh"
LAUNCHER="${HOME}/.local/bin/sentinel-x"

if [[ ! -x "${LAUNCHER}" ]]; then
  echo "[setup] Instalación local no detectada. Instalando..."
  DECKTROY_NO_AUTOLAUNCH=1 bash "${INSTALLER}"
fi

exec "${LAUNCHER}" "$@"
