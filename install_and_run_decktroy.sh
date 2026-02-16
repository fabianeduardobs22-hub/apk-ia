#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALLER="${ROOT_DIR}/packaging/install_sentinel_x.sh"
LAUNCHER="${HOME}/.local/bin/Decktroy"

bash "${INSTALLER}"

if [[ ! -x "${LAUNCHER}" ]]; then
  echo "[error] No se encontró lanzador ${LAUNCHER}" >&2
  exit 1
fi

exec "${LAUNCHER}" "$@"
