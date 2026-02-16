#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_DIR="${HOME}/.local/share/sentinel-x"
VENV_DIR="${INSTALL_DIR}/venv"
BIN_DIR="${HOME}/.local/bin"
SENTINEL_PATH="${BIN_DIR}/sentinel-x-app"
DECKTROY_PATH="${BIN_DIR}/decktroy"
DECKTROY_UPPER_PATH="${BIN_DIR}/Decktroy"
DESKTOP_DIR="${HOME}/.local/share/applications"

mkdir -p "${INSTALL_DIR}" "${BIN_DIR}" "${DESKTOP_DIR}"

python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip
"${VENV_DIR}/bin/python" -m pip install -r "${ROOT_DIR}/requirements.txt"
"${VENV_DIR}/bin/python" -m pip install -e "${ROOT_DIR}"

cat > "${SENTINEL_PATH}" <<WRAPPER
#!/usr/bin/env bash
set -euo pipefail
exec "${VENV_DIR}/bin/python" -m sentinel_x_defense_suite.cli.app "\$@"
WRAPPER
chmod +x "${SENTINEL_PATH}"

cat > "${DECKTROY_PATH}" <<DECK
#!/usr/bin/env bash
set -euo pipefail
exec "${VENV_DIR}/bin/python" -m decktroy.decktroy_cli "$@"
DECK
chmod +x "${DECKTROY_PATH}"

cat > "${DECKTROY_UPPER_PATH}" <<DECKUP
#!/usr/bin/env bash
set -euo pipefail
exec "${BIN_DIR}/decktroy" "$@"
DECKUP
chmod +x "${DECKTROY_UPPER_PATH}"

cp "${ROOT_DIR}/packaging/sentinel-x.desktop" "${DESKTOP_DIR}/sentinel-x.desktop"

echo "SENTINEL X instalado correctamente"
echo "- Ejecutables: ${SENTINEL_PATH}, ${DECKTROY_PATH}, ${DECKTROY_UPPER_PATH}"
echo "- Arranque inmediato GUI: Decktroy"
echo "- Instalación y ejecución en un paso: ./install_decktroy_linux.sh"
