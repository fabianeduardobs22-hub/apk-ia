#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_ROOT="${HOME}/.local/share/decktroy"
APP_DIR="${INSTALL_ROOT}/app"
VENV_DIR="${INSTALL_ROOT}/venv"
BIN_DIR="${HOME}/.local/bin"
DESKTOP_DIR="${HOME}/.local/share/applications"

SENTINEL_PATH="${BIN_DIR}/sentinel-x"
DECKTROY_PATH="${BIN_DIR}/decktroy"
DECKTROY_UPPER_PATH="${BIN_DIR}/Decktroy"

log() {
  echo "[install_decktroy_linux] $*"
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

need_sudo=0
if [[ "${EUID}" -ne 0 ]]; then
  need_sudo=1
fi

run_root() {
  if [[ ${need_sudo} -eq 1 ]]; then
    sudo "$@"
  else
    "$@"
  fi
}

install_system_dependencies() {
  log "Verificando dependencias del sistema..."

  if has_cmd apt-get; then
    run_root apt-get update -y
    run_root apt-get install -y python3 python3-pip python3-venv libpcap-dev build-essential libgl1 libegl1 libxkbcommon-x11-0 libdbus-1-3 libxcb-cursor0
  elif has_cmd dnf; then
    run_root dnf install -y python3 python3-pip python3-virtualenv libpcap-devel gcc mesa-libGL libxkbcommon-x11 libdbusmenu-qt5
  elif has_cmd yum; then
    run_root yum install -y python3 python3-pip python3-virtualenv libpcap-devel gcc mesa-libGL libxkbcommon-x11
  elif has_cmd pacman; then
    run_root pacman -Sy --noconfirm python python-pip python-virtualenv libpcap base-devel mesa libxkbcommon
  elif has_cmd zypper; then
    run_root zypper --non-interactive refresh
    run_root zypper --non-interactive install python3 python3-pip python3-virtualenv libpcap-devel gcc Mesa-libGL1 libxkbcommon-x11-0
  else
    log "No se detectó un gestor de paquetes compatible."
    log "Instala manualmente: python3, pip, venv, toolchain de compilación y librerías GUI (OpenGL/xkbcommon)."
  fi
}

ensure_file_path() {
  local path="$1"
  if [[ -d "${path}" ]]; then
    local backup="${path}.backup.$(date +%s)"
    log "Se encontró un directorio en ${path}; moviendo respaldo a ${backup}"
    mv "${path}" "${backup}"
  fi
}

copy_project_source() {
  log "Copiando proyecto a ${APP_DIR}"
  mkdir -p "${INSTALL_ROOT}"
  rm -rf "${APP_DIR}"
  mkdir -p "${APP_DIR}"
  cp -a "${ROOT_DIR}/." "${APP_DIR}/"
  rm -rf "${APP_DIR}/.git"
}

create_virtualenv() {
  log "Creando entorno virtual en ${VENV_DIR}"
  rm -rf "${VENV_DIR}"
  python3 -m venv "${VENV_DIR}"
  "${VENV_DIR}/bin/python" -m pip install --upgrade pip setuptools wheel
  "${VENV_DIR}/bin/python" -m pip install -r "${APP_DIR}/requirements.txt"
  "${VENV_DIR}/bin/python" -m pip install -e "${APP_DIR}"
}

create_wrappers() {
  mkdir -p "${BIN_DIR}"
  ensure_file_path "${SENTINEL_PATH}"
  ensure_file_path "${DECKTROY_PATH}"
  ensure_file_path "${DECKTROY_UPPER_PATH}"

  cat > "${SENTINEL_PATH}" <<WRAPPER
#!/usr/bin/env bash
set -euo pipefail
exec "${VENV_DIR}/bin/python" -m sentinel_x_defense_suite.cli.app "\$@"
WRAPPER

  cat > "${DECKTROY_PATH}" <<WRAPPER
#!/usr/bin/env bash
set -euo pipefail
exec "${VENV_DIR}/bin/python" -m decktroy.decktroy_cli "\$@"
WRAPPER

  cat > "${DECKTROY_UPPER_PATH}" <<WRAPPER
#!/usr/bin/env bash
set -euo pipefail
exec "${BIN_DIR}/decktroy" "\$@"
WRAPPER

  chmod +x "${SENTINEL_PATH}" "${DECKTROY_PATH}" "${DECKTROY_UPPER_PATH}"
}

install_desktop_entry() {
  mkdir -p "${DESKTOP_DIR}"
  cp "${APP_DIR}/packaging/sentinel-x.desktop" "${DESKTOP_DIR}/sentinel-x.desktop"
}

if [[ "${DECKTROY_SKIP_SYSTEM_DEPS:-0}" == "1" ]]; then
  log "Saltando dependencias del sistema (DECKTROY_SKIP_SYSTEM_DEPS=1)."
else
  install_system_dependencies
fi
copy_project_source
create_virtualenv
create_wrappers
install_desktop_entry

if ! echo ":${PATH}:" | grep -q ":${HOME}/.local/bin:"; then
  log "Aviso: ${HOME}/.local/bin no está en PATH para esta sesión."
  log "Puedes ejecutar temporalmente: export PATH=\"${HOME}/.local/bin:$PATH\""
fi

if [[ "${DECKTROY_NO_AUTOLAUNCH:-0}" == "1" ]]; then
  log "Instalación completada. Autoarranque deshabilitado (DECKTROY_NO_AUTOLAUNCH=1)."
  exit 0
fi

log "Instalación completada. Iniciando interfaz gráfica..."
exec "${DECKTROY_UPPER_PATH}" "$@"
