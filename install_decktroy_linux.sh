#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALLER="${ROOT_DIR}/packaging/install_sentinel_x.sh"
LAUNCHER="${HOME}/.local/bin/Decktroy"

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
  log "Verificando dependencias base del sistema..."

  local pkgs=(python3 python3-pip python3-venv)

  if has_cmd apt-get; then
    log "Gestor detectado: apt-get"
    run_root apt-get update -y
    run_root apt-get install -y "${pkgs[@]}" libpcap-dev build-essential
  elif has_cmd dnf; then
    log "Gestor detectado: dnf"
    run_root dnf install -y python3 python3-pip python3-virtualenv libpcap-devel gcc
  elif has_cmd yum; then
    log "Gestor detectado: yum"
    run_root yum install -y python3 python3-pip python3-virtualenv libpcap-devel gcc
  elif has_cmd pacman; then
    log "Gestor detectado: pacman"
    run_root pacman -Sy --noconfirm python python-pip python-virtualenv libpcap base-devel
  elif has_cmd zypper; then
    log "Gestor detectado: zypper"
    run_root zypper --non-interactive refresh
    run_root zypper --non-interactive install python3 python3-pip python3-virtualenv libpcap-devel gcc
  else
    log "No se detectó gestor compatible. Continuando sin auto-instalación de paquetes del sistema."
  fi
}

if ! has_cmd python3; then
  log "python3 no encontrado; intentando instalarlo"
fi

install_system_dependencies

if [[ ! -x "${INSTALLER}" ]]; then
  log "No se encontró instalador interno: ${INSTALLER}"
  exit 1
fi

log "Instalando Decktroy/Sentinel X..."
bash "${INSTALLER}"

if [[ ! -x "${LAUNCHER}" ]]; then
  log "No se pudo crear el lanzador ${LAUNCHER}"
  exit 1
fi

log "Instalación completada. Iniciando GUI nativa..."
exec "${LAUNCHER}" "$@"
