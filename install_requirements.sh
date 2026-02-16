#!/usr/bin/env bash
set -euo pipefail

info() { printf '\033[96m[INFO]\033[0m %s\n' "$1"; }
warn() { printf '\033[93m[WARN]\033[0m %s\n' "$1"; }
err()  { printf '\033[91m[ERR ]\033[0m %s\n' "$1"; }

is_termux() {
  [[ "${PREFIX:-}" == *"com.termux"* ]] || [[ -n "${TERMUX_VERSION:-}" ]]
}

needs_root() {
  [[ "${EUID:-$(id -u)}" -ne 0 ]]
}

run_root() {
  if ! needs_root; then
    "$@"
    return
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo "$@"
    return
  fi
  if command -v doas >/dev/null 2>&1; then
    doas "$@"
    return
  fi
  err "Se requieren privilegios de administrador y no se encontró sudo/doas."
  exit 1
}

os_like() {
  local key="$1"
  [[ -r /etc/os-release ]] || return 1
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "$key" ]] || [[ " ${ID_LIKE:-} " == *" ${key} "* ]]
}

install_termux() {
  info "Entorno Termux detectado (sin root)."
  pkg update -y
  pkg upgrade -y

  info "Instalando dependencias base para ejecución en Termux..."
  pkg install -y python git termux-api iproute2 net-tools

  warn "En Termux, Bluetooth de bajo nivel depende de Android y permisos del dispositivo."
  warn "Instala Termux:API y concede permisos del sistema para telemetría de red local."
  info "Instalación base en Termux finalizada."
}

install_apt_family() {
  info "Detectado entorno Debian/Ubuntu/Kali (apt)."
  run_root apt-get update
  run_root apt-get install -y \
    python3 git bluez bluez-tools bluez-obexd \
    net-tools wireless-tools iproute2 network-manager rfkill
}

install_dnf_family() {
  info "Detectado entorno Fedora/RHEL-like (dnf)."
  run_root dnf install -y \
    python3 git bluez bluez-tools \
    net-tools wireless-tools iproute NetworkManager util-linux
}

install_pacman_family() {
  info "Detectado entorno Arch/Manjaro (pacman)."
  run_root pacman -Sy --noconfirm \
    python git bluez bluez-utils \
    net-tools wireless_tools iproute2 networkmanager util-linux
}

install_zypper_family() {
  info "Detectado entorno openSUSE/SLE (zypper)."
  run_root zypper --non-interactive install \
    python3 git bluez bluez-tools \
    net-tools wireless-tools iproute2 NetworkManager util-linux
}

print_github_tools_note() {
  cat <<'EOF'

[INFO] Integración de herramientas GitHub (modo defensivo):
  - BTScanner / ScannerBleah / BlueBorne se integran por parseo de salida o adaptadores externos.
  - Este proyecto no instala ni ejecuta capacidades de explotación.
  - Si deseas usar binarios externos, instálalos manualmente y solo en entornos autorizados.
EOF
}

main() {
  if is_termux; then
    install_termux
    print_github_tools_note
    exit 0
  fi

  if command -v apt-get >/dev/null 2>&1 || os_like debian || os_like ubuntu || os_like kali; then
    install_apt_family
    print_github_tools_note
    exit 0
  fi

  if command -v dnf >/dev/null 2>&1 || os_like fedora || os_like rhel || os_like centos; then
    install_dnf_family
    print_github_tools_note
    exit 0
  fi

  if command -v pacman >/dev/null 2>&1 || os_like arch || os_like manjaro; then
    install_pacman_family
    print_github_tools_note
    exit 0
  fi

  if command -v zypper >/dev/null 2>&1 || os_like suse || os_like opensuse; then
    install_zypper_family
    print_github_tools_note
    exit 0
  fi

  err "No se detectó un gestor soportado automáticamente (pkg/apt/dnf/pacman/zypper)."
  warn "Instala manualmente: python3, git, bluez, bluez-tools, net-tools, iproute2, NetworkManager, rfkill."
  exit 1
}

main "$@"
