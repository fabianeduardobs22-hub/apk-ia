#!/usr/bin/env bash
set -euo pipefail

info() { printf '\033[96m[INFO]\033[0m %s\n' "$1"; }
warn() { printf '\033[93m[WARN]\033[0m %s\n' "$1"; }
err()  { printf '\033[91m[ERR ]\033[0m %s\n' "$1"; }

TARGET="auto"

usage() {
  cat <<'EOF'
Uso:
  ./install_requirements.sh [--target auto|termux|apt|dnf|pacman|zypper]

Ejemplos:
  ./install_requirements.sh
  ./install_requirements.sh --target termux
  ./install_requirements.sh --target apt
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --target)
        TARGET="${2:-}"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        err "Argumento no reconocido: $1"
        usage
        exit 1
        ;;
    esac
  done
}

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
  info "Instalando en Termux (sin root)."
  pkg update -y
  pkg upgrade -y
  pkg install -y bash python git termux-api iproute2 net-tools jq curl clang libffi openssl

  info "Habilitando repositorios adicionales (si existen)..."
  pkg install -y root-repo 2>/dev/null || true
  pkg install -y unstable-repo 2>/dev/null || true

  info "Intentando paquetes Bluetooth adicionales en Termux (si están disponibles)..."
  pkg install -y bluez bluez-tools 2>/dev/null || warn "bluez/bluez-tools no disponibles en este repositorio Termux."

  info "Verificando comandos clave de Termux..."
  command -v termux-bluetooth-scan >/dev/null 2>&1 && info "termux-bluetooth-scan detectado." || warn "termux-bluetooth-scan no detectado (revisa termux-api app/permisos)."
  command -v termux-wifi-connectioninfo >/dev/null 2>&1 && info "termux-wifi-connectioninfo detectado." || warn "termux-wifi-connectioninfo no detectado."

  warn "En Termux, bluetoothctl/hcitool/sdptool pueden no estar disponibles según Android/paquetes/permisos."
  warn "Instala Termux:API (app) y concede permisos del sistema para telemetría local."
}

install_apt_family() {
  info "Detectado entorno Debian/Ubuntu/Kali (apt)."
  run_root apt-get update
  run_root apt-get install -y \
    bash python3 git bluez bluez-tools bluez-obexd \
    net-tools wireless-tools iproute2 network-manager rfkill jq curl
}

install_dnf_family() {
  info "Detectado entorno Fedora/RHEL-like (dnf)."
  run_root dnf install -y \
    bash python3 git bluez bluez-tools \
    net-tools wireless-tools iproute NetworkManager util-linux jq curl
}

install_pacman_family() {
  info "Detectado entorno Arch/Manjaro (pacman)."
  run_root pacman -Sy --noconfirm \
    bash python git bluez bluez-utils \
    net-tools wireless_tools iproute2 networkmanager util-linux jq curl
}

install_zypper_family() {
  info "Detectado entorno openSUSE/SLE (zypper)."
  run_root zypper --non-interactive install \
    bash python3 git bluez bluez-tools \
    net-tools wireless-tools iproute2 NetworkManager util-linux jq curl
}


install_python_backends() {
  info "Instalando backends Python opcionales (bleak, pybluez)..."
  python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
  python3 -m pip install bleak pybluez >/dev/null 2>&1 || warn "No se pudieron instalar bleak/pybluez con pip."
}

print_github_tools_note() {
  cat <<'EOF'

[INFO] Integración de herramientas GitHub (modo defensivo):
  - BTScanner / ScannerBleah / BlueBorne se integran por parseo de salida o adaptadores externos.
  - Este proyecto no instala ni ejecuta capacidades de explotación.
  - Si deseas usar binarios externos, instálalos manualmente y solo en entornos autorizados.
EOF
}

detect_target() {
  if is_termux; then
    echo "termux"
    return
  fi
  if command -v apt-get >/dev/null 2>&1 || os_like debian || os_like ubuntu || os_like kali; then
    echo "apt"
    return
  fi
  if command -v dnf >/dev/null 2>&1 || os_like fedora || os_like rhel || os_like centos; then
    echo "dnf"
    return
  fi
  if command -v pacman >/dev/null 2>&1 || os_like arch || os_like manjaro; then
    echo "pacman"
    return
  fi
  if command -v zypper >/dev/null 2>&1 || os_like suse || os_like opensuse; then
    echo "zypper"
    return
  fi
  echo "unknown"
}

main() {
  parse_args "$@"

  local selected="$TARGET"
  if [[ "$selected" == "auto" ]]; then
    selected="$(detect_target)"
    info "Detección automática: $selected"
  else
    info "Target forzado por usuario: $selected"
  fi

  case "$selected" in
    termux)
      install_termux
      ;;
    apt)
      install_apt_family
      ;;
    dnf)
      install_dnf_family
      ;;
    pacman)
      install_pacman_family
      ;;
    zypper)
      install_zypper_family
      ;;
    *)
      err "No se detectó un gestor soportado automáticamente (pkg/apt/dnf/pacman/zypper)."
      warn "Instala manualmente: bash, python3, git, bluez, bluez-tools, net-tools, iproute2, NetworkManager, rfkill, jq, curl."
      exit 1
      ;;
  esac

  install_python_backends
  print_github_tools_note
  info "Instalación finalizada."
}

main "$@"
