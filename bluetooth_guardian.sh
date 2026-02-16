#!/usr/bin/env bash
set -euo pipefail

# Bluetooth Guardian (Bash Edition)
# Uso defensivo: inventario y postura de seguridad en entornos autorizados.

COLOR_RESET='\033[0m'
C_CYAN='\033[96m'
C_GREEN='\033[92m'
C_YELLOW='\033[93m'
C_RED='\033[91m'
C_BLUE='\033[94m'
C_MAG='\033[95m'
C_WHITE='\033[97m'

DEVICE_CACHE=".bt_guardian_devices.tsv"
RESULTS_CACHE=".bt_guardian_results.log"

printc() { printf "%b%s%b\n" "$1" "$2" "$COLOR_RESET"; }

banner() {
  printc "$C_CYAN" "╔═══════════════════════════════════════════════════════════════════════╗"
  printc "$C_CYAN" "║                    BLUETOOTH GUARDIAN (BASH EDITION)                 ║"
  printc "$C_CYAN" "║          Auditoría defensiva portable para Termux y Linux            ║"
  printc "$C_CYAN" "╚═══════════════════════════════════════════════════════════════════════╝"
}

progress() {
  local title="$1"; local steps="${2:-20}"; local style="${3:-matrix}"; local delay="${4:-0.02}"
  local -a frames
  case "$style" in
    pulse) frames=("◐" "◓" "◑" "◒") ;;
    radar) frames=("◜" "◠" "◝" "◞" "◡" "◟") ;;
    *) frames=("▁" "▂" "▃" "▄" "▅" "▆" "▇" "█") ;;
  esac

  printc "$C_YELLOW" ""
  printc "$C_YELLOW" "▶ $title"
  for ((i=0; i<=steps; i++)); do
    local width=34
    local filled=$(( i * width / steps ))
    local percent=$(( i * 100 / steps ))
    local frame="${frames[$((i % ${#frames[@]}))]}"
    local bar=""
    for ((j=0; j<filled; j++)); do bar+="█"; done
    for ((j=filled; j<width; j++)); do bar+="░"; done
    printf "\r   %s [%s] %3d%%" "$frame" "$bar" "$percent"
    sleep "$delay"
  done
  printf "\n"
}

is_termux() {
  [[ "${PREFIX:-}" == *"com.termux"* ]] || [[ -n "${TERMUX_VERSION:-}" ]]
}

check_dep() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1
}

dependency_status() {
  progress "Verificando dependencias" 8 matrix 0.015
  printc "$C_MAG" ""
  printc "$C_MAG" "Estado de dependencias"

  local deps=(python3 git)
  if is_termux; then
    deps+=(termux-bluetooth-scan termux-wifi-connectioninfo)
  else
    deps+=(bluetoothctl hcitool sdptool btmgmt nmcli iwgetid)
  fi

  for dep in "${deps[@]}"; do
    if check_dep "$dep"; then
      printc "$C_GREEN" "  ✔ $(printf '%-24s' "$dep") $(command -v "$dep")"
    else
      printc "$C_RED" "  ✖ $(printf '%-24s' "$dep") no instalado"
    fi
  done

  if is_termux; then
    for classic in bluetoothctl hcitool sdptool; do
      if check_dep "$classic"; then
        printc "$C_GREEN" "  ✔ $(printf '%-24s' "$classic") $(command -v "$classic")"
      else
        printc "$C_YELLOW" "  ⚠ $(printf '%-24s' "$classic") no disponible en Termux (limitación Android/paquetes)"
      fi
    done
  fi
}

append_device() {
  local mac="$1" name="$2" source="$3"
  [[ -z "$mac" ]] && return
  printf "%s\t%s\t%s\n" "$mac" "$name" "$source" >> "$DEVICE_CACHE"
}

scan_termux() {
  check_dep termux-bluetooth-scan || return 0
  local out
  out="$(termux-bluetooth-scan 2>/dev/null || true)"
  [[ -z "$out" ]] && return 0

  if check_dep jq; then
    while IFS=$'\t' read -r mac name; do
      append_device "${mac^^}" "${name:-unknown}" "termux-bluetooth-scan"
    done < <(printf '%s' "$out" | jq -r '.[] | [.address // .mac // "", .name // .alias // "unknown"] | @tsv' 2>/dev/null || true)
  else
    while IFS= read -r line; do
      [[ "$line" =~ ([0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}) ]] || continue
      append_device "${BASH_REMATCH[1]^^}" "unknown" "termux-bluetooth-scan"
    done <<< "$out"
  fi
}

scan_bluetoothctl() {
  check_dep bluetoothctl || return 0
  while IFS= read -r line; do
    [[ "$line" =~ ^Device[[:space:]]+([0-9A-F:]{17})[[:space:]]+(.+)$ ]] || continue
    append_device "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "bluetoothctl"
  done < <(bluetoothctl devices 2>/dev/null || true)

  while IFS= read -r line; do
    [[ "$line" =~ ^Device[[:space:]]+([0-9A-F:]{17})[[:space:]]+(.+)$ ]] || continue
    append_device "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "paired-devices"
  done < <(bluetoothctl paired-devices 2>/dev/null || true)
}

scan_hcitool() {
  check_dep hcitool || return 0
  while IFS= read -r line; do
    [[ "$line" =~ ^([0-9A-F:]{17})[[:space:]]+(.+)$ ]] || continue
    append_device "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "hcitool"
  done < <(hcitool scan 2>/dev/null | sed '1d' | sed 's/^\t//')
}

scan_btmgmt() {
  check_dep btmgmt || return 0
  while IFS= read -r line; do
    [[ "$line" =~ dev_found[[:space:]]+([0-9A-F:]{17}).*name[[:space:]]+(.+)$ ]] || continue
    append_device "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "btmgmt"
  done < <(btmgmt find 2>/dev/null || true)
}

dedupe_devices() {
  [[ -f "$DEVICE_CACHE" ]] || return 0
  awk -F'\t' '!seen[toupper($1)]++ {print $0}' "$DEVICE_CACHE" | sort > "${DEVICE_CACHE}.tmp"
  mv "${DEVICE_CACHE}.tmp" "$DEVICE_CACHE"
}

show_devices() {
  printc "$C_GREEN" ""
  printc "$C_GREEN" "Dispositivos detectados"
  printf '%s\n' '--------------------------------------------------------------------------------'
  printf '%-4s%-22s%-34s%-20s\n' '#' 'MAC' 'Nombre' 'Fuente'
  printf '%s\n' '--------------------------------------------------------------------------------'

  if [[ ! -s "$DEVICE_CACHE" ]]; then
    printc "$C_RED" "No se detectaron dispositivos."
    printf '%s\n' '--------------------------------------------------------------------------------'
    return
  fi

  local i=1
  while IFS=$'\t' read -r mac name source; do
    printf '%-4s%-22s%-34s%-20s\n' "$i" "$mac" "${name:0:32}" "$source"
    ((i++))
  done < "$DEVICE_CACHE"
  printf '%s\n' '--------------------------------------------------------------------------------'
}

scan_devices() {
  : > "$DEVICE_CACHE"
  progress "Escaneando entorno Bluetooth (Bash multi-motor)" 20 radar 0.02

  progress "Motor Termux/API" 6 pulse 0.012
  scan_termux

  progress "Motor bluetoothctl" 6 pulse 0.012
  scan_bluetoothctl

  progress "Motor hcitool" 6 pulse 0.012
  scan_hcitool

  progress "Motor btmgmt" 6 pulse 0.012
  scan_btmgmt

  dedupe_devices
  show_devices
}

host_network_info() {
  progress "Recolectando contexto de red local" 10 pulse 0.015
  printc "$C_MAG" ""
  printc "$C_MAG" "Contexto de red del host local"

  local platform_name="linux"
  is_termux && platform_name="termux"

  local public_ip="no-disponible"
  public_ip="$(curl -s --max-time 4 https://api.ipify.org || true)"
  [[ -z "$public_ip" ]] && public_ip="no-disponible"

  local iface="no-disponible" gw="no-disponible"
  local route_out
  route_out="$(ip route 2>/dev/null || true)"
  if [[ "$route_out" =~ default[[:space:]]+via[[:space:]]+([^[:space:]]+)[[:space:]]+dev[[:space:]]+([^[:space:]]+) ]]; then
    gw="${BASH_REMATCH[1]}"
    iface="${BASH_REMATCH[2]}"
  fi

  local ssid="no-disponible" bssid="no-disponible"
  if check_dep termux-wifi-connectioninfo; then
    local wj
    wj="$(termux-wifi-connectioninfo 2>/dev/null || true)"
    if check_dep jq; then
      ssid="$(printf '%s' "$wj" | jq -r '.ssid // "no-disponible"' 2>/dev/null || echo 'no-disponible')"
      bssid="$(printf '%s' "$wj" | jq -r '.bssid // "no-disponible"' 2>/dev/null || echo 'no-disponible')"
      local wi
      wi="$(printf '%s' "$wj" | jq -r '.interface // empty' 2>/dev/null || true)"
      [[ -n "$wi" ]] && iface="$wi"
    fi
  elif check_dep iwgetid; then
    ssid="$(iwgetid -r 2>/dev/null || true)"
    [[ -z "$ssid" ]] && ssid="no-disponible"
  fi

  printf '  • %-10s: %s\n' platform "$platform_name"
  printf '  • %-10s: %s\n' public_ip "$public_ip"
  printf '  • %-10s: %s\n' interface "$iface"
  printf '  • %-10s: %s\n' gateway "$gw"
  printf '  • %-10s: %s\n' wifi_ssid "$ssid"
  printf '  • %-10s: %s\n' wifi_bssid "$bssid"
}

auditar_dispositivo() {
  if [[ ! -s "$DEVICE_CACHE" ]]; then
    printc "$C_RED" "Primero debes escanear dispositivos."
    return
  fi

  show_devices
  read -r -p "Ingresa el número del dispositivo a auditar: " idx
  [[ "$idx" =~ ^[0-9]+$ ]] || { printc "$C_RED" "Entrada inválida."; return; }

  local line
  line="$(sed -n "${idx}p" "$DEVICE_CACHE" || true)"
  [[ -n "$line" ]] || { printc "$C_RED" "Número fuera de rango."; return; }

  IFS=$'\t' read -r mac name source <<< "$line"
  progress "Analizando superficie de $mac" 14 pulse 0.015

  printc "$C_BLUE" ""
  printc "$C_BLUE" "Hallazgos del análisis"

  if check_dep bluetoothctl; then
    local info
    info="$(bluetoothctl info "$mac" 2>/dev/null || true)"
    if grep -qi 'Trusted: yes' <<< "$info"; then
      printc "$C_YELLOW" "  [MEDIUM] Dispositivo marcado como Trusted"
      printc "$C_WHITE" "      Acción: revisar confianza persistente."
    fi
    if grep -qi 'Paired: yes' <<< "$info"; then
      printc "$C_CYAN" "  [INFO] Dispositivo emparejado"
      printc "$C_WHITE" "      Acción: validar legitimidad del pareado."
    fi
  fi

  if check_dep sdptool; then
    local sdp
    sdp="$(sdptool browse --tree "$mac" 2>/dev/null || true)"
    if grep -qi 'OBEX\|Serial Port\|Human Interface Device\|Audio Sink' <<< "$sdp"; then
      printc "$C_YELLOW" "  [MEDIUM] Se detectaron perfiles con superficie relevante"
      printc "$C_WHITE" "      Acción: restringir visibilidad y endurecer políticas de emparejamiento."
    else
      printc "$C_CYAN" "  [INFO] Sin perfiles críticos obvios en salida SDP"
    fi
  else
    printc "$C_CYAN" "  [INFO] sdptool no disponible; análisis SDP omitido."
  fi

  printf '%s\t%s\t%s\n' "$mac" "$name" "$source" >> "$RESULTS_CACHE"
}

blueborne_posture() {
  progress "Evaluando postura BlueBorne defensiva" 10 matrix 0.015
  printc "$C_BLUE" ""
  printc "$C_BLUE" "Hallazgos del análisis"

  local kernel
  kernel="$(uname -r 2>/dev/null || echo 'desconocido')"
  printc "$C_CYAN" "  [INFO] Kernel local: $kernel"

  local bluez_ver="desconocida"
  check_dep bluetoothd && bluez_ver="$(bluetoothd -v 2>/dev/null || echo 'desconocida')"
  printc "$C_CYAN" "  [INFO] BlueZ: $bluez_ver"

  if [[ "$bluez_ver" =~ ^([0-9]+)\.([0-9]+) ]]; then
    local maj="${BASH_REMATCH[1]}" min="${BASH_REMATCH[2]}"
    if (( maj < 5 || (maj == 5 && min < 48) )); then
      printc "$C_RED" "  [HIGH] Versión BlueZ potencialmente obsoleta"
      printc "$C_WHITE" "      Acción: actualizar stack BlueZ y aplicar parches de seguridad."
    fi
  fi
}

summary() {
  progress "Generando resumen de sesión" 8 pulse 0.015
  printc "$C_CYAN" ""
  printc "$C_CYAN" "Resumen de sesión"
  printf '%s\n' '================================================================================'

  host_network_info

  local count=0
  [[ -f "$RESULTS_CACHE" ]] && count="$(wc -l < "$RESULTS_CACHE" | tr -d ' ')"
  printc "$C_GREEN" ""
  printc "$C_GREEN" "Auditorías ejecutadas: $count"

  if [[ -s "$RESULTS_CACHE" ]]; then
    local i=1
    while IFS=$'\t' read -r mac name source; do
      printf "[%d] %s (%s) via %s\n" "$i" "$name" "$mac" "$source"
      ((i++))
    done < "$RESULTS_CACHE"
  fi

  printf '%s\n' '================================================================================'
}

menu() {
  printc "$C_CYAN" ""
  printc "$C_CYAN" "Panel interactivo"
  local options=(
    "1) Escanear dispositivos Bluetooth"
    "2) Auditar dispositivo por número"
    "3) Ver contexto de red del host local"
    "4) Evaluar postura BlueBorne (defensivo)"
    "5) Ver resumen de sesión"
    "6) Salir"
  )
  for o in "${options[@]}"; do
    sleep 0.05
    printc "$C_WHITE" "  $o"
  done
  printf "%b" "${C_YELLOW}\nSelecciona una opción: ${COLOR_RESET}"
}

main() {
  local non_interactive="0"
  [[ "${1:-}" == "--non-interactive" ]] && non_interactive="1"

  : > "$DEVICE_CACHE"
  : > "$RESULTS_CACHE"

  banner
  printc "$C_YELLOW" "Uso permitido: laboratorio propio y pentest autorizado."
  printc "$C_RED" "No realiza explotación, bypass de autenticación ni reverse shell."

  dependency_status

  if [[ "$non_interactive" == "1" ]]; then
    scan_devices
    host_network_info
    return 0
  fi

  while true; do
    menu
    read -r choice
    case "$choice" in
      1) scan_devices ;;
      2) auditar_dispositivo ;;
      3) host_network_info ;;
      4) blueborne_posture ;;
      5) summary ;;
      6) printc "$C_CYAN" "\nFinalizado."; break ;;
      *) printc "$C_RED" "Opción inválida. Intenta de nuevo." ;;
    esac
  done

  rm -f "$DEVICE_CACHE" "$RESULTS_CACHE"
}

main "$@"
