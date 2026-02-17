#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"

RESET='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'
CYAN='\033[36m'
GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
WHITE='\033[97m'
BG_DARK='\033[48;5;235m'
BG_PANEL='\033[48;5;237m'

MENU_ITEMS=(
  "Dashboard"
  "Decktroy CLI"
  "Decktroy Web"
  "Full System Check"
  "Runtime Monitor"
  "Incident Center"
  "Defensive Scanner"
  "Detection Engine"
  "ML Detection"
  "Forensics Export"
  "Plugin Manager"
  "Integrity Monitor"
  "Settings"
  "Exit"
)

selected=0

cleanup() {
  tput sgr0 || true
  tput cnorm || true
}

boot_animation() {
  clear
  printf "%b" "${CYAN}${BOLD}"
  printf "Inicializando Sentinel-X SOC: "
  for _ in $(seq 1 28); do
    printf "█"
    sleep 0.02
  done
  printf "\n${DIM}Cargando módulos Decktroy + Sentinel-X...${RESET}\n"
  sleep 0.5
}

draw_frame() {
  local cols rows menu_width panel_width i item marker
  cols="$(tput cols)"
  rows="$(tput lines)"

  menu_width=28
  panel_width=$((cols - menu_width - 4))
  ((panel_width < 32)) && panel_width=32

  tput cup 0 0
  printf "%b%-*s%b\n" "${BG_DARK}${WHITE}${BOLD}" "$cols" "  SENTINEL-X SOC CONTROL CENTER" "${RESET}"
  printf "%b%-*s%b\n" "${BG_DARK}" "$cols" "" "${RESET}"

  for ((i=0; i<rows-5; i++)); do
    tput cup $((i + 2)) 0
    if (( i < ${#MENU_ITEMS[@]} )); then
      item="${MENU_ITEMS[$i]}"
      if (( i == selected )); then
        marker="▸"
        printf "%b %-1s %-*s %b│ %b%-*s%b" \
          "${BG_PANEL}${CYAN}${BOLD}" "$marker" $((menu_width - 4)) "$item" "${RESET}" \
          "${BG_DARK}${DIM}" "$panel_width" "" "${RESET}"
      else
        marker=" "
        printf "%b %-1s %-*s %b│ %b%-*s%b" \
          "${BG_DARK}${WHITE}" "$marker" $((menu_width - 4)) "$item" "${RESET}" \
          "${BG_DARK}${DIM}" "$panel_width" "" "${RESET}"
      fi
    else
      printf "%b %-*s %b│ %b%-*s%b" \
        "${BG_DARK}" $((menu_width - 1)) "" "${RESET}" \
        "${BG_DARK}${DIM}" "$panel_width" "" "${RESET}"
    fi
  done

  tput cup $((rows - 2)) 0
  printf "%b%-*s%b\n" "${BG_DARK}" "$cols" "" "${RESET}"
  tput cup $((rows - 1)) 0
  printf "%b ${GREEN}Status${WHITE}: ONLINE  |  ${GREEN}Python${WHITE}: %s  |  ${GREEN}Mode${WHITE}: SECURE%b" \
    "${BG_DARK}${WHITE}" "$($PYTHON --version 2>&1)" "${RESET}"
}

show_panel_message() {
  local msg="$1"
  local rows
  rows="$(tput lines)"
  tput cup 3 33
  printf "%b%-60s%b" "${CYAN}${BOLD}" "PANEL DERECHO" "${RESET}"
  tput cup 5 33
  printf "%b%-80s%b" "${WHITE}" "$msg" "${RESET}"
  tput cup $((rows - 3)) 33
  printf "%bPresiona Enter para continuar...%b" "${DIM}" "${RESET}"
  read -r _
}

settings_menu() {
  clear
  cat <<'MENU'
⚙ SETTINGS PANEL

1) Instalar dependencias
2) Ver requirements
3) Ver entorno Python
0) Volver
MENU
  read -rp "Selecciona opción: " opt
  case "$opt" in
    1) pip install -r "$PROJECT_ROOT/requirements.txt" ;;
    2) ${PAGER:-less} "$PROJECT_ROOT/requirements.txt" ;;
    3) "$PYTHON" --version ;;
    0) return ;;
    *) echo "Opción inválida" ;;
  esac
  read -rp "Presiona Enter para volver..." _
}

run_selected() {
  clear
  case "${MENU_ITEMS[$selected]}" in
    "Dashboard")
      draw_frame
      show_panel_message "Sistema listo para operaciones defensivas."
      ;;
    "Decktroy CLI") "$PYTHON" -m decktroy.decktroy_cli ;;
    "Decktroy Web") "$PYTHON" -m decktroy.decktroy_web ;;
    "Full System Check") "$PYTHON" -m decktroy.full_system_check ;;
    "Runtime Monitor") "$PYTHON" -m decktroy.runtime_monitor ;;
    "Incident Center") "$PYTHON" -m decktroy.incident_center ;;
    "Defensive Scanner") "$PYTHON" -m sentinel_x_defense_suite.scanner.defensive_scanner ;;
    "Detection Engine") "$PYTHON" -m sentinel_x_defense_suite.detection.engine ;;
    "ML Detection") "$PYTHON" -m sentinel_x_defense_suite.detection.ml ;;
    "Forensics Export") "$PYTHON" -m sentinel_x_defense_suite.forensics.exporters ;;
    "Plugin Manager") "$PYTHON" -m sentinel_x_defense_suite.plugins.manager ;;
    "Integrity Monitor") "$PYTHON" -m sentinel_x_defense_suite.security.integrity ;;
    "Settings") settings_menu ;;
    "Exit") exit 0 ;;
  esac
}

read_key() {
  local key
  IFS= read -rsn1 key || return 1
  if [[ "$key" == $'\x1b' ]]; then
    IFS= read -rsn2 -t 0.05 key || true
    case "$key" in
      '[A') echo "up" ;;
      '[B') echo "down" ;;
      *) echo "other" ;;
    esac
    return 0
  fi

  if [[ "$key" == "k" ]]; then
    echo "up"
  elif [[ "$key" == "j" ]]; then
    echo "down"
  elif [[ -z "$key" ]]; then
    echo "enter"
  else
    echo "other"
  fi
}

main_loop() {
  trap cleanup EXIT
  tput civis || true
  while true; do
    draw_frame
    case "$(read_key)" in
      up)
        ((selected--))
        (( selected < 0 )) && selected=$((${#MENU_ITEMS[@]} - 1))
        ;;
      down)
        ((selected++))
        (( selected >= ${#MENU_ITEMS[@]} )) && selected=0
        ;;
      enter)
        run_selected
        ;;
    esac
  done
}

boot_animation
main_loop
