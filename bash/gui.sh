#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=bash/lib.sh
source "${ROOT_DIR}/bash/lib.sh"

_gui_with_whiptail() {
  while true; do
    local choice
    choice="$(whiptail --title "Sentinel X Bash SOC" --menu "Panel principal" 20 90 10 \
      1 "Dashboard runtime" \
      2 "Actualizar alertas desde logs" \
      3 "Exportar alertas" \
      4 "Agregar tarea" \
      5 "Ver tareas" \
      6 "Salir" 3>&1 1>&2 2>&3)" || return 0

    case "$choice" in
      1)
        whiptail --title "Dashboard" --msgbox "$(sx_collect_runtime_snapshot)" 20 90
        ;;
      2)
        local count
        count="$(sx_scan_logs_to_alerts 500)"
        whiptail --title "Alertas" --msgbox "Alertas detectadas: ${count}\nArchivo: ${SENTINELX_ALERTS_FILE}" 12 80
        ;;
      3)
        local outfile
        outfile="$(whiptail --inputbox "Ruta de exportación" 10 80 "$(pwd)/alerts_export.json" 3>&1 1>&2 2>&3)" || continue
        sx_export_alerts "$outfile"
        whiptail --msgbox "Exportado en ${outfile}" 10 80
        ;;
      4)
        local task
        task="$(whiptail --inputbox "Título de tarea" 10 80 "" 3>&1 1>&2 2>&3)" || continue
        [[ -n "$task" ]] && sx_add_task "$task" "pendiente"
        ;;
      5)
        whiptail --title "Tareas" --msgbox "$(sx_list_tasks_pretty)" 20 100
        ;;
      6)
        return 0
        ;;
    esac
  done
}

_gui_plain() {
  echo "=== Sentinel X Bash SOC (modo texto) ==="
  while true; do
    cat <<MENU
1) Dashboard runtime
2) Actualizar alertas desde logs
3) Exportar alertas
4) Agregar tarea
5) Ver tareas
6) Salir
MENU
    read -rp "Selecciona opción: " opt
    case "$opt" in
      1) sx_collect_runtime_snapshot ;;
      2) echo "Alertas detectadas: $(sx_scan_logs_to_alerts 500)" ;;
      3) read -rp "Ruta salida JSON: " out; sx_export_alerts "$out"; echo "OK" ;;
      4) read -rp "Título de tarea: " task; sx_add_task "$task" "pendiente" ;;
      5) sx_list_tasks_pretty ;;
      6) break ;;
      *) echo "Opción inválida" ;;
    esac
  done
}

main() {
  sx_bootstrap_files
  if command -v whiptail >/dev/null 2>&1; then
    _gui_with_whiptail
  else
    _gui_plain
  fi
}

main "$@"
