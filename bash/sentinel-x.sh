#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=bash/lib.sh
source "${ROOT_DIR}/bash/lib.sh"

PROGRAM_NAME="sentinel-x"
CONFIG="sentinel_x.yaml"

usage() {
  cat <<USAGE
Uso: ${PROGRAM_NAME} [--config ruta] <comando>

Comandos:
  quickstart                   Inicializa datos y abre GUI Bash
  init-config                  Genera archivo de configuración YAML (Bash)
  run [--max-packets N]        Escaneo defensivo de logs y snapshot
  gui                          Abre GUI Bash (whiptail/texto)
  export-alerts --output FILE  Exporta alertas JSON
USAGE
}

die(){ echo "[${PROGRAM_NAME}] ERROR: $*" >&2; exit 1; }

init_config() {
  cat > "$CONFIG" <<YAML
app:
  mode: defensive
  runtime: bash
storage:
  home: ${SENTINELX_HOME}
  alerts: ${SENTINELX_ALERTS_FILE}
  tasks: ${SENTINELX_TASKS_FILE}
capture:
  source: system_logs
YAML
  echo "Configuración creada en ${CONFIG}"
}

run_monitor() {
  local max_lines=500
  while (($#)); do
    case "$1" in
      --max-packets)
        shift; (($#)) || die "Falta valor para --max-packets"; max_lines="$1";;
      --simulate)
        ;;
      *) die "Argumento no soportado en run: $1" ;;
    esac
    shift
  done
  sx_bootstrap_files
  local c
  c="$(sx_scan_logs_to_alerts "$max_lines")"
  echo "[run] alertas detectadas: ${c}"
  sx_collect_runtime_snapshot > "${SENTINELX_DATA_DIR}/runtime_snapshot.json"
  echo "[run] snapshot: ${SENTINELX_DATA_DIR}/runtime_snapshot.json"
}

export_alerts_cmd() {
  local output=""
  while (($#)); do
    case "$1" in
      --output) shift; (($#)) || die "Falta ruta en --output"; output="$1" ;;
      *) die "Argumento no soportado: $1" ;;
    esac
    shift
  done
  [[ -n "$output" ]] || die "Debes indicar --output"
  sx_export_alerts "$output"
  echo "Alertas exportadas: ${output}"
}

ARGS=()
while (($#)); do
  case "$1" in
    --config) shift; (($#)) || die "Falta valor para --config"; CONFIG="$1" ;;
    --help|-h) usage; exit 0 ;;
    *) ARGS+=("$1") ;;
  esac
  shift
done

((${#ARGS[@]})) || ARGS=(quickstart)
cmd="${ARGS[0]}"
rest=("${ARGS[@]:1}")

case "$cmd" in
  quickstart)
    sx_bootstrap_files
    [[ -f "$CONFIG" ]] || init_config
    exec "${ROOT_DIR}/bash/gui.sh"
    ;;
  init-config) init_config ;;
  run) run_monitor "${rest[@]}" ;;
  gui) exec "${ROOT_DIR}/bash/gui.sh" ;;
  export-alerts) export_alerts_cmd "${rest[@]}" ;;
  *) usage; die "Comando no reconocido: ${cmd}" ;;
esac
