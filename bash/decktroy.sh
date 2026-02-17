#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=bash/lib.sh
source "${ROOT_DIR}/bash/lib.sh"

PROGRAM_NAME="decktroy"

usage() {
  cat <<USAGE
Uso: ${PROGRAM_NAME} <comando>

Comandos:
  startup [-o archivo.json]   Snapshot de host/rendimiento
  selftest                    Verificación de dependencias del sistema
  advisor [-o archivo.json]   Recomendaciones defensivas desde alertas
  gui                         GUI Bash SOC
  task add "titulo"           Agrega tarea de analista
  task list                   Lista tareas
USAGE
}

die(){ echo "[${PROGRAM_NAME}] ERROR: $*" >&2; exit 1; }

cmd_startup(){
  local out=""
  while (($#)); do
    case "$1" in
      -o|--output) shift; (($#)) || die "Falta archivo"; out="$1" ;;
      *) die "Argumento inválido: $1" ;;
    esac
    shift
  done
  sx_bootstrap_files
  local payload
  payload="$(sx_collect_runtime_snapshot)"
  if [[ -n "$out" ]]; then
    printf '%s\n' "$payload" > "$out"
    echo "Snapshot guardado en ${out}"
  else
    printf '%s\n' "$payload"
  fi
}

cmd_selftest(){
  local fail=0
  local tools=(bash awk sed grep ip ss journalctl whiptail python3)
  for t in "${tools[@]}"; do
    if command -v "$t" >/dev/null 2>&1; then
      printf 'OK   %s\n' "$t"
    else
      printf 'MISS %s\n' "$t"
      fail=1
    fi
  done
  return "$fail"
}

cmd_advisor(){
  local out=""
  while (($#)); do
    case "$1" in
      -o|--output) shift; (($#)) || die "Falta archivo"; out="$1" ;;
      *) die "Argumento inválido: $1" ;;
    esac
    shift
  done
  sx_bootstrap_files
  sx_scan_logs_to_alerts 500 >/dev/null
  local payload
  payload="$(python3 - <<'PY' "$SENTINELX_ALERTS_FILE"
import json,sys,collections,datetime
path=sys.argv[1]
alerts=json.load(open(path,encoding='utf-8')) if path else []
by_type=collections.Counter(a.get('type','unknown') for a in alerts)
by_sev=collections.Counter(a.get('severity','low') for a in alerts)
primary=by_type.most_common(1)[0][0] if by_type else 'hardening-gap'
priority='high' if by_sev.get('high',0)>0 else 'medium'
out={
 'generated_at': datetime.datetime.utcnow().replace(microsecond=0).isoformat()+'Z',
 'detected_primary_scenario': primary,
 'priority': priority,
 'total_alerts': len(alerts),
 'top_attack_types': by_type,
 'severity': by_sev,
 'recommended_actions': [
   'Aplicar hardening y MFA en servicios críticos',
   'Conservar evidencias y exportar alertas',
   'Escalar incidente al equipo SOC si hay severidad alta'
 ]
}
print(json.dumps(out,ensure_ascii=False,indent=2,default=dict))
PY
)"
  if [[ -n "$out" ]]; then
    printf '%s\n' "$payload" > "$out"
    echo "Advisor guardado en ${out}"
  else
    printf '%s\n' "$payload"
  fi
}

cmd_task(){
  local sub="${1:-}"; shift || true
  case "$sub" in
    add)
      (($#)) || die "Indica título de tarea"
      sx_add_task "$*" "pendiente"
      echo "Tarea registrada"
      ;;
    list)
      sx_list_tasks_pretty
      ;;
    *) die "Subcomando task inválido" ;;
  esac
}

main(){
  (($#)) || { usage; exit 0; }
  case "$1" in
    --help|-h) usage ;;
    startup) shift; cmd_startup "$@" ;;
    selftest) shift; cmd_selftest "$@" ;;
    advisor) shift; cmd_advisor "$@" ;;
    gui) exec "${ROOT_DIR}/bash/gui.sh" ;;
    task) shift; cmd_task "$@" ;;
    *) usage; die "Comando no reconocido: $1" ;;
  esac
}

main "$@"
