#!/usr/bin/env bash
set -euo pipefail

SENTINELX_HOME_DEFAULT="${HOME}/.local/share/sentinelx-bash"
SENTINELX_HOME="${SENTINELX_HOME:-$SENTINELX_HOME_DEFAULT}"
SENTINELX_DATA_DIR="${SENTINELX_DATA_DIR:-$SENTINELX_HOME/data}"
SENTINELX_LOG_DIR="${SENTINELX_LOG_DIR:-$SENTINELX_HOME/logs}"
SENTINELX_ALERTS_FILE="${SENTINELX_ALERTS_FILE:-$SENTINELX_DATA_DIR/alerts.json}"
SENTINELX_TASKS_FILE="${SENTINELX_TASKS_FILE:-$SENTINELX_DATA_DIR/tasks.tsv}"

sx_mkdirs() {
  mkdir -p "$SENTINELX_HOME" "$SENTINELX_DATA_DIR" "$SENTINELX_LOG_DIR"
}

sx_now() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

sx_json_escape() {
  python3 - <<'PY' "$1"
import json,sys
print(json.dumps(sys.argv[1]))
PY
}

sx_detect_tool() {
  command -v "$1" >/dev/null 2>&1
}

sx_bootstrap_files() {
  sx_mkdirs
  [[ -f "$SENTINELX_ALERTS_FILE" ]] || printf '[]\n' > "$SENTINELX_ALERTS_FILE"
  [[ -f "$SENTINELX_TASKS_FILE" ]] || : > "$SENTINELX_TASKS_FILE"
}

sx_collect_runtime_snapshot() {
  local host kernel distro uptime_s mem_free mem_total load1 ips
  host="$(hostname 2>/dev/null || echo unknown)"
  kernel="$(uname -r 2>/dev/null || echo unknown)"
  distro="$(grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"' || echo unknown)"
  uptime_s="$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)"
  read -r mem_total mem_free < <(awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{print t+0, a+0}' /proc/meminfo 2>/dev/null || echo "0 0")
  load1="$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0)"
  ips="$(ip -brief a 2>/dev/null | awk '{print $1":"$3}' | tr '\n' ';' || true)"

  cat <<JSON
{
  "timestamp": "$(sx_now)",
  "host": $(sx_json_escape "$host"),
  "kernel": $(sx_json_escape "$kernel"),
  "distro": $(sx_json_escape "$distro"),
  "uptime_seconds": ${uptime_s},
  "memory_kb": {"total": ${mem_total}, "available": ${mem_free}},
  "load_1m": ${load1},
  "interfaces": $(sx_json_escape "$ips")
}
JSON
}

sx_scan_logs_to_alerts() {
  sx_bootstrap_files
  local max_lines="${1:-300}" source logs
  if sx_detect_tool journalctl; then
    source="journalctl"
    logs="$(journalctl -n "$max_lines" --no-pager 2>/dev/null || true)"
  elif [[ -f /var/log/auth.log ]]; then
    source="auth.log"
    logs="$(tail -n "$max_lines" /var/log/auth.log 2>/dev/null || true)"
  else
    source="none"
    logs=""
  fi

  python3 - <<'PY' "$logs" "$SENTINELX_ALERTS_FILE" "$source"
import json,re,sys,datetime
raw, path, source = sys.argv[1], sys.argv[2], sys.argv[3]
ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
patterns = [
    ("bruteforce", "high", ["failed password","invalid user","authentication failure"]),
    ("ddos", "high", ["flood","ddos","too many requests","rate limit"]),
    ("web_injection", "high", ["xss","sql","injection","union select","<script"]),
    ("privilege_abuse", "high", ["sudo","permission denied","unauthorized"]),
]
alerts=[]
for line in raw.splitlines()[-500:]:
    low=line.lower()
    kind="suspicious_activity"; sev="medium"
    for k,s,keys in patterns:
      if any(x in low for x in keys):
        kind,sev=k,s
        break
    ips=ip_re.findall(line)
    if not ips and kind=="suspicious_activity":
      continue
    alerts.append({
      "timestamp": datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z",
      "type": kind,
      "severity": sev,
      "source_ip": ips[0] if ips else "n/a",
      "raw": line[:260],
      "source": source,
    })
with open(path,"w",encoding="utf-8") as f:
  json.dump(alerts,f,ensure_ascii=False,indent=2)
print(len(alerts))
PY
}

sx_export_alerts() {
  sx_bootstrap_files
  local out="$1"
  cp "$SENTINELX_ALERTS_FILE" "$out"
}

sx_add_task() {
  sx_bootstrap_files
  local title="$1" status="${2:-pendiente}" ts
  ts="$(sx_now)"
  printf '%s\t%s\t%s\n' "$ts" "$status" "$title" >> "$SENTINELX_TASKS_FILE"
}

sx_list_tasks_pretty() {
  sx_bootstrap_files
  if [[ ! -s "$SENTINELX_TASKS_FILE" ]]; then
    echo "Sin tareas registradas"
    return
  fi
  awk -F'\t' 'BEGIN{printf "%-22s %-12s %s\n", "Timestamp", "Estado", "Título"}
{printf "%-22s %-12s %s\n",$1,$2,$3}' "$SENTINELX_TASKS_FILE"
}
