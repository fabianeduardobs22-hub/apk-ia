# DECKTROY CLI + Dashboard (Blue Team)

CLI avanzada para operaciones de **defensa**, hardening y respuesta a incidentes en Linux.

## Alcance de seguridad

Esta suite está diseñada para:
- monitoreo de postura defensiva,
- verificación de controles,
- apoyo operativo con playbooks,
- dashboard visual para operación,
- ejecución restringida de comandos de solo defensa.

No incluye funciones de intrusión, explotación ni contraataque ofensivo.

## Instalación Linux

```bash
./install_decktroy_linux.sh
```

Esto instala el launcher `decktroy` en `~/.local/bin/decktroy`.

## Comandos

### 1) Inventario

```bash
decktroy inventory
decktroy inventory -o decktroy_inventory.json
```

### 2) Evaluación defensiva

```bash
decktroy assess
decktroy assess -o decktroy_assessment.json
```

### 3) Asistente IA defensiva

```bash
decktroy advisor --environment auto
decktroy advisor --environment prod -o decktroy_advisor.json
```

Genera recomendaciones tácticas defensivas y ruta de respuesta legal/forense.

### 4) Feed de ciberataques (tiempo real desde logs)

```bash
decktroy threat-feed --environment auto --lines 300
decktroy threat-feed --environment prod -o decktroy_threat_feed.json
```

Genera eventos, severidades, top IPs y top tipos de ataque para operación defensiva.

### 5) Gestión de servicios (estado/modificación)

```bash
decktroy services --action list
decktroy services --action status --name nginx
decktroy services --action restart --name nginx --apply
```

> `--apply` requiere privilegios root y ejecuta cambios reales.

### 6) Guardia automática de conexiones (ML baseline + anomalías)

```bash
decktroy connection-guard --mode learn --duration 30
decktroy connection-guard --mode analyze --duration 10
decktroy connection-guard --mode watch --duration 60 --interval 5
# aplicar bloqueo defensivo (root + ufw):
decktroy connection-guard --mode analyze --apply-block
```

Detecta patrones fuera de baseline, señales tipo escaneo (Nmap-like), genera alertas y acciones defensivas sugeridas/automatizables.

### 7) Centro de incidentes (case management)

```bash
decktroy incident list
decktroy incident create --title "Suspicious scanner" --severity high --source connection_guard --details "Multiple ports"
decktroy incident status --id INC-000001 --status investigating --note "Analista asignado"
decktroy incident evidence --id INC-000001 --path /var/log/auth.log --note "auth evidence"
decktroy incident from-guard
```

Permite trazabilidad de incidentes, timeline y evidencia con hash SHA-256.

### 8) Estado integral de inicio

```bash
decktroy startup
decktroy startup -o decktroy_startup_status.json
```

Genera un JSON de estado completo al iniciar con:
- compatibilidad Linux,
- snapshot técnico,
- hallazgos de evaluación,
- resultado de `bootstrap_healthcheck`.

### 9) Dashboard web (CLI gráfica)

```bash
decktroy web --host 0.0.0.0 --port 8080 --refresh 5
decktroy web --host 0.0.0.0 --port 8080 --enable-service-control
```

Rutas:
- `/` panel visual de control defensivo.
- `/api/status` estado en JSON para integraciones.
- Menú visual incluye: Dashboard, Estado servidor, Conexiones, Logs, Playbooks, Asistente IA, Mapa ataques (3D simplificado), Servicios, Ajustes, Guardia conexiones e Incidentes.
- UI mejorada con popups operativos, terminal visual segura (allowlist), KPI tácticos y globo 3D con silueta continental para contexto geográfico defensivo.

### 10) Playbooks

```bash
decktroy playbook list
decktroy playbook show isolate-service
decktroy playbook show bruteforce-shield
decktroy playbook show ddos-rate-limit
```

### 11) Ejecutor restringido

```bash
decktroy execute ss -tulpen
decktroy execute ufw status verbose
```

Solo permite una lista blanca de comandos defensivos no destructivos.

## Flujo recomendado de operación

1. `decktroy startup` para validar estado integral al iniciar.
2. `decktroy web --host 0.0.0.0 --port 8080` para control visual.
3. `decktroy assess` para priorizar brechas.
4. `decktroy playbook show <nombre>` para respuesta guiada.
5. Registrar resultados en SIEM/ticketing.



### 12) Monitor de ejecución integral

```bash
decktroy runtime-monitor
decktroy runtime-monitor -o decktroy_runtime_monitor.json
```

Ejecuta validaciones de disponibilidad sobre módulos clave y genera un reporte de salud operativa sin alterar la arquitectura del sistema.

### 13) Verificación total

```bash
decktroy selftest
# o
python3 decktroy/full_system_check.py
```

Genera `decktroy_full_system_check.json` validando módulos uno por uno.


## Referencia estratégica

- Comparativa con suites avanzadas y roadmap de mejora: `docs/DECKTROY_COMPARISON.md`.
