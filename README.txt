Guardian Network CLI
====================

Herramienta de auditoría **defensiva** para Bluetooth + WiFi con interfaz interactiva en terminal.

Características principales:
- Menú interactivo renovado (Bluetooth, WiFi, combinado, auditoría y reportes).
- Escaneo Bluetooth multi-motor sin dependencia obligatoria de `bluetoothctl` (prioriza `termux-bluetooth-scan`, `hcitool`, `btmgmt`; usa `bluetoothctl` solo como apoyo opcional).
- Escaneo WiFi defensivo usando `termux-wifi-scaninfo`, `nmcli`, `iw`, `iwlist` según disponibilidad local.
- Auditoría no intrusiva de activos detectados con recomendaciones de hardening.
- Exportación de reporte en `audit_report.json` y `audit_report.html`.
- Compatible con Termux y distribuciones Linux (incluyendo Kali), degradando funciones de forma segura cuando faltan herramientas.

Uso:

    python3 bluetooth_guardian.py

Modo rápido (sin menú):

    python3 bluetooth_guardian.py --non-interactive

Flujo sugerido:
1. Opción 1, 2 o 3 para escanear.
2. Opción 4 para auditar un activo por número.
3. Opción 5 o 6 para exportar reporte.

DECKTROY (plan defensivo para servidores):
- Documento de descubrimiento/arquitectura: `docs/DECKTROY_DISCOVERY.md`
- Script de chequeo inicial de integridad: `python3 decktroy/bootstrap_healthcheck.py`

DECKTROY CLI (blue-team defensivo):
- Instalación Linux: `./install_decktroy_linux.sh`
- Comando global: `decktroy --help` (después de instalar)
- Ejecutar ayuda: `python3 decktroy/decktroy_cli.py --help`
- Inventario: `python3 decktroy/decktroy_cli.py inventory`
- Evaluación de postura: `python3 decktroy/decktroy_cli.py assess`
- Asistente defensivo IA: `python3 decktroy/decktroy_cli.py advisor --environment auto`
- Threat feed: `python3 decktroy/decktroy_cli.py threat-feed --environment auto --lines 300`
- Servicios: `python3 decktroy/decktroy_cli.py services --action list`
- Guardia conexiones: `python3 decktroy/decktroy_cli.py connection-guard --mode analyze --duration 10`
- Incidentes: `python3 decktroy/decktroy_cli.py incident list`
- Playbooks: `python3 decktroy/decktroy_cli.py playbook list`
- Estado inicial integral: `python3 decktroy/decktroy_cli.py startup -o decktroy_startup_status.json`
- Dashboard web: `python3 decktroy/decktroy_cli.py web --host 0.0.0.0 --port 8080`
- Dashboard con control de servicios: `python3 decktroy/decktroy_cli.py web --host 0.0.0.0 --port 8080 --enable-service-control`
- Terminal visual segura en UI: `/api/execute-safe` (allowlist defensiva)
- Selftest integral: `python3 decktroy/decktroy_cli.py selftest`
- Monitor runtime: `python3 decktroy/decktroy_cli.py runtime-monitor -o decktroy_runtime_monitor.json`
- Instalación paso a paso (.txt): `INSTALL_DECKTROY.txt`
- Documentación CLI: `docs/DECKTROY_CLI.md`
- Comparativa y roadmap avanzado: `docs/DECKTROY_COMPARISON.md`

Notas importantes:
- Esta herramienta NO explota vulnerabilidades ni intenta obtener acceso no autorizado.
- Está pensada para laboratorios y auditorías con permiso explícito.
- Revisar `LEGAL_NOTICE.md` y `TERMS_OF_USE.md` antes de usar.
