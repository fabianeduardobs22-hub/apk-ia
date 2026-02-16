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

Notas importantes:
- Esta herramienta NO explota vulnerabilidades ni intenta obtener acceso no autorizado.
- Está pensada para laboratorios y auditorías con permiso explícito.
- Revisar `LEGAL_NOTICE.md` y `TERMS_OF_USE.md` antes de usar.
