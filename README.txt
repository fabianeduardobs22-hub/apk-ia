Bluetooth Guardian CLI
======================

Herramienta de auditoría Bluetooth **defensiva** con interfaz progresiva en terminal.

Características principales:
- Menú interactivo con opciones numéricas.
- Escaneo de dispositivos por `bluetoothctl`, `paired-devices` y `hcitool`.
- Auditoría no intrusiva del dispositivo seleccionado.
- Identificación de superficie expuesta (servicios/perfiles SDP) para hardening.
- Exportación de reporte en `audit_report.json` y `audit_report.html` (estilo cyber visual).

Uso:

    python3 bluetooth_guardian.py

Modo rápido (sin menú):

    python3 bluetooth_guardian.py --non-interactive

Flujo sugerido:
1. Opción 1: Escanear dispositivos.
2. Opción 2: Seleccionar dispositivo por número y auditar.
3. Opción 3 o 4: Exportar reporte.

Notas importantes:
- Esta herramienta NO explota vulnerabilidades ni intenta obtener acceso no autorizado.
- Está pensada para laboratorios y auditorías con permiso explícito.
- Revisar `LEGAL_NOTICE.md` y `TERMS_OF_USE.md` antes de usar.
