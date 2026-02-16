Bluetooth Guardian CLI
======================

Herramienta de auditoría Bluetooth **defensiva** con interfaz progresiva en terminal.

Características principales
---------------------------

- Menú interactivo con opciones numéricas y animaciones de progreso.
- Barras de progreso en todas las tareas principales (verificación, escaneo, auditoría, postura, importación, resumen).
- Escaneo Bluetooth unificado multi-motor:
  - `bluetoothctl devices` / `paired-devices`
  - `bluetoothctl` escaneo activo temporal
  - `hcitool scan`
  - `btmgmt find`
- Auditoría no intrusiva del dispositivo seleccionado (`info` + servicios SDP).
- Evaluación de postura **BlueBorne** defensiva (kernel/BlueZ local + recomendaciones).
- Integración defensiva de herramientas externas:
  - Importación desde archivo con parseo de MAC (salidas tipo BTScanner/ScannerBleah).
  - Adaptadores externos de ejecución para inventario no intrusivo.
- Descubrimiento de contexto de red del **host local** (IP pública, interfaz, gateway, SSID/BSSID cuando esté disponible).
- Resumen de auditoría en terminal en tiempo real (sin salida HTML).

Instalación de requisitos
-------------------------

Ejecuta:

    ./install_requirements.sh

Detección automática de entorno / gestor:
- **Termux en Android sin root** (`pkg`) ✅
- **Kali/Ubuntu/Debian** (`apt`) ✅
- **Fedora/RHEL-like** (`dnf`) ✅
- **Arch/Manjaro** (`pacman`) ✅
- **openSUSE/SLE** (`zypper`) ✅

El instalador también detecta si requiere privilegios de administrador y usa `sudo`/`doas` cuando aplica (Termux no requiere root para su parte base).

Uso
---

    python3 bluetooth_guardian.py

Modo rápido (sin menú):

    python3 bluetooth_guardian.py --non-interactive

Flujo sugerido
--------------

1. Opción 1: escanear dispositivos Bluetooth.
2. Opción 2: seleccionar dispositivo por número y auditar.
3. Opción 4: evaluar postura BlueBorne defensiva del host.
4. Opción 5/6: consolidar inventario con fuentes externas.
5. Opción 7: ver resumen consolidado en terminal.

Notas importantes
-----------------

- Esta herramienta NO explota vulnerabilidades ni intenta obtener acceso no autorizado.
- No obtiene red/IP de dispositivos remotos por Bluetooth; solo reporta telemetría del host auditor.
- Está pensada para laboratorios y auditorías con permiso explícito.
- Revisar `LEGAL_NOTICE.md` y `TERMS_OF_USE.md` antes de usar.
