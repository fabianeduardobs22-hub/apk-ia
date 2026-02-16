Bluetooth Guardian CLI
======================

Herramienta de auditoría Bluetooth **defensiva** con interfaz progresiva en terminal.

> Implementación principal recomendada: **Bash** (`bluetooth_guardian.sh`) para máxima portabilidad en Termux y Linux.

Características principales
---------------------------

- Menú interactivo con opciones numéricas y animaciones de progreso.
- Barras de progreso en tareas clave (verificación, escaneo, auditoría, postura, resumen).
- Escaneo Bluetooth multi-motor (según disponibilidad en el sistema):
  - `termux-bluetooth-scan` (Termux:API)
  - `bluetoothctl devices` / `paired-devices`
  - `hcitool scan`
  - `btmgmt find`
- Auditoría no intrusiva del dispositivo seleccionado (info y/o SDP cuando exista soporte).
- Evaluación de postura **BlueBorne** defensiva (kernel/BlueZ local + recomendaciones).
- Contexto de red del host local (IP pública, interfaz, gateway, SSID/BSSID cuando esté disponible).
- Resumen de auditoría en terminal en tiempo real.

Instalación de requisitos
-------------------------

Automática por detección:

    ./install_requirements.sh

Forzar target manual:

    ./install_requirements.sh --target termux
    ./install_requirements.sh --target apt
    ./install_requirements.sh --target dnf
    ./install_requirements.sh --target pacman
    ./install_requirements.sh --target zypper

Compatibilidad del instalador
-----------------------------

- **Termux en Android sin root** (`pkg`) ✅
- **Kali/Ubuntu/Debian** (`apt`) ✅
- **Fedora/RHEL-like** (`dnf`) ✅
- **Arch/Manjaro** (`pacman`) ✅
- **openSUSE/SLE** (`zypper`) ✅

Notas de Termux
---------------

- El script intenta instalar `bluez`/`bluez-tools` si el repositorio los tiene.
- En muchos Android, `bluetoothctl`, `hcitool` y `sdptool` pueden no estar disponibles por limitaciones del SO.
- La vía principal en Termux es `termux-bluetooth-scan` + permisos de Termux:API.
- Si `jq` no está presente, el parser usa fallback básico por regex de MAC.

Uso
---

Recomendado (Bash):

    ./bluetooth_guardian.sh

Modo rápido (sin menú):

    ./bluetooth_guardian.sh --non-interactive

Compatibilidad heredada:

    python3 bluetooth_guardian.py --non-interactive

Notas importantes
-----------------

- Esta herramienta NO explota vulnerabilidades ni intenta obtener acceso no autorizado.
- No obtiene red/IP de dispositivos remotos por Bluetooth; solo reporta telemetría del host auditor.
- Está pensada para laboratorios y auditorías con permiso explícito.
- Revisar `LEGAL_NOTICE.md` y `TERMS_OF_USE.md` antes de usar.
