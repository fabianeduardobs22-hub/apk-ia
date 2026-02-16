# DECKTROY / SENTINEL X DEFENSE SUITE

Suite defensiva para Linux con GUI nativa (PyQt6), captura de red, detección y análisis forense.

## Instalación rápida automática (archivo único)

```bash
chmod +x install_decktroy_linux.sh
./install_decktroy_linux.sh
```

Este script:

- instala dependencias base del sistema según la distro,
- copia el proyecto a `~/.local/share/decktroy/app` para que los recursos siempre estén en una ruta estable,
- crea un entorno virtual en `~/.local/share/decktroy/venv`,
- configura los comandos `Decktroy`, `decktroy` y `sentinel-x` en `~/.local/bin`,
- abre la GUI automáticamente al finalizar.

## Comandos disponibles tras instalar

```bash
Decktroy
```

También:

```bash
decktroy
sentinel-x
```

## Notas operativas

- Si `~/.local/bin` no está en tu `PATH`, agrega:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

- `Decktroy` abre la GUI nativa de inmediato.
- El sistema mantiene un enfoque 100% defensivo.
