# DECKTROY / SENTINEL X DEFENSE SUITE

Suite defensiva para Linux con GUI nativa (PyQt6), captura de red, detección y análisis forense.

## Mejoras operativas recientes

- Pivot entre módulos con contexto compartido: desde alertas se puede abrir Threat Hunting filtrado por entidad/IP.
- Bandeja de trabajo del analista con tareas y estado operativo (pendiente, en curso, revisión).
- Historial de auditoría visible en GUI y exportable a CSV.
- Plantillas de respuesta para incidentes frecuentes: brute force, beaconing y exposición de servicio.

## Perfiles de build (`core` y `extended`)

El empaquetado ahora soporta dos perfiles controlados por `SENTINELX_BUILD_PROFILE` en `setup.py` y manifiestos explícitos en `packaging/`:

- **`core`**: instalación base ligera para despliegues mínimos (dependencias base de parsing/configuración y módulos principales).
- **`extended`**: incluye lo de `core` y añade recursos defensivos opcionales offline para operación avanzada:
  - reglas defensivas (`resources/defensive_rules/`),
  - IOC feeds offline (`resources/ioc_feeds/`),
  - plantillas forenses (`resources/forensic_templates/`).

Manifiestos de control de artefactos:

- `packaging/profile-core.txt`
- `packaging/profile-extended.txt`

Ejemplos:

```bash
# Build base (por defecto)
SENTINELX_BUILD_PROFILE=core python -m build

# Build extendido
SENTINELX_BUILD_PROFILE=extended python -m build
```

### Justificación funcional del tamaño

- El perfil **`core`** prioriza footprint reducido para instalación rápida, menor superficie de dependencias y ejecución en hosts con recursos limitados.
- El perfil **`extended`** crece en tamaño de manera deliberada porque incorpora inteligencia defensiva y material forense usable sin conectividad externa, lo que mejora respuesta ante incidentes y análisis post-mortem.
- En CI puede validarse con `scripts/check_artifact_size.py`, que reporta tamaño final y falla solo cuando el artefacto queda fuera del rango acordado por perfil.


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

## Plan de sprints UI/QA, métricas UX y demo SOC

Se documentó el plan operativo de entregables por sprint, criterios de aceptación por módulo, pruebas de regresión, métricas UX/performance y checklist de demo final en:

- `docs/UI_FUNCTIONAL_SPRINT_PLAN.md`

