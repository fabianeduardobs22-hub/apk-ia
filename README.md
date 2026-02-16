# DECKTROY / SENTINEL X DEFENSE SUITE

Centro defensivo de monitoreo en tiempo real para Linux con GUI nativa PyQt6.

## Instalación automática + ejecución inmediata (archivo único)

```bash
chmod +x install_decktroy_linux.sh
./install_decktroy_linux.sh
```

Este script:
- instala dependencias y requisitos en `~/.local/share/sentinel-x/venv`,
- crea los comandos `Decktroy`, `decktroy` y `sentinel-x`,
- abre de inmediato la GUI nativa.

## Uso diario

```bash
Decktroy
```

También:

```bash
decktroy
sentinel-x
```

## Funciones visuales principales de la GUI

- Mapa global textual de actividad remota sospechosa.
- Panel de servicios expuestos detectados en tiempo real (`ss -tulpen`).
- Panel de superficie expuesta con servicios públicos.
- Panel de conexiones activas del host (`ss -tunap`).
- Centro de respuesta con comandos defensivos listos para ejecutar.
- Tabla SOC de eventos con inspector de tráfico y recomendaciones de contención.
- Pestaña Mission Control para visión operacional consolidada.

## Arquitectura y diseño estratégico

Documento integral (arquitectura, base de datos, flujos SOAR, wireframes, roadmap técnico e inversores):

- `docs/DECKTROY_STRATEGIC_BLUEPRINT.md`

## Enfoque

Uso exclusivamente defensivo y de respuesta operacional.
