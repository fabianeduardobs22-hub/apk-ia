# SENTINEL X DEFENSE SUITE

Plataforma nativa para Linux orientada 100% a defensa, monitoreo de red, detección y análisis forense.

## Capacidades clave

- Captura de tráfico en tiempo real (`scapy/libpcap`) con fallback seguro.
- Pipeline asíncrono (`asyncio`) para alto volumen.
- Detección híbrida defensiva:
  - exceso de conexiones simultáneas
  - patrones de fuerza bruta
  - beaconing sospechoso
- Motor de puntaje de riesgo por IP (LOW/MEDIUM/HIGH/CRITICAL).
- Persistencia forense en SQLite con hash encadenado para trazabilidad.
- Exportación de alertas a JSON y CSV.
- Integración de inteligencia de amenazas:
  - reputación por listas blanca/negra
  - geolocalización con rate limiting
- GUI nativa con PyQt6 (tema SOC oscuro) con layout estilo analizador profesional: tabla de conexiones, inspector detallado, resumen de riesgo y vista hex/ASCII en texto plano.
- Menú superior con submenús operativos (Archivo/Vista/Herramientas/Ayuda), menú contextual sobre conexiones y ventanas emergentes para resumen técnico, configuración visual y utilidades SOC.
- Sistema de plugins dinámicos para ampliación sin tocar el core.

## Estructura

- `sentinel_x_defense_suite/core`: orquestación, DI y logging JSON.
- `sentinel_x_defense_suite/capture`: captura de paquetes.
- `sentinel_x_defense_suite/analysis`: procesamiento y estadísticas.
- `sentinel_x_defense_suite/detection`: reglas, comportamiento y módulo ML ligero.
- `sentinel_x_defense_suite/forensics`: almacenamiento y exportación.
- `sentinel_x_defense_suite/gui`: escritorio nativo PyQt6.
- `sentinel_x_defense_suite/plugins`: cargador dinámico.
- `sentinel_x_defense_suite/security`: validaciones e integridad.
- `sentinel_x_defense_suite/scanner`: escáner defensivo limitado por tasa.
- `sentinel_x_defense_suite/intel`: feeds de inteligencia.
- `packaging`: scripts para instalación, .deb, AppImage y systemd.

## Instalación rápida

```bash
make install
sentinel-x --config sentinel_x.yaml init-config
sentinel-x --config sentinel_x.yaml run --max-packets 300
```

## Comandos CLI

```bash
sentinel-x --config sentinel_x.yaml run --max-packets 500
sentinel-x --config sentinel_x.yaml gui
sentinel-x --config sentinel_x.yaml export-alerts --output alerts.json
```

## Seguridad y legalidad

- El software está diseñado **únicamente para defensa**.
- No incorpora explotación, intrusión ni automatización ofensiva; la interfaz solo propone playbooks de respuesta defensiva.
- La captura en vivo requiere root o capacidades Linux (`CAP_NET_RAW`, `CAP_NET_ADMIN`). Para análisis sin privilegios, usar modo replay/offline.
- Se recomienda ejecución con principio de mínimo privilegio fuera de la fase de captura.

## Análisis comparativo

- Ver `docs/SENTINEL_X_COMPARATIVE_ANALYSIS.md` para la comparación defensiva contra categorías públicas de suites SOC avanzadas y mejoras aplicadas.
