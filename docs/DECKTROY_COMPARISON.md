# Comparativa práctica DECKTROY vs plataformas defensivas avanzadas

> Alcance: **defensivo y legal** (sin intrusión ofensiva).

## Resumen ejecutivo

DECKTROY hoy cubre bien una capa **host-based blue-team ligera** (inventario, baseline, playbooks, dashboard, guardia de conexiones, incidentes y health checks).

Frente a suites enterprise/militarizadas (Wazuh/Security Onion/Splunk ES/Elastic SIEM/CrowdStrike), las brechas más importantes son:

1. Escala multi-host y gestión centralizada masiva.
2. Correlación SIEM avanzada + reglas enriquecidas (Sigma/YARA/MITRE de forma nativa a gran escala).
3. Gestión de identidades, RBAC granular y trazabilidad de auditoría de operadores.
4. Integración madura con EDR/NDR, CMDB, threat intel comercial y SOAR.
5. Resiliencia de arquitectura (HA, colas, retención y cifrado de evidencia en repositorios dedicados).

---

## Benchmark (alto nivel)

| Capacidad | DECKTROY (actual) | Referentes avanzados | Brecha | Prioridad |
|---|---|---|---|---|
| Telemetría host local | Buena | Muy alta | Media | Alta |
| Detección por logs/reglas básicas | Buena | Muy alta (SIEM correlado) | Alta | Alta |
| Detección de anomalías conexión | Buena (baseline + heurística) | Alta (ML + comportamiento global) | Media | Alta |
| Gestión incidentes/evidencia | Media | Alta (case mgmt enterprise) | Media | Media |
| Orquestación automática segura | Media | Alta (SOAR) | Alta | Alta |
| Escala multi-servidor | Baja/Media | Muy alta | Alta | Crítica |
| Gobierno/RBAC/auditoría operadores | Básica | Alta | Alta | Crítica |
| UX operativa SOC | Buena | Muy alta | Media | Media |

---

## Mejoras prioritarias recomendadas (roadmap)

### Fase 1 – Endurecimiento operacional (corto plazo)
- Añadir configuración central (`decktroy.yaml`) con perfiles (`lab`, `prod`, `high-security`).
- Firmar y versionar playbooks + políticas (hash y control de cambios).
- Alertas salientes multi-canal con reintentos y circuit-breaker (webhook/Slack/Telegram).
- Retención local de reportes con rotación y compresión.

### Fase 2 – Escala y correlación (medio plazo)
- Agente ligero por host + colector central DECKTROY HUB.
- Motor de reglas normalizadas (Sigma-like) y mapeo MITRE ATT&CK completo.
- Correlación entre eventos de firewall/logins/servicios/conexiones en ventanas temporales.
- Cola de eventos (Kafka/Redis Streams) para evitar pérdidas en picos.

### Fase 3 – Madurez SOC (medio/largo plazo)
- RBAC completo (viewer/operator/admin), MFA y auditoría firmada de acciones.
- Módulo de casos avanzado: SLA, owner, evidencias cifradas, export legal.
- Integraciones SIEM/SOAR/EDR de terceros para ecosistema mixto.
- Alta disponibilidad: réplicas, backups de evidencia, recuperación ante desastre.

---

## Mejoras UX para la CLI gráfica (implementadas en esta iteración)

- Rediseño visual con layout de centro de comando, paneles KPI, tema táctico y tarjetas enriquecidas.
- Gráficas más claras: series temporales (CPU/MEM/Disco) + histograma de severidad.
- Dashboard táctico con resumen operacional y telemetría de riesgo en una sola vista.
- Mejor organización visual de módulos (mapa, servicios, guardia, incidentes, logs, advisor).

---

## Objetivo realista de “grado militar” (defensivo)

Un nivel “grado militar” práctico no depende solo de UI o scripts: requiere arquitectura resiliente, gobierno de acceso, cadena de custodia robusta, pruebas continuas y operación SOC 24/7.

DECKTROY ya avanza en base defensiva host-centric; el siguiente salto es **escala, gobernanza, correlación y resiliencia operacional**.
