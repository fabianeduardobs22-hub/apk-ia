# DECKTROY — Descubrimiento Inicial y Arquitectura Segura

> Alcance: defensa activa **estrictamente defensiva** para hardening, monitoreo, detección y contención.
> No incluye instrucciones de explotación, intrusión ni "contraataque" ofensivo.

## 1) Información que hay que recopilar antes de construir

### Inventario técnico del entorno
- Sistemas operativos, kernel y nivel de parches.
- Topología de red (segmentos, DMZ, saltos, VPN, balanceadores).
- Inventario de servicios expuestos por host y por puerto.
- Dependencias críticas: bases de datos, colas, APIs internas/externas.
- Requisitos de continuidad: RTO/RPO, SLA y ventanas de mantenimiento.

### Contexto de seguridad y cumplimiento
- Marco normativo aplicable (ISO 27001, NIST, ENS, etc.).
- Reglas legales de respuesta a incidentes y cadena de custodia.
- Modelo de amenaza por activo (actores, capacidades, impacto).
- Clasificación de datos y controles de acceso por criticidad.

### Telemetría y observabilidad existentes
- Fuentes de logs (syslog, app logs, cloud logs, WAF, IDS).
- Stack SIEM/SOAR actual y conectores disponibles.
- Métricas de infraestructura (CPU, RAM, IO, red, latencia).
- Canales de alerta operativos (Slack, Telegram, email, PagerDuty).

## 2) Arquitectura recomendada (defensa en profundidad)

1. **Capa de borde**
   - WAF + rate limiting + anti-DDoS upstream.
   - Geoblocking/ASN rules cuando aplique.
2. **Capa de host**
   - Firewall por host (UFW/iptables/nftables).
   - IDS/IPS (Suricata/Snort) y bloqueo de fuerza bruta (Fail2Ban).
   - Endurecimiento de SSH (MFA, llaves, listas de control).
3. **Capa de aplicación**
   - Protección contra OWASP Top 10.
   - Gestión de secretos y rotación de credenciales.
4. **Capa de detección y respuesta**
   - SIEM centralizado con reglas de correlación.
   - Playbooks SOAR para aislamiento, bloqueo y escalado.
5. **Capa de gobernanza**
   - Gestión de vulnerabilidades (escaneo continuo + parcheo).
   - Simulaciones y ejercicios de respuesta (tabletop/red-purple team).

## 3) Módulos sugeridos para el proyecto

- `collector/`: ingestión de telemetría de red, host y aplicación.
- `detector/`: reglas + modelos de anomalía explicables.
- `responder/`: acciones automatizadas permitidas (bloqueo IP, cuarentena).
- `orchestrator/`: políticas de severidad y priorización de incidentes.
- `ui/`: dashboard, alertas, trazabilidad y auditoría.
- `compliance/`: evidencias, reportes y controles normativos.

## 4) Política de respuesta automática segura

Las respuestas deben ser proporcionales y auditables:
- **Baja severidad**: alertar, etiquetar, aumentar observabilidad.
- **Media severidad**: rate-limit, challenge, bloqueo temporal.
- **Alta severidad**: aislamiento de servicio, revocación de credenciales,
  activación de runbook de incidente y escalado humano.

## 5) KPIs para medir efectividad

- MTTD (Mean Time To Detect).
- MTTR (Mean Time To Respond).
- Tasa de falsos positivos/negativos.
- Cobertura de activos monitoreados (%).
- Tiempo de despliegue de parches críticos.

## 6) Plan de implementación por fases

1. **Fase 0**: inventario + threat modeling + baseline de seguridad.
2. **Fase 1**: telemetría mínima viable + dashboard operativo.
3. **Fase 2**: detección avanzada + alertas multicanal.
4. **Fase 3**: automatización de respuesta defensiva.
5. **Fase 4**: hardening continuo + pruebas de resiliencia.

## 7) Verificación de integridad del sistema

Usar `decktroy/bootstrap_healthcheck.py` para validar requisitos base:
- Firewall detectado y consultable.
- IDS/IPS y anti-bruteforce instalados/activos.
- Herramientas de visibilidad de red disponibles.
- Conectividad de salida para alertas automatizadas.

Ejecutar:

```bash
python3 decktroy/bootstrap_healthcheck.py
```

Códigos de salida:
- `0`: todo OK.
- `1`: advertencias (faltan componentes recomendados).
- `2`: fallas críticas (falta protección base).
