# Plan UI/Funcional por Sprint + QA de Regresión + Métricas UX/Performance

## 1) Entregables por sprint con criterios de aceptación por módulo

### Sprint 1 · Fundación de navegación SOC

#### Módulo SOC Dashboard
**Entregables**
- Navegación lateral operativa entre módulos principales (`SOC`, `Threat Hunting`, `Incident Response`, `Forensics Timeline`).
- Historial de navegación (`atrás` / `adelante`) con persistencia del último módulo activo.
- Inspector central con tabs de análisis operativo.

**Criterios de aceptación**
- Al cambiar entre módulos, el workspace actualiza la vista sin errores ni pantallas en blanco.
- Al cerrar/reabrir la aplicación, se recupera el último módulo visitado.
- Los tabs críticos (`Inspector de paquete`, `Anomalías y riesgo`, `Respuesta defensiva`, `Timeline`) renderizan y son interactivos.

#### Módulo Threat Hunting
**Entregables**
- Filtro rápido y consulta de hunting persistentes.
- Pivot de entidad y filtro de severidad rehidratados al reinicio.

**Criterios de aceptación**
- Cambios en query/pivot/severidad se guardan y restauran correctamente.
- El filtro reduce o mantiene el conjunto de resultados, nunca lo incrementa de forma inconsistente.

### Sprint 2 · Operación y resiliencia

#### Módulo Incident Response
**Entregables**
- Checklist de respuesta con estados de ejecución.
- Integración con acciones defensivas permitidas por rol.

**Criterios de aceptación**
- Las acciones restringidas por RBAC muestran bloqueo y no ejecutan operaciones.
- El estado de playbook cambia de forma auditable (inicio/ejecución/cierre).

#### Módulo Forensics Timeline
**Entregables**
- Línea temporal de eventos con columnas forenses mínimas (`Hora`, `Severidad`, `Entidad`, `Resumen`).
- Sincronización con contexto lateral (`snapshot`, `alerts`, `assets`).

**Criterios de aceptación**
- La selección de evento mantiene coherencia de datos entre panel central y panel contextual.
- No hay pérdida de filas al refrescar telemetría incremental.

### Sprint 3 · Hardening UX y cierre funcional

#### Módulos transversales (todos)
**Entregables**
- Persistencia robusta de estado UI (módulo, filtros, tab activa, splitters).
- Telemetría de rendimiento UX visible para validación técnica.
- Pruebas de regresión E2E y de componentes críticos en CI.

**Criterios de aceptación**
- Reapertura de sesión recupera estado previo en < 2 segundos.
- Refresco periódico no bloquea la interfaz ni degrada navegación.
- Suite de regresión verde en escenarios nominales.

---

## 2) Estrategia de pruebas de regresión

### Cobertura mínima obligatoria
- **Navegación**: cambio de módulo, historial atrás/adelante, sincronización sidebar/router.
- **Persistencia de estado**: último módulo, tab de workspace, filtros rápidos y perfil de analista.
- **Render crítico**: estructura de tablas e inspectores SOC, tabs operativas y panel contextual.

### Criterios de salida QA
- 0 fallos en pruebas de regresión críticas.
- 0 regresiones visuales en componentes críticos (tablas/tabs principales).
- Cobertura estable de pruebas GUI relacionadas a navegación y estado.

---

## 3) Métricas UX/performance objetivo

### KPIs operativos
1. **Tiempo de carga de módulo (TTM: Time To Module)**
   - Definición: tiempo entre acción de navegación y render estable del módulo.
   - Objetivo: `p95 <= 800 ms`, umbral crítico `> 1200 ms`.

2. **Refresco de telemetría (TRI: Telemetry Refresh Interval)**
   - Definición: latencia efectiva entre ciclos de refresh y disponibilidad de datos en vista.
   - Objetivo: intervalo nominal `1500 ms ± 300 ms`, jitter crítico `> 500 ms` sostenido.

3. **Uso de memoria de GUI (RSM: Resident Set Memory)**
   - Definición: memoria residente del proceso durante operación SOC continua.
   - Objetivo: `<= 450 MB` en carga normal; alerta temprana desde `> 550 MB`.

### Reglas de evaluación
- **OK**: todos los KPIs bajo umbral objetivo.
- **WARN**: al menos un KPI fuera de objetivo pero dentro de umbral crítico.
- **CRITICAL**: cualquier KPI sobre umbral crítico durante 3 ventanas consecutivas.

---

## 4) Demo final con escenarios SOC reales

### Escenarios de demostración
1. **Exposición de servicio no autorizado**
   - Detección en panel de exposición.
   - Navegación a Incident Response.
   - Aplicación de acción defensiva sugerida.

2. **Pico de autenticaciones fallidas / fuerza bruta**
   - Incremento de alertas de severidad alta.
   - Correlación en Threat Hunting.
   - Evidencia en Forensics Timeline.

3. **Conexión saliente sospechosa persistente**
   - Visualización en módulo SOC (conexiones entrantes/salientes).
   - Inspección contextual del activo/servicio.
   - Registro de decisión operativa de contención.

### Checklist de validación operativa (go/no-go)
- [ ] Navegación entre módulos sin errores ni congelamientos.
- [ ] Persistencia de estado validada tras reinicio.
- [ ] Render correcto de componentes críticos (tabs, tablas, panel contextual).
- [ ] Métricas TTM/TRI/RSM capturadas y dentro de umbral aceptable.
- [ ] Flujo completo de al menos 2 escenarios SOC ejecutado de punta a punta.
- [ ] Evidencia forense exportable y trazable.

