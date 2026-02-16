from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class CapabilityScore:
    name: str
    sentinel_score: int
    reference_score: int
    rationale: str


def default_capability_matrix() -> list[CapabilityScore]:
    """Comparativa orientativa contra categorías de suites SOC avanzadas.

    Nota: no replica software propietario; usa criterios públicos de referencia.
    """

    return [
        CapabilityScore(
            name="Visibilidad en tiempo real",
            sentinel_score=9,
            reference_score=8,
            rationale="Tabla live con inspección detallada, riesgo y vista hex/ASCII integrada.",
        ),
        CapabilityScore(
            name="Detección híbrida",
            sentinel_score=8,
            reference_score=8,
            rationale="Reglas + comportamiento + módulo ML ligero opcional.",
        ),
        CapabilityScore(
            name="Trazabilidad forense",
            sentinel_score=9,
            reference_score=7,
            rationale="Alertas con hash encadenado y exportación estructurada.",
        ),
        CapabilityScore(
            name="Operación defensiva segura",
            sentinel_score=9,
            reference_score=8,
            rationale="Validación de privilegios y política explícita no-ofensiva.",
        ),
        CapabilityScore(
            name="Extensibilidad",
            sentinel_score=8,
            reference_score=8,
            rationale="Sistema de plugins y módulos desacoplados por capas.",
        ),
    ]


def summarize_matrix(scores: list[CapabilityScore]) -> dict[str, float]:
    if not scores:
        return {"sentinel_avg": 0.0, "reference_avg": 0.0, "delta": 0.0}

    sentinel_avg = sum(s.sentinel_score for s in scores) / len(scores)
    reference_avg = sum(s.reference_score for s in scores) / len(scores)
    return {
        "sentinel_avg": round(sentinel_avg, 2),
        "reference_avg": round(reference_avg, 2),
        "delta": round(sentinel_avg - reference_avg, 2),
    }
