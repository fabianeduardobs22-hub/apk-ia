from __future__ import annotations

from dataclasses import dataclass

from sentinel_x_defense_suite.gui.sections.workflow import DrillDownRecord


@dataclass(slots=True)
class HuntingFinding:
    identifier: str
    time: str
    entity: str
    value: str
    severity: str
    detection: str
    evidence: list[str]
    recommendation: str

    def to_drilldown(self) -> DrillDownRecord:
        return DrillDownRecord(
            identifier=self.identifier,
            summary=f"{self.entity}={self.value} ({self.severity})",
            detail={
                "Hora": self.time,
                "Entidad": self.entity,
                "Valor": self.value,
                "Severidad": self.severity,
                "Detección": self.detection,
            },
            evidence=self.evidence,
            recommended_action=self.recommendation,
        )
