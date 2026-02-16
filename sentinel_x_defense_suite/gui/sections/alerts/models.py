from __future__ import annotations

from dataclasses import dataclass

from sentinel_x_defense_suite.gui.sections.workflow import DrillDownRecord


@dataclass(slots=True)
class AlertRecord:
    identifier: str
    time: str
    severity: str
    entity: str
    detection: str
    state: str
    evidence: list[str]
    recommendation: str

    def to_drilldown(self) -> DrillDownRecord:
        return DrillDownRecord(
            identifier=self.identifier,
            summary=f"{self.severity} · {self.entity}",
            detail={
                "Hora": self.time,
                "Severidad": self.severity,
                "Entidad": self.entity,
                "Detección": self.detection,
                "Estado": self.state,
            },
            evidence=self.evidence,
            recommended_action=self.recommendation,
        )
