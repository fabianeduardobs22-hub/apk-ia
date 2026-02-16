from __future__ import annotations

from dataclasses import dataclass

from sentinel_x_defense_suite.gui.sections.workflow import DrillDownRecord


@dataclass(slots=True)
class TimelineEvent:
    identifier: str
    time: str
    severity: str
    entity: str
    kind: str
    summary: str
    evidence: list[str]
    recommendation: str

    def to_drilldown(self) -> DrillDownRecord:
        return DrillDownRecord(
            identifier=self.identifier,
            summary=self.summary,
            detail={
                "Hora": self.time,
                "Severidad": self.severity,
                "Entidad": self.entity,
                "Tipo": self.kind,
            },
            evidence=self.evidence,
            recommended_action=self.recommendation,
        )
