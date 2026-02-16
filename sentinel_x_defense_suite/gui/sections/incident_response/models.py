from __future__ import annotations

from dataclasses import dataclass

from sentinel_x_defense_suite.gui.sections.workflow import DrillDownRecord


@dataclass(slots=True)
class ResponseTask:
    identifier: str
    phase: str
    owner: str
    state: str
    evidence: list[str]
    recommendation: str

    def to_drilldown(self) -> DrillDownRecord:
        return DrillDownRecord(
            identifier=self.identifier,
            summary=f"{self.phase} · {self.state}",
            detail={"Fase": self.phase, "Responsable": self.owner, "Estado": self.state},
            evidence=self.evidence,
            recommended_action=self.recommendation,
        )
