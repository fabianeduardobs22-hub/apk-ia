from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Role(StrEnum):
    READ_ONLY = "read_only"
    ANALYST = "analyst"
    OPERATOR = "operator"
    ADMIN = "admin"


ROLE_LABELS: dict[Role, str] = {
    Role.READ_ONLY: "Solo lectura",
    Role.ANALYST: "Analista",
    Role.OPERATOR: "Operador",
    Role.ADMIN: "Admin",
}


@dataclass(frozen=True, slots=True)
class AccessPolicy:
    view_roles: dict[str, Role]
    action_roles: dict[str, Role]

    def allows_view(self, role: Role, view_id: str) -> bool:
        return _rank(role) >= _rank(self.view_roles.get(view_id, Role.READ_ONLY))

    def allows_action(self, role: Role, action_id: str) -> bool:
        return _rank(role) >= _rank(self.action_roles.get(action_id, Role.READ_ONLY))


def _rank(role: Role) -> int:
    return [Role.READ_ONLY, Role.ANALYST, Role.OPERATOR, Role.ADMIN].index(role)


DEFAULT_POLICY = AccessPolicy(
    view_roles={
        "dashboard": Role.READ_ONLY,
        "alerts": Role.READ_ONLY,
        "hunting": Role.ANALYST,
        "incident_response": Role.OPERATOR,
        "forensics": Role.ANALYST,
    },
    action_roles={
        "alerts.acknowledge": Role.ANALYST,
        "alerts.escalate": Role.OPERATOR,
        "incident.playbook.execute": Role.OPERATOR,
        "runtime.settings.write": Role.ADMIN,
        "demo.event.generate": Role.OPERATOR,
    },
)
