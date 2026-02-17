ROLE_PERMISSIONS = {
    "SUPER_ADMIN": ["*"],
    "TENANT_ADMIN": ["view", "edit", "manage_users", "view_audit", "respond"],
    "SOC_ANALYST": ["view", "respond", "view_audit"],
    "READ_ONLY": ["view"],
}


def authorize(role: str, action: str) -> bool:
    perms = ROLE_PERMISSIONS.get(role, [])
    return "*" in perms or action in perms
