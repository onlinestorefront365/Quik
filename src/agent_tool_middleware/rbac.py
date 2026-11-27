from __future__ import annotations


class RBACPolicy:
    """Maps roles to granular resource:action permissions."""

    def __init__(self, role_permissions: dict[str, set[str]]) -> None:
        self._role_permissions = role_permissions

    def is_authorized(self, roles: frozenset[str], permission: str) -> bool:
        for role in roles:
            granted = self._role_permissions.get(role, set())
            if "*" in granted or permission in granted:
                return True
        return False
