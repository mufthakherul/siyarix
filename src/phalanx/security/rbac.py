"""Role-Based Access Control (RBAC) System.

Defines permissions, roles, and enforcement mechanisms for Phalanx operations.
"""

import os
from enum import StrEnum
from typing import Any


class OperationPermission(StrEnum):
    """Granular permissions for cyber operations."""
    READ_ONLY = "read_only"        # List tools, view history, read knowledge graph
    PASSIVE = "passive"            # OSINT, passive recon (no packets to target)
    ACTIVE = "active"              # Port scans, web crawling, directory brute-forcing
    INTRUSIVE = "intrusive"        # Vuln scanning, exploitation, payload drops
    DESTRUCTIVE = "destructive"    # Data deletion, service disruption (requires --force)


class Role(StrEnum):
    """Pre-defined enterprise roles."""
    VIEWER = "viewer"
    ANALYST = "analyst"
    OPERATOR = "operator"
    PENTESTER = "pentester"
    ADMIN = "admin"


class RolePermissions:
    """Mapping of roles to their allowed permissions."""
    
    _MAPPING: dict[Role, set[OperationPermission]] = {
        Role.VIEWER: {OperationPermission.READ_ONLY},
        Role.ANALYST: {OperationPermission.READ_ONLY, OperationPermission.PASSIVE},
        Role.OPERATOR: {
            OperationPermission.READ_ONLY,
            OperationPermission.PASSIVE,
            OperationPermission.ACTIVE,
        },
        Role.PENTESTER: {
            OperationPermission.READ_ONLY,
            OperationPermission.PASSIVE,
            OperationPermission.ACTIVE,
            OperationPermission.INTRUSIVE,
        },
        Role.ADMIN: {
            OperationPermission.READ_ONLY,
            OperationPermission.PASSIVE,
            OperationPermission.ACTIVE,
            OperationPermission.INTRUSIVE,
            OperationPermission.DESTRUCTIVE,
        },
    }

    @classmethod
    def get_permissions(cls, role: Role | str) -> set[OperationPermission]:
        """Get permissions for a given role."""
        try:
            r = Role(role)
            return cls._MAPPING.get(r, set())
        except ValueError:
            return set()


class RBACEnforcer:
    """Enforces RBAC policies for the current session."""

    def __init__(self) -> None:
        # In a real enterprise system, this would be fetched from LDAP/SSO.
        # Here we allow an environment variable override, default to ADMIN for local CLI.
        self.current_role = Role(os.getenv("PHALANX_USER_ROLE", Role.ADMIN))
        self.current_permissions = RolePermissions.get_permissions(self.current_role)

    def has_permission(self, permission: OperationPermission | str) -> bool:
        """Check if the current user has the requested permission."""
        try:
            perm = OperationPermission(permission)
            return perm in self.current_permissions
        except ValueError:
            return False

    def require(self, permission: OperationPermission | str) -> None:
        """Raise an exception if the user lacks the permission."""
        if not self.has_permission(permission):
            raise PermissionError(
                f"Access Denied: Your role ({self.current_role}) lacks the "
                f"'{permission}' permission required for this operation."
            )

# Global singleton
rbac = RBACEnforcer()
