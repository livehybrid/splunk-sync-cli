"""
RBAC (Role-Based Access Control) management for Splunk knowledge objects.

This module provides comprehensive permission management capabilities
for Splunk knowledge objects with proper validation and error handling.
"""

import logging
from typing import Dict, Any, List, Optional, Set, Union
from dataclasses import dataclass, field
from enum import Enum

from .exceptions import PermissionError, ValidationError, SplunkSyncError
from .knowledge_objects import KnowledgeObject

logger = logging.getLogger(__name__)


class SharingLevel(Enum):
    """Sharing levels for knowledge objects."""

    PRIVATE = "user"
    APP = "app"
    GLOBAL = "global"


@dataclass
class Permission:
    """Represents a permission setting."""

    read: Set[str] = field(default_factory=set)
    write: Set[str] = field(default_factory=set)

    def __post_init__(self):
        """Validate permissions after initialization."""
        # Ensure write permissions are subset of read permissions
        if not self.write.issubset(self.read):
            logger.warning("Write permissions should be a subset of read permissions")


@dataclass
class ACL:
    """Access Control List for knowledge objects."""

    owner: str
    app: str
    sharing: SharingLevel
    permissions: Permission = field(default_factory=Permission)
    modifiable: bool = True
    removable: bool = True

    def __post_init__(self):
        """Validate ACL after initialization."""
        if not self.owner:
            raise ValidationError("Owner cannot be empty", "", "")

        if not self.app:
            raise ValidationError("App cannot be empty", "", "")

    def to_dict(self) -> Dict[str, Any]:
        """Convert ACL to dictionary format."""
        return {
            "owner": self.owner,
            "app": self.app,
            "sharing": self.sharing.value,
            "perms.read": (
                ",".join(sorted(self.permissions.read))
                if self.permissions.read
                else "*"
            ),
            "perms.write": (
                ",".join(sorted(self.permissions.write))
                if self.permissions.write
                else "*"
            ),
            "modifiable": str(int(self.modifiable)),
            "removable": str(int(self.removable)),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ACL":
        """Create ACL from dictionary."""
        # Parse sharing level
        sharing_value = data.get("sharing", "app")
        try:
            sharing = SharingLevel(sharing_value)
        except ValueError:
            logger.warning(
                f"Invalid sharing level '{sharing_value}', defaulting to 'app'"
            )
            sharing = SharingLevel.APP

        # Parse permissions
        read_perms = data.get("perms.read", "*")
        write_perms = data.get("perms.write", "*")

        read_set = set(read_perms.split(",")) if read_perms != "*" else {"*"}
        write_set = set(write_perms.split(",")) if write_perms != "*" else {"*"}

        return cls(
            owner=data.get("owner", "admin"),
            app=data.get("app", "search"),
            sharing=sharing,
            permissions=Permission(read=read_set, write=write_set),
            modifiable=bool(int(data.get("modifiable", "1"))),
            removable=bool(int(data.get("removable", "1"))),
        )


class RoleManager:
    """Manages Splunk roles and their capabilities."""

    def __init__(self):
        """Initialize role manager."""
        self.default_roles = {
            "admin": {
                "capabilities": ["*"],
                "description": "Administrator role with full access",
            },
            "power": {
                "capabilities": [
                    "schedule_search",
                    "edit_own_search",
                    "edit_search_scheduler",
                    "edit_user",
                    "edit_roles_grantable",
                    "list_settings",
                ],
                "description": "Power user role with extended capabilities",
            },
            "user": {
                "capabilities": ["schedule_search", "edit_own_search"],
                "description": "Standard user role",
            },
            "splunk-system-role": {
                "capabilities": ["*"],
                "description": "System role for internal operations",
            },
        }

    def get_role_capabilities(self, role: str) -> List[str]:
        """Get capabilities for a specific role."""
        return self.default_roles.get(role, {}).get("capabilities", [])

    def validate_role(self, role: str) -> bool:
        """Validate if a role exists."""
        return role in self.default_roles

    def can_access_knowledge_object(
        self, role: str, ko_type: str, operation: str
    ) -> bool:
        """Check if a role can perform an operation on a knowledge object type."""
        capabilities = self.get_role_capabilities(role)

        if "*" in capabilities:
            return True

        # Define required capabilities for different operations
        required_caps = {
            "read": {
                "savedsearches": ["list_saved_searches"],
                "macros": ["list_macros"],
                "eventtypes": ["list_event_types"],
                "tags": ["list_tags"],
                "workflow_actions": ["list_workflow_actions"],
                "transforms": ["list_transforms"],
                "props": ["list_props"],
            },
            "write": {
                "savedsearches": ["edit_saved_searches"],
                "macros": ["edit_macros"],
                "eventtypes": ["edit_event_types"],
                "tags": ["edit_tags"],
                "workflow_actions": ["edit_workflow_actions"],
                "transforms": ["edit_transforms"],
                "props": ["edit_props"],
            },
        }

        required = required_caps.get(operation, {}).get(ko_type, [])
        return any(cap in capabilities for cap in required)


class PermissionManager:
    """Manages permissions for knowledge objects."""

    def __init__(self, default_permissions: Dict[str, str]):
        """Initialize with default permissions."""
        self.default_permissions = default_permissions
        self.role_manager = RoleManager()

    def create_default_acl(self, ko: KnowledgeObject) -> ACL:
        """Create default ACL for a knowledge object."""
        return ACL(
            owner=ko.owner,
            app=ko.app,
            sharing=SharingLevel(ko.sharing),
            permissions=Permission(read={"*"}, write={"*"}),
            modifiable=True,
            removable=True,
        )

    def validate_acl(self, acl: ACL, ko: KnowledgeObject) -> List[str]:
        """Validate ACL configuration."""
        issues = []

        # Validate owner
        if not acl.owner:
            issues.append("Owner cannot be empty")

        # Validate app
        if not acl.app:
            issues.append("App cannot be empty")

        # Validate sharing level
        if acl.sharing == SharingLevel.GLOBAL and acl.owner != "nobody":
            issues.append("Global objects must be owned by 'nobody'")

        # Validate permissions
        if acl.permissions.read and "*" not in acl.permissions.read:
            for role in acl.permissions.read:
                if not self.role_manager.validate_role(role):
                    issues.append(f"Invalid role in read permissions: {role}")

        if acl.permissions.write and "*" not in acl.permissions.write:
            for role in acl.permissions.write:
                if not self.role_manager.validate_role(role):
                    issues.append(f"Invalid role in write permissions: {role}")

        return issues

    def merge_permissions(
        self, current_acl: ACL, new_permissions: Dict[str, Any]
    ) -> ACL:
        """Merge new permissions with existing ACL."""
        # Create a copy of current ACL
        merged_acl = ACL(
            owner=new_permissions.get("owner", current_acl.owner),
            app=new_permissions.get("app", current_acl.app),
            sharing=SharingLevel(
                new_permissions.get("sharing", current_acl.sharing.value)
            ),
            permissions=Permission(
                read=set(new_permissions.get("read", current_acl.permissions.read)),
                write=set(new_permissions.get("write", current_acl.permissions.write)),
            ),
            modifiable=new_permissions.get("modifiable", current_acl.modifiable),
            removable=new_permissions.get("removable", current_acl.removable),
        )

        return merged_acl

    def calculate_effective_permissions(
        self, acl: ACL, user_roles: List[str]
    ) -> Dict[str, bool]:
        """Calculate effective permissions for a user."""
        effective = {"read": False, "write": False, "delete": False, "modify": False}

        # Check if user is owner
        if acl.owner in user_roles:
            effective.update(
                {"read": True, "write": True, "delete": True, "modify": True}
            )
            return effective

        # Check read permissions
        if "*" in acl.permissions.read or any(
            role in acl.permissions.read for role in user_roles
        ):
            effective["read"] = True

        # Check write permissions
        if "*" in acl.permissions.write or any(
            role in acl.permissions.write for role in user_roles
        ):
            effective["write"] = True

        # Delete and modify depend on object properties
        if acl.removable and effective["write"]:
            effective["delete"] = True

        if acl.modifiable and effective["write"]:
            effective["modify"] = True

        return effective

    def get_permission_template(
        self, ko_type: str, sharing: SharingLevel
    ) -> Dict[str, Any]:
        """Get permission template for a knowledge object type."""
        templates = {
            "savedsearches": {
                SharingLevel.PRIVATE: {"read": ["user"], "write": ["user"]},
                SharingLevel.APP: {"read": ["*"], "write": ["admin", "power"]},
                SharingLevel.GLOBAL: {"read": ["*"], "write": ["admin"]},
            },
            "macros": {
                SharingLevel.PRIVATE: {"read": ["user"], "write": ["user"]},
                SharingLevel.APP: {"read": ["*"], "write": ["admin", "power"]},
                SharingLevel.GLOBAL: {"read": ["*"], "write": ["admin"]},
            },
            "eventtypes": {
                SharingLevel.PRIVATE: {"read": ["user"], "write": ["user"]},
                SharingLevel.APP: {"read": ["*"], "write": ["admin", "power"]},
                SharingLevel.GLOBAL: {"read": ["*"], "write": ["admin"]},
            },
        }

        return templates.get(ko_type, {}).get(
            sharing, {"read": ["*"], "write": ["admin"]}
        )


class RBACManager:
    """Main RBAC management class."""

    def __init__(self, default_permissions: Dict[str, str], enabled: bool = True):
        """Initialize RBAC manager."""
        self.enabled = enabled
        self.permission_manager = PermissionManager(default_permissions)
        self.role_manager = RoleManager()

    def is_enabled(self) -> bool:
        """Check if RBAC is enabled."""
        return self.enabled

    def get_object_acl(
        self, ko: KnowledgeObject, remote_acl: Optional[Dict[str, Any]] = None
    ) -> ACL:
        """Get ACL for a knowledge object."""
        if remote_acl:
            return ACL.from_dict(remote_acl)
        else:
            return self.permission_manager.create_default_acl(ko)

    def update_object_permissions(
        self, ko: KnowledgeObject, new_permissions: Dict[str, Any]
    ) -> ACL:
        """Update permissions for a knowledge object."""
        if not self.enabled:
            logger.info("RBAC is disabled, skipping permission update")
            return self.permission_manager.create_default_acl(ko)

        # Get current ACL (this would typically come from Splunk)
        current_acl = self.permission_manager.create_default_acl(ko)

        # Merge with new permissions
        updated_acl = self.permission_manager.merge_permissions(
            current_acl, new_permissions
        )

        # Validate the updated ACL
        issues = self.permission_manager.validate_acl(updated_acl, ko)
        if issues:
            raise PermissionError(
                f"Permission validation failed: {issues}", ko.ko_type, ko.name, "update"
            )

        logger.info(f"Updated permissions for {ko.ko_type}/{ko.name}")
        return updated_acl

    def check_access(
        self, ko: KnowledgeObject, user_roles: List[str], operation: str
    ) -> bool:
        """Check if user has access to perform an operation."""
        if not self.enabled:
            return True

        # Get object ACL
        acl = self.permission_manager.create_default_acl(ko)

        # Calculate effective permissions
        effective_perms = self.permission_manager.calculate_effective_permissions(
            acl, user_roles
        )

        # Check specific operation
        return effective_perms.get(operation, False)

    def get_accessible_objects(
        self, objects: List[KnowledgeObject], user_roles: List[str]
    ) -> List[KnowledgeObject]:
        """Filter objects based on user access."""
        if not self.enabled:
            return objects

        accessible = []
        for ko in objects:
            if self.check_access(ko, user_roles, "read"):
                accessible.append(ko)

        return accessible

    def apply_default_permissions(self, ko: KnowledgeObject) -> Dict[str, Any]:
        """Apply default permissions to a knowledge object."""
        if not self.enabled:
            return {}

        # Get sharing level
        sharing = SharingLevel(ko.sharing)

        # Get template permissions
        template = self.permission_manager.get_permission_template(ko.ko_type, sharing)

        # Create ACL
        acl = ACL(
            owner=ko.owner,
            app=ko.app,
            sharing=sharing,
            permissions=Permission(
                read=set(template.get("read", ["*"])),
                write=set(template.get("write", ["admin"])),
            ),
        )

        return acl.to_dict()

    def validate_object_permissions(
        self, ko: KnowledgeObject, permissions: Dict[str, Any]
    ) -> List[str]:
        """Validate permissions for a knowledge object."""
        if not self.enabled:
            return []

        try:
            acl = ACL.from_dict(permissions)
            return self.permission_manager.validate_acl(acl, ko)
        except Exception as e:
            return [f"Invalid permission format: {e}"]

    def get_permission_summary(self, ko: KnowledgeObject) -> Dict[str, Any]:
        """Get permission summary for a knowledge object."""
        if not self.enabled:
            return {"rbac_enabled": False}

        acl = self.permission_manager.create_default_acl(ko)

        return {
            "rbac_enabled": True,
            "owner": acl.owner,
            "app": acl.app,
            "sharing": acl.sharing.value,
            "read_roles": list(acl.permissions.read),
            "write_roles": list(acl.permissions.write),
            "modifiable": acl.modifiable,
            "removable": acl.removable,
        }
