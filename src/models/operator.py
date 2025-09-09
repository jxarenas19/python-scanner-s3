"""
Operator entity data model
Represents a system operator/user with authentication and permissions
"""

import hashlib
import secrets
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional


class OperatorRole(Enum):
    """Operator roles"""

    ADMIN = "admin"
    OPERATOR = "operator"
    SUPERVISOR = "supervisor"


class OperatorStatus(Enum):
    """Operator status"""

    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"
    SUSPENDED = "suspended"


class Operator:
    """
    Operator entity representing a system user

    Attributes:
        operator_id: Unique operator identifier
        username: Login username
        password_hash: Hashed password
        role: Operator role
        status: Current operator status
        branch: Default branch assignment
        created_at: Account creation timestamp
        last_login_at: Last successful login
        failed_login_attempts: Count of recent failed logins
        account_locked_until: Lockout expiration (if locked)
        permissions: Operator permissions
        metadata: Additional operator metadata
    """

    def __init__(
        self,
        operator_id: str,
        username: str,
        password_hash: str,
        role: OperatorRole,
        branch: str,
        created_at: Optional[datetime] = None,
    ):
        self.operator_id = operator_id
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.status = OperatorStatus.ACTIVE
        self.branch = branch
        self.created_at = created_at or datetime.now()
        self.last_login_at: Optional[datetime] = None
        self.failed_login_attempts = 0
        self.account_locked_until: Optional[datetime] = None
        self.permissions: List[str] = []
        self.metadata: Dict[str, Any] = {}

        # Set default permissions based on role
        self._set_default_permissions()

        # Validation
        self._validate()

    def _validate(self) -> None:
        """Validate operator data"""
        if not self.operator_id:
            raise ValueError("Operator ID cannot be empty")

        if not self.username:
            raise ValueError("Username cannot be empty")

        if len(self.username) < 3:
            raise ValueError("Username must be at least 3 characters")

        if not self.password_hash:
            raise ValueError("Password hash cannot be empty")

        if not self.branch:
            raise ValueError("Branch cannot be empty")

    def _set_default_permissions(self) -> None:
        """Set default permissions based on role"""
        base_permissions = [
            "scan_document",
            "encrypt_document",
            "upload_document",
            "view_own_documents",
        ]

        supervisor_permissions = base_permissions + [
            "view_branch_documents",
            "view_statistics",
            "manage_operators",
        ]

        admin_permissions = supervisor_permissions + [
            "system_admin",
            "view_all_documents",
            "manage_system_settings",
            "manage_branches",
        ]

        permission_map = {
            OperatorRole.OPERATOR: base_permissions,
            OperatorRole.SUPERVISOR: supervisor_permissions,
            OperatorRole.ADMIN: admin_permissions,
        }

        self.permissions = permission_map.get(self.role, base_permissions).copy()

    @classmethod
    def create_new(
        cls,
        username: str,
        password: str,
        role: OperatorRole,
        branch: str,
        operator_id: Optional[str] = None,
    ) -> "Operator":
        """
        Create new operator with hashed password

        Args:
            username: Login username
            password: Plain text password
            role: Operator role
            branch: Default branch
            operator_id: Optional operator ID (generated if not provided)

        Returns:
            New Operator instance
        """
        if not operator_id:
            operator_id = cls.generate_operator_id(username, branch)

        password_hash = cls.hash_password(password)

        return cls(
            operator_id=operator_id,
            username=username,
            password_hash=password_hash,
            role=role,
            branch=branch,
        )

    @staticmethod
    def generate_operator_id(username: str, branch: str) -> str:
        """
        Generate unique operator ID

        Args:
            username: Username
            branch: Branch name

        Returns:
            Unique operator ID
        """
        # Create unique string
        unique_str = f"{branch}_{username}_{datetime.now().isoformat()}"

        # Generate hash
        hash_obj = hashlib.sha256(unique_str.encode())
        hash_suffix = hash_obj.hexdigest()[:8]

        return f"op_{branch}_{username}_{hash_suffix}"

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash password using secure method

        Args:
            password: Plain text password

        Returns:
            Hashed password
        """
        # Generate salt
        salt = secrets.token_bytes(32)

        # Hash password with salt using PBKDF2
        import base64

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # OWASP recommended minimum
        )

        key = kdf.derive(password.encode())

        # Combine salt and key for storage
        stored_password = salt + key

        # Base64 encode for string storage
        return base64.b64encode(stored_password).decode("ascii")

    def verify_password(self, password: str) -> bool:
        """
        Verify password against stored hash

        Args:
            password: Plain text password to verify

        Returns:
            True if password matches
        """
        try:
            import base64

            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

            # Decode stored password
            stored_password = base64.b64decode(self.password_hash.encode("ascii"))

            # Extract salt and key
            salt = stored_password[:32]
            stored_key = stored_password[32:]

            # Hash provided password with same salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )

            key = kdf.derive(password.encode())

            # Compare keys
            return key == stored_key

        except Exception:
            return False

    def is_active(self) -> bool:
        """
        Check if operator is active and not locked

        Returns:
            True if operator can log in
        """
        if self.status != OperatorStatus.ACTIVE:
            return False

        # Check if account is locked
        if self.account_locked_until:
            if datetime.now() < self.account_locked_until:
                return False
            else:
                # Unlock account if lockout period expired
                self.unlock_account()

        return True

    def is_locked(self) -> bool:
        """
        Check if operator account is locked

        Returns:
            True if account is locked
        """
        if self.status == OperatorStatus.LOCKED:
            return True

        if self.account_locked_until and datetime.now() < self.account_locked_until:
            return True

        return False

    def lock_account(
        self, duration_minutes: int = 30, reason: str = "too_many_failed_attempts"
    ) -> None:
        """
        Lock operator account

        Args:
            duration_minutes: Lockout duration in minutes
            reason: Reason for lockout
        """
        self.status = OperatorStatus.LOCKED
        self.account_locked_until = datetime.now() + timedelta(minutes=duration_minutes)
        self.metadata["locked_reason"] = reason
        self.metadata["locked_at"] = datetime.now().isoformat()

    def unlock_account(self) -> None:
        """Unlock operator account"""
        if self.status == OperatorStatus.LOCKED:
            self.status = OperatorStatus.ACTIVE

        self.account_locked_until = None
        self.failed_login_attempts = 0

        if "locked_reason" in self.metadata:
            del self.metadata["locked_reason"]
        if "locked_at" in self.metadata:
            del self.metadata["locked_at"]

    def record_successful_login(self) -> None:
        """Record successful login"""
        self.last_login_at = datetime.now()
        self.failed_login_attempts = 0

        # Auto-unlock if needed
        if (
            self.is_locked()
            and self.account_locked_until
            and datetime.now() >= self.account_locked_until
        ):
            self.unlock_account()

    def record_failed_login(self, max_attempts: int = 5) -> None:
        """
        Record failed login attempt

        Args:
            max_attempts: Maximum failed attempts before lockout
        """
        self.failed_login_attempts += 1

        # Lock account if too many failed attempts
        if self.failed_login_attempts >= max_attempts:
            self.lock_account(duration_minutes=30, reason="too_many_failed_attempts")

    def has_permission(self, permission: str) -> bool:
        """
        Check if operator has specific permission

        Args:
            permission: Permission to check

        Returns:
            True if operator has permission
        """
        return permission in self.permissions

    def add_permission(self, permission: str) -> None:
        """
        Add permission to operator

        Args:
            permission: Permission to add
        """
        if permission not in self.permissions:
            self.permissions.append(permission)

    def remove_permission(self, permission: str) -> None:
        """
        Remove permission from operator

        Args:
            permission: Permission to remove
        """
        if permission in self.permissions:
            self.permissions.remove(permission)

    def can_access_branch(self, branch: str) -> bool:
        """
        Check if operator can access specific branch

        Args:
            branch: Branch name to check

        Returns:
            True if operator can access branch
        """
        # Operators can access their own branch
        if branch == self.branch:
            return True

        # Admins can access all branches
        if self.role == OperatorRole.ADMIN:
            return True

        # Check for specific branch permissions
        return self.has_permission(f"access_branch_{branch}")

    def change_password(self, old_password: str, new_password: str) -> bool:
        """
        Change operator password

        Args:
            old_password: Current password
            new_password: New password

        Returns:
            True if password changed successfully
        """
        if not self.verify_password(old_password):
            return False

        # Validate new password
        if len(new_password) < 8:
            raise ValueError("Password must be at least 8 characters")

        # Hash and store new password
        self.password_hash = self.hash_password(new_password)
        self.metadata["password_changed_at"] = datetime.now().isoformat()

        return True

    def get_login_statistics(self) -> Dict[str, Any]:
        """
        Get operator login statistics

        Returns:
            Dictionary with login stats
        """
        days_since_created = (datetime.now() - self.created_at).days
        days_since_last_login = None

        if self.last_login_at:
            days_since_last_login = (datetime.now() - self.last_login_at).days

        return {
            "days_since_created": days_since_created,
            "days_since_last_login": days_since_last_login,
            "failed_login_attempts": self.failed_login_attempts,
            "is_locked": self.is_locked(),
            "account_age": days_since_created,
        }

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Convert operator to dictionary representation

        Args:
            include_sensitive: Whether to include sensitive data like password hash

        Returns:
            Dictionary with operator data
        """
        data = {
            "operator_id": self.operator_id,
            "username": self.username,
            "role": self.role.value,
            "status": self.status.value,
            "branch": self.branch,
            "created_at": self.created_at.isoformat(),
            "last_login_at": (
                self.last_login_at.isoformat() if self.last_login_at else None
            ),
            "failed_login_attempts": self.failed_login_attempts,
            "account_locked_until": (
                self.account_locked_until.isoformat()
                if self.account_locked_until
                else None
            ),
            "permissions": self.permissions.copy(),
            "is_active": self.is_active(),
            "is_locked": self.is_locked(),
            "login_stats": self.get_login_statistics(),
            "metadata": self.metadata.copy(),
        }

        if include_sensitive:
            data["password_hash"] = self.password_hash

        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Operator":
        """
        Create operator from dictionary representation

        Args:
            data: Dictionary with operator data

        Returns:
            Operator instance
        """
        created_at = datetime.fromisoformat(data["created_at"])

        operator = cls(
            operator_id=data["operator_id"],
            username=data["username"],
            password_hash=data["password_hash"],
            role=OperatorRole(data["role"]),
            branch=data["branch"],
            created_at=created_at,
        )

        # Set optional fields
        operator.status = OperatorStatus(data["status"])

        if data.get("last_login_at"):
            operator.last_login_at = datetime.fromisoformat(data["last_login_at"])

        operator.failed_login_attempts = data.get("failed_login_attempts", 0)

        if data.get("account_locked_until"):
            operator.account_locked_until = datetime.fromisoformat(
                data["account_locked_until"]
            )

        operator.permissions = data.get("permissions", []).copy()
        operator.metadata = data.get("metadata", {}).copy()

        return operator

    def __str__(self) -> str:
        """String representation"""
        return f"Operator(username={self.username}, role={self.role.value}, branch={self.branch})"

    def __repr__(self) -> str:
        """Detailed string representation"""
        return (
            f"Operator(operator_id='{self.operator_id}', "
            f"username='{self.username}', role={self.role.value}, "
            f"branch='{self.branch}', status={self.status.value})"
        )
