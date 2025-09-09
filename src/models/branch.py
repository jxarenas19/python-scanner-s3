"""
Branch entity data model
Represents a branch office with configuration and operational data
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class BranchStatus(Enum):
    """Branch operational status"""

    ACTIVE = "active"
    INACTIVE = "inactive"
    MAINTENANCE = "maintenance"
    SUSPENDED = "suspended"


class BranchType(Enum):
    """Branch types"""

    MAIN = "main"
    BRANCH = "branch"
    AGENCY = "agency"
    MOBILE = "mobile"


class Branch:
    """
    Branch entity representing a branch office

    Attributes:
        branch_id: Unique branch identifier
        name: Branch name/code
        display_name: Human-readable branch name
        branch_type: Type of branch
        status: Current operational status
        address: Branch physical address
        created_at: Branch creation timestamp
        timezone: Branch timezone
        business_hours: Operating hours configuration
        contact_info: Contact information
        configuration: Branch-specific settings
        statistics: Operational statistics
        metadata: Additional branch data
    """

    def __init__(
        self,
        branch_id: str,
        name: str,
        display_name: str,
        branch_type: BranchType,
        address: Dict[str, str],
        created_at: Optional[datetime] = None,
    ):
        self.branch_id = branch_id
        self.name = name  # Used as identifier (e.g., "sucursal-centro")
        self.display_name = display_name  # Human readable (e.g., "Sucursal Centro")
        self.branch_type = branch_type
        self.status = BranchStatus.ACTIVE
        self.address = address.copy()
        self.created_at = created_at or datetime.now()
        self.timezone = "America/Mexico_City"  # Default timezone
        self.business_hours: Dict[str, Any] = {}
        self.contact_info: Dict[str, str] = {}
        self.configuration: Dict[str, Any] = {}
        self.statistics: Dict[str, Any] = {}
        self.metadata: Dict[str, Any] = {}

        # Set default configuration
        self._set_default_configuration()

        # Validation
        self._validate()

    def _validate(self) -> None:
        """Validate branch data"""
        if not self.branch_id:
            raise ValueError("Branch ID cannot be empty")

        if not self.name:
            raise ValueError("Branch name cannot be empty")

        if not self.display_name:
            raise ValueError("Display name cannot be empty")

        if not self.address:
            raise ValueError("Address cannot be empty")

        # Validate required address fields
        required_address_fields = ["street", "city", "state", "postal_code"]
        for field in required_address_fields:
            if field not in self.address or not self.address[field]:
                raise ValueError(f"Address field '{field}' is required")

    def _set_default_configuration(self) -> None:
        """Set default branch configuration"""
        self.configuration = {
            # Scanner settings
            "scanner": {
                "default_format": "TIFF",
                "resolution_dpi": 300,
                "color_mode": "color",
                "timeout_seconds": 30,
            },
            # Encryption settings
            "encryption": {
                "algorithm": "AES-256-GCM",
                "key_derivation_iterations": 100000,
                "cleanup_after_upload": True,
            },
            # Upload settings
            "upload": {"retry_attempts": 3, "timeout_seconds": 120, "chunk_size_mb": 5},
            # Session settings
            "session": {
                "duration_hours": 8,
                "idle_timeout_minutes": 30,
                "max_concurrent_sessions": 5,
            },
            # Document processing
            "document": {
                "max_file_size_mb": 50,
                "quality_threshold": 80,
                "auto_cleanup_days": 7,
            },
        }

        # Set default business hours (9 AM - 6 PM, Monday-Friday)
        self.business_hours = {
            "monday": {"open": "09:00", "close": "18:00", "enabled": True},
            "tuesday": {"open": "09:00", "close": "18:00", "enabled": True},
            "wednesday": {"open": "09:00", "close": "18:00", "enabled": True},
            "thursday": {"open": "09:00", "close": "18:00", "enabled": True},
            "friday": {"open": "09:00", "close": "18:00", "enabled": True},
            "saturday": {"open": "09:00", "close": "14:00", "enabled": False},
            "sunday": {"open": "00:00", "close": "00:00", "enabled": False},
        }

    @classmethod
    def create_new(
        cls,
        name: str,
        display_name: str,
        branch_type: BranchType,
        street: str,
        city: str,
        state: str,
        postal_code: str,
        country: str = "Mexico",
    ) -> "Branch":
        """
        Create new branch with address

        Args:
            name: Branch identifier name
            display_name: Human-readable name
            branch_type: Type of branch
            street: Street address
            city: City
            state: State/province
            postal_code: Postal code
            country: Country

        Returns:
            New Branch instance
        """
        branch_id = cls.generate_branch_id(name)

        address = {
            "street": street,
            "city": city,
            "state": state,
            "postal_code": postal_code,
            "country": country,
        }

        return cls(
            branch_id=branch_id,
            name=name,
            display_name=display_name,
            branch_type=branch_type,
            address=address,
        )

    @staticmethod
    def generate_branch_id(name: str) -> str:
        """
        Generate unique branch ID

        Args:
            name: Branch name

        Returns:
            Unique branch ID
        """
        import hashlib

        # Create unique string
        unique_str = f"branch_{name}_{datetime.now().isoformat()}"

        # Generate hash
        hash_obj = hashlib.sha256(unique_str.encode())
        hash_suffix = hash_obj.hexdigest()[:8]

        return f"br_{name}_{hash_suffix}"

    def is_operational(self) -> bool:
        """
        Check if branch is operational

        Returns:
            True if branch can process documents
        """
        return self.status == BranchStatus.ACTIVE

    def is_during_business_hours(self, check_time: Optional[datetime] = None) -> bool:
        """
        Check if current time is during business hours

        Args:
            check_time: Time to check (default: now)

        Returns:
            True if during business hours
        """
        if not check_time:
            check_time = datetime.now()

        # Get day of week (0=Monday, 6=Sunday)
        day_names = [
            "monday",
            "tuesday",
            "wednesday",
            "thursday",
            "friday",
            "saturday",
            "sunday",
        ]
        day_name = day_names[check_time.weekday()]

        if day_name not in self.business_hours:
            return False

        day_config = self.business_hours[day_name]

        if not day_config.get("enabled", False):
            return False

        # Parse time strings
        open_time_str = day_config.get("open", "00:00")
        close_time_str = day_config.get("close", "00:00")

        try:
            open_hour, open_minute = map(int, open_time_str.split(":"))
            close_hour, close_minute = map(int, close_time_str.split(":"))

            current_minutes = check_time.hour * 60 + check_time.minute
            open_minutes = open_hour * 60 + open_minute
            close_minutes = close_hour * 60 + close_minute

            return open_minutes <= current_minutes < close_minutes

        except (ValueError, AttributeError):
            return False

    def get_configuration_value(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation

        Args:
            key_path: Configuration key path (e.g., "scanner.resolution_dpi")
            default: Default value if not found

        Returns:
            Configuration value
        """
        keys = key_path.split(".")
        value = self.configuration

        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default

    def set_configuration_value(self, key_path: str, value: Any) -> None:
        """
        Set configuration value using dot notation

        Args:
            key_path: Configuration key path
            value: Value to set
        """
        keys = key_path.split(".")
        config = self.configuration

        # Navigate to parent dict
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]

        # Set value
        config[keys[-1]] = value

    def update_business_hours(
        self, day: str, open_time: str, close_time: str, enabled: bool = True
    ) -> None:
        """
        Update business hours for specific day

        Args:
            day: Day name (monday, tuesday, etc.)
            open_time: Opening time (HH:MM format)
            close_time: Closing time (HH:MM format)
            enabled: Whether branch operates on this day
        """
        if day not in [
            "monday",
            "tuesday",
            "wednesday",
            "thursday",
            "friday",
            "saturday",
            "sunday",
        ]:
            raise ValueError(f"Invalid day: {day}")

        # Validate time format
        try:
            hour, minute = map(int, open_time.split(":"))
            if not (0 <= hour <= 23 and 0 <= minute <= 59):
                raise ValueError("Invalid open time")

            hour, minute = map(int, close_time.split(":"))
            if not (0 <= hour <= 23 and 0 <= minute <= 59):
                raise ValueError("Invalid close time")
        except ValueError:
            raise ValueError("Time must be in HH:MM format")

        self.business_hours[day] = {
            "open": open_time,
            "close": close_time,
            "enabled": enabled,
        }

    def add_contact_info(self, contact_type: str, value: str) -> None:
        """
        Add contact information

        Args:
            contact_type: Type of contact (phone, email, fax, etc.)
            value: Contact value
        """
        self.contact_info[contact_type] = value

    def update_statistics(self, stat_name: str, value: Any) -> None:
        """
        Update operational statistics

        Args:
            stat_name: Statistics name
            value: Statistics value
        """
        self.statistics[stat_name] = value
        self.statistics["last_updated"] = datetime.now().isoformat()

    def increment_statistic(self, stat_name: str, increment: int = 1) -> int:
        """
        Increment a numeric statistic

        Args:
            stat_name: Statistics name
            increment: Amount to increment

        Returns:
            New statistic value
        """
        current_value = self.statistics.get(stat_name, 0)
        new_value = current_value + increment
        self.statistics[stat_name] = new_value
        self.statistics["last_updated"] = datetime.now().isoformat()
        return new_value

    def get_daily_statistics(self) -> Dict[str, Any]:
        """
        Get daily operational statistics

        Returns:
            Dictionary with daily stats
        """
        today = datetime.now().date().isoformat()

        return {
            "date": today,
            "documents_scanned": self.statistics.get(f"daily_{today}_scanned", 0),
            "documents_uploaded": self.statistics.get(f"daily_{today}_uploaded", 0),
            "active_sessions": self.statistics.get(f"daily_{today}_sessions", 0),
            "processing_errors": self.statistics.get(f"daily_{today}_errors", 0),
            "average_processing_time": self.statistics.get(
                f"daily_{today}_avg_time", 0.0
            ),
        }

    def set_maintenance_mode(self, enabled: bool, reason: str = "") -> None:
        """
        Enable/disable maintenance mode

        Args:
            enabled: Whether to enable maintenance mode
            reason: Reason for maintenance
        """
        if enabled:
            self.status = BranchStatus.MAINTENANCE
            self.metadata["maintenance_reason"] = reason
            self.metadata["maintenance_started"] = datetime.now().isoformat()
        else:
            self.status = BranchStatus.ACTIVE
            if "maintenance_reason" in self.metadata:
                del self.metadata["maintenance_reason"]
            if "maintenance_started" in self.metadata:
                del self.metadata["maintenance_started"]

    def get_full_address(self) -> str:
        """
        Get formatted full address

        Returns:
            Formatted address string
        """
        parts = [
            self.address.get("street", ""),
            self.address.get("city", ""),
            self.address.get("state", ""),
            self.address.get("postal_code", ""),
            self.address.get("country", ""),
        ]

        return ", ".join(part for part in parts if part)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert branch to dictionary representation

        Returns:
            Dictionary with branch data
        """
        return {
            "branch_id": self.branch_id,
            "name": self.name,
            "display_name": self.display_name,
            "branch_type": self.branch_type.value,
            "status": self.status.value,
            "address": self.address.copy(),
            "full_address": self.get_full_address(),
            "created_at": self.created_at.isoformat(),
            "timezone": self.timezone,
            "business_hours": self.business_hours.copy(),
            "contact_info": self.contact_info.copy(),
            "configuration": self.configuration.copy(),
            "statistics": self.statistics.copy(),
            "daily_stats": self.get_daily_statistics(),
            "is_operational": self.is_operational(),
            "is_business_hours": self.is_during_business_hours(),
            "metadata": self.metadata.copy(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Branch":
        """
        Create branch from dictionary representation

        Args:
            data: Dictionary with branch data

        Returns:
            Branch instance
        """
        created_at = datetime.fromisoformat(data["created_at"])

        branch = cls(
            branch_id=data["branch_id"],
            name=data["name"],
            display_name=data["display_name"],
            branch_type=BranchType(data["branch_type"]),
            address=data["address"],
            created_at=created_at,
        )

        # Set optional fields
        branch.status = BranchStatus(data["status"])
        branch.timezone = data.get("timezone", "America/Mexico_City")
        branch.business_hours = data.get("business_hours", {}).copy()
        branch.contact_info = data.get("contact_info", {}).copy()
        branch.configuration = data.get("configuration", {}).copy()
        branch.statistics = data.get("statistics", {}).copy()
        branch.metadata = data.get("metadata", {}).copy()

        return branch

    def __str__(self) -> str:
        """String representation"""
        return f"Branch(name={self.name}, type={self.branch_type.value}, status={self.status.value})"

    def __repr__(self) -> str:
        """Detailed string representation"""
        return (
            f"Branch(branch_id='{self.branch_id}', "
            f"name='{self.name}', display_name='{self.display_name}', "
            f"type={self.branch_type.value}, status={self.status.value})"
        )
