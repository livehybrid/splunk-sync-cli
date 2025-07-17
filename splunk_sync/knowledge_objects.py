"""
Knowledge object management for Splunk synchronization.

This module provides classes for handling different types of Splunk knowledge
objects with proper validation, filtering, and transformation capabilities.
"""

import configparser
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import KnowledgeObjectConfig
from .exceptions import FileOperationError, FilterError, ValidationError

logger = logging.getLogger(__name__)


@dataclass
class KnowledgeObject:
    """Represents a Splunk knowledge object."""

    name: str
    ko_type: str
    content: Dict[str, Any]
    app: str
    owner: str = "admin"
    sharing: str = "app"

    def __post_init__(self):
        """Validate knowledge object after initialization."""
        if not self.name:
            raise ValidationError(
                "Knowledge object name cannot be empty", self.ko_type, self.name
            )

        if not self.content:
            raise ValidationError(
                "Knowledge object content cannot be empty", self.ko_type, self.name
            )


class KnowledgeObjectFilter:
    """Handles filtering of knowledge objects based on various criteria."""

    def __init__(self, config: KnowledgeObjectConfig):
        """Initialize with configuration."""
        self.config = config
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for performance."""
        try:
            self.savedsearches_pattern = re.compile(self.config.savedsearches_allowlist)
        except re.error as e:
            raise FilterError(
                f"Invalid savedsearches allowlist regex: {e}",
                self.config.savedsearches_allowlist,
            )

    def should_process_object(self, ko: KnowledgeObject) -> bool:
        """Determine if a knowledge object should be processed."""
        # Check if KO type is enabled
        if ko.ko_type not in self.config.types:
            logger.debug(f"Skipping {ko.ko_type}/{ko.name} - type not enabled")
            return False

        # Apply savedsearches allowlist
        if ko.ko_type == "savedsearches":
            if not self.savedsearches_pattern.match(ko.name):
                logger.info(
                    f"Skipping savedsearch '{ko.name}' - not in allowlist "
                    f"pattern: {self.config.savedsearches_allowlist}"
                )
                return False

        # Check for email actions if not allowed
        if ko.ko_type == "savedsearches" and not self.config.email_actions_allowed:
            email_keys = [
                key for key in ko.content.keys() if key.startswith("action.email")
            ]
            if email_keys:
                logger.info(
                    f"Skipping savedsearch '{ko.name}' - contains email actions: {email_keys}"
                )
                return False

        return True

    def filter_content(self, ko: KnowledgeObject) -> Dict[str, Any]:
        """Filter content based on ignored keys."""
        filtered_content = {}

        for key, value in ko.content.items():
            # Skip ignored keys
            if key in self.config.ignored_keys:
                logger.debug(f"Ignoring key '{key}' in {ko.ko_type}/{ko.name}")
                continue

            # Remove email actions if not allowed
            if not self.config.email_actions_allowed and key.startswith("action.email"):
                logger.debug(
                    f"Removing email action '{key}' from {ko.ko_type}/{ko.name}"
                )
                continue

            filtered_content[key] = value

        return filtered_content


class KnowledgeObjectHandler(ABC):
    """Abstract base class for knowledge object handlers."""

    def __init__(self, ko_type: str, config: KnowledgeObjectConfig):
        """Initialize handler with type and configuration."""
        self.ko_type = ko_type
        self.config = config
        self.filter = KnowledgeObjectFilter(config)

    @abstractmethod
    def validate(self, ko: KnowledgeObject) -> List[str]:
        """Validate knowledge object and return list of issues."""
        pass

    @abstractmethod
    def transform_for_sync(self, ko: KnowledgeObject) -> Dict[str, Any]:
        """Transform knowledge object for synchronization."""
        pass

    def can_handle(self, ko_type: str) -> bool:
        """Check if this handler can process the given type."""
        return ko_type == self.ko_type


class SavedSearchHandler(KnowledgeObjectHandler):
    """Handler for savedsearches knowledge objects."""

    def __init__(self, config: KnowledgeObjectConfig):
        super().__init__("savedsearches", config)

    def validate(self, ko: KnowledgeObject) -> List[str]:
        """Validate savedsearch configuration."""
        issues = []

        # Check required fields
        if "search" not in ko.content:
            issues.append("search field is required")

        # Validate search query
        search_query = ko.content.get("search", "")
        if not search_query.strip():
            issues.append("search query cannot be empty")

        # Validate email actions if present
        if ko.content.get("action.email") == "1":
            if not ko.content.get("action.email.to"):
                issues.append(
                    "action.email.to is required when email action is enabled"
                )

        # Validate cron schedule if present
        cron_schedule = ko.content.get("cron_schedule")
        if cron_schedule:
            if not self._validate_cron_schedule(cron_schedule):
                issues.append(f"Invalid cron schedule: {cron_schedule}")

        return issues

    def transform_for_sync(self, ko: KnowledgeObject) -> Dict[str, Any]:
        """Transform savedsearch for synchronization."""
        content = self.filter.filter_content(ko)

        # Set default values
        content.setdefault("dispatch.earliest_time", "-24h@h")
        content.setdefault("dispatch.latest_time", "now")
        content.setdefault("is_scheduled", "0")

        # Handle scheduling
        if content.get("is_scheduled") == "1":
            content.setdefault("cron_schedule", "0 6 * * 1")

        return content

    def _validate_cron_schedule(self, schedule: str) -> bool:
        """Validate cron schedule format."""
        parts = schedule.split()
        if len(parts) != 5:
            return False

        # Basic validation - could be more comprehensive
        ranges = [
            (0, 59),  # minute
            (0, 23),  # hour
            (1, 31),  # day
            (1, 12),  # month
            (0, 6),  # weekday
        ]

        for i, (part, (min_val, max_val)) in enumerate(zip(parts, ranges)):
            if part == "*":
                continue

            try:
                value = int(part)
                if not (min_val <= value <= max_val):
                    return False
            except ValueError:
                # Handle ranges, lists, etc.
                if not re.match(r"^[0-9,\-*/]+$", part):
                    return False

        return True


class MacroHandler(KnowledgeObjectHandler):
    """Handler for macros knowledge objects."""

    def __init__(self, config: KnowledgeObjectConfig):
        super().__init__("macros", config)

    def validate(self, ko: KnowledgeObject) -> List[str]:
        """Validate macro configuration."""
        issues = []

        # Check required fields
        if "definition" not in ko.content:
            issues.append("definition field is required")

        # Validate definition
        definition = ko.content.get("definition", "")
        if not definition.strip():
            issues.append("macro definition cannot be empty")

        # Validate arguments if present
        args = ko.content.get("args", "")
        if args:
            # Check argument format
            if not re.match(
                r"^[a-zA-Z_][a-zA-Z0-9_]*(?:,[a-zA-Z_][a-zA-Z0-9_]*)*$", args
            ):
                issues.append(f"Invalid argument format: {args}")

        return issues

    def transform_for_sync(self, ko: KnowledgeObject) -> Dict[str, Any]:
        """Transform macro for synchronization."""
        content = self.filter.filter_content(ko)

        # Set default values
        content.setdefault("args", "")
        content.setdefault("validation", "")

        return content


class EventTypeHandler(KnowledgeObjectHandler):
    """Handler for eventtypes knowledge objects."""

    def __init__(self, config: KnowledgeObjectConfig):
        super().__init__("eventtypes", config)

    def validate(self, ko: KnowledgeObject) -> List[str]:
        """Validate eventtype configuration."""
        issues = []

        # Check required fields
        if "search" not in ko.content:
            issues.append("search field is required")

        # Validate search query
        search_query = ko.content.get("search", "")
        if not search_query.strip():
            issues.append("search query cannot be empty")

        # Validate priority if present
        priority = ko.content.get("priority")
        if priority:
            try:
                priority_int = int(priority)
                if not (1 <= priority_int <= 10):
                    issues.append("priority must be between 1 and 10")
            except ValueError:
                issues.append("priority must be a number")

        return issues

    def transform_for_sync(self, ko: KnowledgeObject) -> Dict[str, Any]:
        """Transform eventtype for synchronization."""
        content = self.filter.filter_content(ko)

        # Set default values
        content.setdefault("priority", "1")
        content.setdefault("disabled", "0")

        return content


class TagHandler(KnowledgeObjectHandler):
    """Handler for tags knowledge objects."""

    def __init__(self, config: KnowledgeObjectConfig):
        super().__init__("tags", config)

    def validate(self, ko: KnowledgeObject) -> List[str]:
        """Validate tag configuration."""
        issues = []

        # Tags have minimal validation requirements
        # Each key-value pair represents a tag assignment
        for key, value in ko.content.items():
            if not key.strip():
                issues.append("tag key cannot be empty")

            if value not in ("enabled", "disabled"):
                issues.append("tag value must be 'enabled' or 'disabled'")

        return issues

    def transform_for_sync(self, ko: KnowledgeObject) -> Dict[str, Any]:
        """Transform tag for synchronization."""
        content = self.filter.filter_content(ko)

        # Ensure all values are valid
        for key, value in content.items():
            if value not in ("enabled", "disabled"):
                content[key] = "enabled"

        return content


class WorkflowActionHandler(KnowledgeObjectHandler):
    """Handler for workflow_actions knowledge objects."""

    def __init__(self, config: KnowledgeObjectConfig):
        super().__init__("workflow_actions", config)

    def validate(self, ko: KnowledgeObject) -> List[str]:
        """Validate workflow action configuration."""
        issues = []

        # Check required fields
        if "link.method" not in ko.content:
            issues.append("link.method field is required")

        if "link.uri" not in ko.content:
            issues.append("link.uri field is required")

        # Validate method
        method = ko.content.get("link.method", "")
        if method not in ("get", "post"):
            issues.append("link.method must be 'get' or 'post'")

        # Validate URI
        uri = ko.content.get("link.uri", "")
        if not uri.strip():
            issues.append("link.uri cannot be empty")

        return issues

    def transform_for_sync(self, ko: KnowledgeObject) -> Dict[str, Any]:
        """Transform workflow action for synchronization."""
        content = self.filter.filter_content(ko)

        # Set default values
        content.setdefault("display_location", "field_menu")
        content.setdefault("type", "link")

        return content


class TransformHandler(KnowledgeObjectHandler):
    """Handler for transforms knowledge objects."""

    def __init__(self, config: KnowledgeObjectConfig):
        super().__init__("transforms", config)

    def validate(self, ko: KnowledgeObject) -> List[str]:
        """Validate transform configuration."""
        issues = []

        # Transforms have complex validation based on type
        # This is a simplified version

        if "REGEX" in ko.content and "FORMAT" not in ko.content:
            issues.append("FORMAT field is required when REGEX is present")

        return issues

    def transform_for_sync(self, ko: KnowledgeObject) -> Dict[str, Any]:
        """Transform transforms for synchronization."""
        return self.filter.filter_content(ko)


class PropsHandler(KnowledgeObjectHandler):
    """Handler for props knowledge objects."""

    def __init__(self, config: KnowledgeObjectConfig):
        super().__init__("props", config)

    def validate(self, ko: KnowledgeObject) -> List[str]:
        """Validate props configuration."""
        issues = []

        # Props validation is complex and depends on the stanza type
        # This is a simplified version

        return issues

    def transform_for_sync(self, ko: KnowledgeObject) -> Dict[str, Any]:
        """Transform props for synchronization."""
        return self.filter.filter_content(ko)


class KnowledgeObjectManager:
    """Manages knowledge objects with proper handlers and validation."""

    def __init__(self, config: KnowledgeObjectConfig):
        """Initialize with configuration."""
        self.config = config
        self.handlers = self._create_handlers()
        self.filter = KnowledgeObjectFilter(config)

    def _create_handlers(self) -> Dict[str, KnowledgeObjectHandler]:
        """Create handlers for each knowledge object type."""
        handlers = {
            "savedsearches": SavedSearchHandler(self.config),
            "macros": MacroHandler(self.config),
            "eventtypes": EventTypeHandler(self.config),
            "tags": TagHandler(self.config),
            "workflow_actions": WorkflowActionHandler(self.config),
            "transforms": TransformHandler(self.config),
            "props": PropsHandler(self.config),
        }

        return handlers

    def get_handler(self, ko_type: str) -> Optional[KnowledgeObjectHandler]:
        """Get handler for a specific knowledge object type."""
        return self.handlers.get(ko_type)

    def validate_object(self, ko: KnowledgeObject) -> List[str]:
        """Validate a knowledge object."""
        handler = self.get_handler(ko.ko_type)
        if not handler:
            return [f"No handler available for type: {ko.ko_type}"]

        return handler.validate(ko)

    def transform_object(self, ko: KnowledgeObject) -> Dict[str, Any]:
        """Transform a knowledge object for synchronization."""
        handler = self.get_handler(ko.ko_type)
        if not handler:
            raise ValidationError(
                f"No handler available for type: {ko.ko_type}", ko.ko_type, ko.name
            )

        return handler.transform_for_sync(ko)

    def should_process_object(self, ko: KnowledgeObject) -> bool:
        """Check if an object should be processed."""
        return self.filter.should_process_object(ko)

    def load_from_file(
        self, file_path: Path, ko_type: str, app: str
    ) -> List[KnowledgeObject]:
        """Load knowledge objects from a configuration file."""
        try:
            if not file_path.exists():
                logger.warning(f"Configuration file not found: {file_path}")
                return []

            config = configparser.RawConfigParser()
            config.optionxform = str  # Preserve case
            config.read(file_path)

            objects = []
            for section_name in config.sections():
                content = dict(config[section_name])

                ko = KnowledgeObject(
                    name=section_name, ko_type=ko_type, content=content, app=app
                )

                # Validate object
                issues = self.validate_object(ko)
                if issues:
                    logger.warning(
                        f"Validation issues for {ko_type}/{section_name}: {issues}"
                    )
                    continue

                # Check if should be processed
                if self.should_process_object(ko):
                    objects.append(ko)

            logger.info(f"Loaded {len(objects)} {ko_type} objects from {file_path}")
            return objects

        except Exception as e:
            raise FileOperationError(
                f"Failed to load {ko_type} from {file_path}: {e}",
                str(file_path),
                "read",
            )

    def save_to_file(
        self, objects: List[KnowledgeObject], file_path: Path, ko_type: str
    ) -> None:
        """Save knowledge objects to a configuration file."""
        try:
            config = configparser.RawConfigParser()
            config.optionxform = str  # Preserve case

            for ko in objects:
                if ko.ko_type != ko_type:
                    continue

                content = self.transform_object(ko)
                config.add_section(ko.name)

                for key, value in content.items():
                    config.set(ko.name, key, str(value))

            # Ensure directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)

            with open(file_path, "w") as f:
                config.write(f)

            logger.info(f"Saved {len(objects)} {ko_type} objects to {file_path}")

        except Exception as e:
            raise FileOperationError(
                f"Failed to save {ko_type} to {file_path}: {e}", str(file_path), "write"
            )
