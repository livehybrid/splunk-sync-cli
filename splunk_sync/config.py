"""
Configuration management for Splunk synchronization tool.

This module provides a centralized configuration system with validation,
environment variable support, and extensible settings management.
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union, Any
import configparser
import logging
from enum import Enum

logger = logging.getLogger(__name__)


class SyncMode(Enum):
    """Synchronization modes supported by the tool."""

    PUSH = "push"
    PULL = "pull"
    SYNC = "sync"


@dataclass
class SplunkConnectionConfig:
    """Configuration for Splunk server connection."""

    host: str
    port: int = 8089
    scheme: str = "https"
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    app: str = "search"
    owner: str = "admin"
    verify_ssl: bool = True
    timeout: int = 60
    retry_count: int = 3
    retry_delay: float = 1.0

    def __post_init__(self):
        """Validate configuration after initialization."""
        if not self.token and not (self.username and self.password):
            raise ValueError("Either token or username/password must be provided")

        if self.port <= 0 or self.port > 65535:
            raise ValueError(f"Invalid port number: {self.port}")

        if self.scheme not in ("http", "https"):
            raise ValueError(f"Invalid scheme: {self.scheme}")

    @property
    def base_url(self) -> str:
        """Generate the base URL for Splunk API."""
        return f"{self.scheme}://{self.host}:{self.port}"


@dataclass
class ProxyConfig:
    """Configuration for proxy settings."""

    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None

    @property
    def enabled(self) -> bool:
        """Check if proxy is enabled."""
        return bool(self.host and self.port)

    @property
    def url(self) -> Optional[str]:
        """Generate proxy URL."""
        if not self.enabled:
            return None

        auth = ""
        if self.username and self.password:
            auth = f"{self.username}:{self.password}@"

        return f"http://{auth}{self.host}:{self.port}"


@dataclass
class KnowledgeObjectConfig:
    """Configuration for knowledge object processing."""

    types: List[str] = field(
        default_factory=lambda: [
            "macros",
            "tags",
            "eventtypes",
            "savedsearches",
            "workflow_actions",
            "transforms",
            "props",
            "lookups",
        ]
    )
    ignored_keys: List[str] = field(
        default_factory=lambda: ["actions", "alert_threshold", "alert_comparator"]
    )
    savedsearches_allowlist: str = ".*"
    email_actions_allowed: bool = False
    rbac_enabled: bool = True
    default_permissions: Dict[str, str] = field(
        default_factory=lambda: {"owner": "admin", "sharing": "app"}
    )

    def __post_init__(self):
        """Validate knowledge object configuration."""
        # Validate regex pattern
        try:
            re.compile(self.savedsearches_allowlist)
        except re.error as e:
            raise ValueError(f"Invalid savedsearches allowlist regex: {e}")


@dataclass
class SyncConfig:
    """Main configuration for synchronization operations."""

    splunk: SplunkConnectionConfig
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    knowledge_objects: KnowledgeObjectConfig = field(
        default_factory=KnowledgeObjectConfig
    )

    # Sync settings
    mode: SyncMode = SyncMode.PUSH
    dry_run: bool = False
    apps_path: str = "./apps"
    target_app: str = "search"

    # Logging settings
    log_level: str = "INFO"
    log_file: Optional[str] = None
    debug: bool = False

    # Performance settings
    batch_size: int = 100
    concurrent_requests: int = 5

    def __post_init__(self):
        """Validate sync configuration."""
        apps_path = Path(self.apps_path)
        # Allow using the default path even if it does not exist to simplify
        # creation of the configuration object in tests and CLI usage.  A
        # missing path will still be reported by ``ConfigManager.validate_config``.
        if self.apps_path != "./apps" and not apps_path.exists():
            raise ValueError(f"Apps path does not exist: {self.apps_path}")

        if self.log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            raise ValueError(f"Invalid log level: {self.log_level}")

        if self.batch_size <= 0:
            raise ValueError(f"Invalid batch size: {self.batch_size}")

        if self.concurrent_requests <= 0:
            raise ValueError(f"Invalid concurrent requests: {self.concurrent_requests}")


class ConfigManager:
    """Manages configuration loading and validation."""

    DEFAULT_CONFIG_PATHS = [
        "splunk_sync.conf",
        "~/.splunk_sync.conf",
        "/etc/splunk_sync.conf",
    ]

    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration manager."""
        self.config_path = config_path
        self._config: Optional[SyncConfig] = None

    def load_config(self) -> SyncConfig:
        """Load configuration from file and environment variables."""
        if self._config is not None:
            return self._config

        config_data = self._load_base_config()
        self._apply_environment_overrides(config_data)

        # Build configuration objects
        splunk_config = SplunkConnectionConfig(**config_data.get("splunk", {}))
        proxy_config = ProxyConfig(**config_data.get("proxy", {}))
        ko_config = KnowledgeObjectConfig(**config_data.get("knowledge_objects", {}))

        # Extract sync settings
        sync_settings = {
            k: v
            for k, v in config_data.items()
            if k not in ("splunk", "proxy", "knowledge_objects")
        }

        self._config = SyncConfig(
            splunk=splunk_config,
            proxy=proxy_config,
            knowledge_objects=ko_config,
            **sync_settings,
        )

        logger.info(
            f"Configuration loaded successfully from {self.config_path or 'environment'}"
        )
        return self._config

    def _load_base_config(self) -> Dict[str, Any]:
        """Load base configuration from file."""
        config_file = self._find_config_file()

        if not config_file:
            logger.warning("No configuration file found, using defaults")
            return {}

        self.config_path = config_file
        parser = configparser.ConfigParser()
        parser.read(config_file)

        # Convert to nested dictionary
        config_data = {}
        for section_name in parser.sections():
            section_data = dict(parser[section_name])

            # Convert string values to appropriate types
            for key, value in section_data.items():
                section_data[key] = self._convert_value(value)

            config_data[section_name] = section_data

        return config_data

    def _find_config_file(self) -> Optional[str]:
        """Find configuration file in standard locations."""
        if self.config_path:
            if Path(self.config_path).exists():
                return self.config_path
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")

        for path in self.DEFAULT_CONFIG_PATHS:
            expanded_path = Path(path).expanduser()
            if expanded_path.exists():
                return str(expanded_path)

        return None

    def _apply_environment_overrides(self, config_data: Dict[str, Any]) -> None:
        """Apply environment variable overrides."""
        env_mappings = {
            "SPLUNK_HOST": ("splunk", "host"),
            "SPLUNK_PORT": ("splunk", "port"),
            "SPLUNK_USERNAME": ("splunk", "username"),
            "SPLUNK_PASSWORD": ("splunk", "password"),
            "SPLUNK_TOKEN": ("splunk", "token"),
            "SPLUNK_APP": ("splunk", "app"),
            "SPLUNK_VERIFY_SSL": ("splunk", "verify_ssl"),
            "PROXY_HOST": ("proxy", "host"),
            "PROXY_PORT": ("proxy", "port"),
            "PROXY_USERNAME": ("proxy", "username"),
            "PROXY_PASSWORD": ("proxy", "password"),
            "SAVEDSEARCHES_ALLOWLIST": ("knowledge_objects", "savedsearches_allowlist"),
            "DRY_RUN": (None, "dry_run"),
            "DEBUG": (None, "debug"),
            "LOG_LEVEL": (None, "log_level"),
            "LOG_FILE": (None, "log_file"),
        }

        for env_var, (section, key) in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                converted_value = self._convert_value(value)

                if section:
                    if section not in config_data:
                        config_data[section] = {}
                    config_data[section][key] = converted_value
                else:
                    config_data[key] = converted_value

    def _convert_value(self, value: str) -> Union[str, int, bool, float]:
        """Convert string value to appropriate type."""
        # Boolean conversion
        if value.lower() in ("true", "yes", "1", "on"):
            return True
        if value.lower() in ("false", "no", "0", "off"):
            return False

        # Integer conversion
        try:
            return int(value)
        except ValueError:
            pass

        # Float conversion
        try:
            return float(value)
        except ValueError:
            pass

        # Return as string
        return value

    def validate_config(self, config: SyncConfig) -> List[str]:
        """Validate configuration and return list of issues."""
        issues = []

        # Validate required fields
        if not config.splunk.host:
            issues.append("Splunk host is required")

        if not config.target_app:
            issues.append("Target app is required")

        # Validate paths
        if not Path(config.apps_path).exists():
            issues.append(f"Apps path does not exist: {config.apps_path}")

        # Validate knowledge object types
        valid_ko_types = {
            "macros",
            "tags",
            "eventtypes",
            "savedsearches",
            "workflow_actions",
            "transforms",
            "props",
            "lookups",
            "dashboards",
            "nav",
        }

        invalid_types = set(config.knowledge_objects.types) - valid_ko_types
        if invalid_types:
            issues.append(f"Invalid knowledge object types: {invalid_types}")

        return issues

    def create_sample_config(self, path: str) -> None:
        """Create a sample configuration file."""
        sample_config = """
[splunk]
host = localhost
port = 8089
scheme = https
username = admin
password = changeme
app = search
verify_ssl = true
timeout = 60

[proxy]
# host = proxy.example.com
# port = 8080
# username = proxy_user
# password = proxy_pass

[knowledge_objects]
types = macros,tags,eventtypes,savedsearches,workflow_actions,transforms,props,lookups
savedsearches_allowlist = .*
email_actions_allowed = false
rbac_enabled = true

# Sync settings
mode = push
dry_run = false
apps_path = ./apps
target_app = search
log_level = INFO
debug = false
batch_size = 100
concurrent_requests = 5
"""

        with open(path, "w") as f:
            f.write(sample_config.strip())

        logger.info(f"Sample configuration created at {path}")
