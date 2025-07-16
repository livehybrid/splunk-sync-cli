"""
Unit tests for configuration management module.

This module tests the configuration loading, validation, and management
functionality of the Splunk Synchronization Tool.
"""

import pytest
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open

from splunk_sync.config import (
    SyncMode,
    SplunkConnectionConfig,
    ProxyConfig,
    KnowledgeObjectConfig,
    SyncConfig,
    ConfigManager,
)
from splunk_sync.exceptions import ConfigurationError


class TestSyncMode:
    """Test SyncMode enumeration."""

    def test_sync_mode_values(self):
        """Test SyncMode enum values."""
        assert SyncMode.PUSH.value == "push"
        assert SyncMode.PULL.value == "pull"
        assert SyncMode.SYNC.value == "sync"


class TestSplunkConnectionConfig:
    """Test SplunkConnectionConfig dataclass."""

    def test_valid_config_with_token(self):
        """Test valid configuration with token."""
        config = SplunkConnectionConfig(host="localhost", port=8089, token="test-token")
        assert config.host == "localhost"
        assert config.port == 8089
        assert config.token == "test-token"
        assert config.base_url == "https://localhost:8089"

    def test_valid_config_with_username_password(self):
        """Test valid configuration with username/password."""
        config = SplunkConnectionConfig(
            host="localhost", username="admin", password="changeme"
        )
        assert config.username == "admin"
        assert config.password == "changeme"

    def test_invalid_config_no_auth(self):
        """Test invalid configuration without authentication."""
        with pytest.raises(
            ValueError, match="Either token or username/password must be provided"
        ):
            SplunkConnectionConfig(host="localhost")

    def test_invalid_port(self):
        """Test invalid port number."""
        with pytest.raises(ValueError, match="Invalid port number"):
            SplunkConnectionConfig(host="localhost", port=70000, token="test-token")

    def test_invalid_scheme(self):
        """Test invalid scheme."""
        with pytest.raises(ValueError, match="Invalid scheme"):
            SplunkConnectionConfig(host="localhost", scheme="ftp", token="test-token")

    def test_base_url_http(self):
        """Test base URL with HTTP scheme."""
        config = SplunkConnectionConfig(
            host="localhost", port=8000, scheme="http", token="test-token"
        )
        assert config.base_url == "http://localhost:8000"


class TestProxyConfig:
    """Test ProxyConfig dataclass."""

    def test_proxy_disabled(self):
        """Test proxy configuration when disabled."""
        config = ProxyConfig()
        assert not config.enabled
        assert config.url is None

    def test_proxy_enabled_without_auth(self):
        """Test proxy configuration without authentication."""
        config = ProxyConfig(host="proxy.example.com", port=8080)
        assert config.enabled
        assert config.url == "http://proxy.example.com:8080"

    def test_proxy_enabled_with_auth(self):
        """Test proxy configuration with authentication."""
        config = ProxyConfig(
            host="proxy.example.com", port=8080, username="user", password="pass"
        )
        assert config.enabled
        assert config.url == "http://user:pass@proxy.example.com:8080"


class TestKnowledgeObjectConfig:
    """Test KnowledgeObjectConfig dataclass."""

    def test_default_config(self):
        """Test default knowledge object configuration."""
        config = KnowledgeObjectConfig()
        assert "macros" in config.types
        assert "savedsearches" in config.types
        assert config.savedsearches_allowlist == ".*"
        assert not config.email_actions_allowed
        assert config.rbac_enabled

    def test_custom_config(self):
        """Test custom knowledge object configuration."""
        config = KnowledgeObjectConfig(
            types=["macros", "tags"],
            savedsearches_allowlist="Alert.*",
            email_actions_allowed=True,
            rbac_enabled=False,
        )
        assert config.types == ["macros", "tags"]
        assert config.savedsearches_allowlist == "Alert.*"
        assert config.email_actions_allowed
        assert not config.rbac_enabled

    def test_invalid_regex(self):
        """Test invalid regex pattern."""
        with pytest.raises(ValueError, match="Invalid savedsearches allowlist regex"):
            KnowledgeObjectConfig(savedsearches_allowlist="[invalid")


class TestSyncConfig:
    """Test SyncConfig dataclass."""

    def test_valid_config(
        self, splunk_connection_config, proxy_config, knowledge_object_config
    ):
        """Test valid sync configuration."""
        config = SyncConfig(
            splunk=splunk_connection_config,
            proxy=proxy_config,
            knowledge_objects=knowledge_object_config,
        )
        assert config.splunk == splunk_connection_config
        assert config.proxy == proxy_config
        assert config.knowledge_objects == knowledge_object_config
        assert config.mode == SyncMode.PUSH

    def test_invalid_apps_path(self, splunk_connection_config):
        """Test invalid apps path."""
        with pytest.raises(ValueError, match="Apps path does not exist"):
            SyncConfig(splunk=splunk_connection_config, apps_path="/non/existent/path")

    def test_invalid_log_level(self, splunk_connection_config):
        """Test invalid log level."""
        with pytest.raises(ValueError, match="Invalid log level"):
            SyncConfig(splunk=splunk_connection_config, log_level="INVALID")

    def test_invalid_batch_size(self, splunk_connection_config):
        """Test invalid batch size."""
        with pytest.raises(ValueError, match="Invalid batch size"):
            SyncConfig(splunk=splunk_connection_config, batch_size=0)


class TestConfigManager:
    """Test ConfigManager class."""

    def test_init_without_config_path(self):
        """Test initialization without config path."""
        manager = ConfigManager()
        assert manager.config_path is None
        assert manager._config is None

    def test_init_with_config_path(self):
        """Test initialization with config path."""
        manager = ConfigManager("/path/to/config.conf")
        assert manager.config_path == "/path/to/config.conf"

    def test_convert_value_boolean(self):
        """Test value conversion for booleans."""
        manager = ConfigManager()

        # True values
        assert manager._convert_value("true") is True
        assert manager._convert_value("yes") is True
        assert manager._convert_value("1") is True
        assert manager._convert_value("on") is True

        # False values
        assert manager._convert_value("false") is False
        assert manager._convert_value("no") is False
        assert manager._convert_value("0") is False
        assert manager._convert_value("off") is False

    def test_convert_value_integer(self):
        """Test value conversion for integers."""
        manager = ConfigManager()
        assert manager._convert_value("123") == 123
        assert manager._convert_value("-456") == -456

    def test_convert_value_float(self):
        """Test value conversion for floats."""
        manager = ConfigManager()
        assert manager._convert_value("3.14") == 3.14
        assert manager._convert_value("-2.5") == -2.5

    def test_convert_value_string(self):
        """Test value conversion for strings."""
        manager = ConfigManager()
        assert manager._convert_value("hello") == "hello"
        assert manager._convert_value("") == ""

    def test_find_config_file_with_explicit_path(self, mock_config_file):
        """Test finding config file with explicit path."""
        manager = ConfigManager(str(mock_config_file))
        found_path = manager._find_config_file()
        assert found_path == str(mock_config_file)

    def test_find_config_file_nonexistent_explicit_path(self):
        """Test finding config file with nonexistent explicit path."""
        manager = ConfigManager("/non/existent/config.conf")
        with pytest.raises(FileNotFoundError):
            manager._find_config_file()

    @patch("pathlib.Path.expanduser")
    @patch("pathlib.Path.exists")
    def test_find_config_file_in_standard_locations(self, mock_exists, mock_expanduser):
        """Test finding config file in standard locations."""
        manager = ConfigManager()

        # Mock the first standard location to exist
        mock_expanduser.return_value = Path("/home/user/config.conf")
        mock_exists.side_effect = lambda: True

        found_path = manager._find_config_file()
        assert found_path is not None

    def test_find_config_file_not_found(self):
        """Test when config file is not found."""
        manager = ConfigManager()

        with patch("pathlib.Path.exists", return_value=False):
            found_path = manager._find_config_file()
            assert found_path is None

    def test_load_base_config_no_file(self):
        """Test loading base config when no file exists."""
        manager = ConfigManager()

        with patch.object(manager, "_find_config_file", return_value=None):
            config_data = manager._load_base_config()
            assert config_data == {}

    def test_load_base_config_with_file(self, mock_config_file):
        """Test loading base config from file."""
        manager = ConfigManager(str(mock_config_file))
        config_data = manager._load_base_config()

        assert "splunk" in config_data
        assert config_data["splunk"]["host"] == "localhost"
        assert config_data["splunk"]["port"] == 8089
        assert config_data["splunk"]["verify_ssl"] is True

    def test_apply_environment_overrides(self, mock_environment_variables):
        """Test applying environment variable overrides."""
        manager = ConfigManager()
        config_data = {}

        manager._apply_environment_overrides(config_data)

        assert config_data["splunk"]["host"] == "test.splunk.com"
        assert config_data["splunk"]["token"] == "test-token"
        assert config_data["splunk"]["app"] == "test_app"
        assert config_data["knowledge_objects"]["savedsearches_allowlist"] == "Alert.*"
        assert config_data["dry_run"] is True

    def test_load_config_from_file(self, mock_config_file):
        """Test loading complete configuration from file."""
        manager = ConfigManager(str(mock_config_file))
        config = manager.load_config()

        assert isinstance(config, SyncConfig)
        assert config.splunk.host == "localhost"
        assert config.splunk.port == 8089
        assert config.target_app == "search"
        assert config.mode == SyncMode.PUSH

    def test_load_config_cached(self, mock_config_file):
        """Test that configuration is cached."""
        manager = ConfigManager(str(mock_config_file))

        config1 = manager.load_config()
        config2 = manager.load_config()

        assert config1 is config2

    def test_validate_config_valid(self, sync_config):
        """Test validation of valid configuration."""
        manager = ConfigManager()

        # Create temporary apps directory
        with tempfile.TemporaryDirectory() as temp_dir:
            sync_config.apps_path = temp_dir
            issues = manager.validate_config(sync_config)
            assert issues == []

    def test_validate_config_missing_host(self, sync_config):
        """Test validation with missing host."""
        manager = ConfigManager()
        sync_config.splunk.host = ""

        with tempfile.TemporaryDirectory() as temp_dir:
            sync_config.apps_path = temp_dir
            issues = manager.validate_config(sync_config)
            assert "Splunk host is required" in issues

    def test_validate_config_missing_target_app(self, sync_config):
        """Test validation with missing target app."""
        manager = ConfigManager()
        sync_config.target_app = ""

        with tempfile.TemporaryDirectory() as temp_dir:
            sync_config.apps_path = temp_dir
            issues = manager.validate_config(sync_config)
            assert "Target app is required" in issues

    def test_validate_config_nonexistent_apps_path(self, sync_config):
        """Test validation with nonexistent apps path."""
        manager = ConfigManager()
        sync_config.apps_path = "/non/existent/path"

        issues = manager.validate_config(sync_config)
        assert any("Apps path does not exist" in issue for issue in issues)

    def test_validate_config_invalid_ko_types(self, sync_config):
        """Test validation with invalid knowledge object types."""
        manager = ConfigManager()
        sync_config.knowledge_objects.types = ["invalid_type"]

        with tempfile.TemporaryDirectory() as temp_dir:
            sync_config.apps_path = temp_dir
            issues = manager.validate_config(sync_config)
            assert any("Invalid knowledge object types" in issue for issue in issues)

    def test_create_sample_config(self, temp_dir):
        """Test creating sample configuration."""
        manager = ConfigManager()
        config_path = temp_dir / "sample.conf"

        manager.create_sample_config(str(config_path))

        assert config_path.exists()
        content = config_path.read_text()
        assert "[splunk]" in content
        assert "host = localhost" in content
        assert "[knowledge_objects]" in content

    def test_load_config_with_environment_overrides(
        self, mock_config_file, mock_environment_variables
    ):
        """Test loading configuration with environment overrides."""
        manager = ConfigManager(str(mock_config_file))
        config = manager.load_config()

        # Environment variables should override file values
        assert config.splunk.host == "test.splunk.com"
        assert config.splunk.token == "test-token"
        assert config.dry_run is True

    def test_load_config_missing_required_auth(self, temp_dir):
        """Test loading config with missing authentication."""
        # Create config file without authentication
        config_file = temp_dir / "invalid.conf"
        config_file.write_text(
            """[splunk]
host = localhost
port = 8089
"""
        )

        manager = ConfigManager(str(config_file))

        with pytest.raises(
            ValueError, match="Either token or username/password must be provided"
        ):
            manager.load_config()


class TestConfigIntegration:
    """Integration tests for configuration module."""

    def test_end_to_end_config_loading(self, temp_dir):
        """Test end-to-end configuration loading."""
        # Create config file
        config_file = temp_dir / "integration.conf"
        config_content = """[splunk]
host = integration.splunk.com
port = 8089
token = integration-token
app = integration_app

[knowledge_objects]
types = macros,savedsearches
savedsearches_allowlist = Integration.*
rbac_enabled = true

mode = sync
dry_run = true
target_app = integration_app
"""
        config_file.write_text(config_content)

        # Create apps directory
        apps_dir = temp_dir / "apps"
        apps_dir.mkdir()

        # Load configuration
        manager = ConfigManager(str(config_file))
        config = manager.load_config()

        # Update apps_path to use our temp directory
        config.apps_path = str(apps_dir)

        # Validate configuration
        issues = manager.validate_config(config)
        assert issues == []

        # Verify configuration values
        assert config.splunk.host == "integration.splunk.com"
        assert config.splunk.token == "integration-token"
        assert config.mode == SyncMode.SYNC
        assert config.dry_run is True
        assert config.knowledge_objects.types == ["macros", "savedsearches"]
        assert config.knowledge_objects.savedsearches_allowlist == "Integration.*"

    def test_config_with_proxy(self, temp_dir):
        """Test configuration with proxy settings."""
        config_file = temp_dir / "proxy.conf"
        config_content = """[splunk]
host = localhost
token = test-token

[proxy]
host = proxy.example.com
port = 8080
username = proxy_user
password = proxy_pass
"""
        config_file.write_text(config_content)

        apps_dir = temp_dir / "apps"
        apps_dir.mkdir()

        manager = ConfigManager(str(config_file))
        config = manager.load_config()
        config.apps_path = str(apps_dir)

        assert config.proxy.enabled
        assert config.proxy.host == "proxy.example.com"
        assert config.proxy.port == 8080
        assert config.proxy.username == "proxy_user"
        assert config.proxy.password == "proxy_pass"
        assert config.proxy.url == "http://proxy_user:proxy_pass@proxy.example.com:8080"
