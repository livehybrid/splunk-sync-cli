"""
Pytest configuration and fixtures for Splunk Synchronization Tool tests.

This module provides common fixtures and configuration for all test modules.
"""

import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, Mock

import pytest

from splunk_sync.config import (KnowledgeObjectConfig, ProxyConfig,
                                SplunkConnectionConfig, SyncConfig, SyncMode)
from splunk_sync.knowledge_objects import KnowledgeObject
from splunk_sync.rbac import ACL, Permission, SharingLevel


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def sample_config_data() -> Dict[str, Any]:
    """Sample configuration data for testing."""
    return {
        "splunk": {
            "host": "localhost",
            "port": 8089,
            "scheme": "https",
            "username": "admin",
            "password": "changeme",
            "app": "search",
            "verify_ssl": True,
            "timeout": 60,
        },
        "knowledge_objects": {
            "types": ["macros", "savedsearches", "eventtypes"],
            "savedsearches_allowlist": ".*",
            "email_actions_allowed": False,
            "rbac_enabled": True,
        },
        "mode": "push",
        "dry_run": False,
        "apps_path": "./apps",
        "target_app": "search",
        "log_level": "INFO",
    }


@pytest.fixture
def splunk_connection_config() -> SplunkConnectionConfig:
    """Sample Splunk connection configuration."""
    return SplunkConnectionConfig(
        host="localhost",
        port=8089,
        scheme="https",
        username="admin",
        password="changeme",
        token="changeme",
        app="search",
        owner="admin",
        verify_ssl=True,
        timeout=60,
        retry_count=3,
        retry_delay=1.0,
    )


@pytest.fixture
def proxy_config() -> ProxyConfig:
    """Sample proxy configuration."""
    return ProxyConfig(
        host="proxy.example.com",
        port=8080,
        username="proxy_user",
        password="proxy_pass",
    )


@pytest.fixture
def knowledge_object_config() -> KnowledgeObjectConfig:
    """Sample knowledge object configuration."""
    return KnowledgeObjectConfig(
        types=["macros", "savedsearches", "eventtypes"],
        savedsearches_allowlist=".*",
        email_actions_allowed=False,
        rbac_enabled=True,
    )


@pytest.fixture
def sync_config(
    splunk_connection_config, proxy_config, knowledge_object_config
) -> SyncConfig:
    """Complete sync configuration."""
    return SyncConfig(
        splunk=splunk_connection_config,
        proxy=proxy_config,
        knowledge_objects=knowledge_object_config,
        mode=SyncMode.PUSH,
        dry_run=False,
        apps_path="./apps",
        target_app="search",
        log_level="INFO",
    )


@pytest.fixture
def sample_knowledge_object() -> KnowledgeObject:
    """Sample knowledge object for testing."""
    return KnowledgeObject(
        name="test_macro",
        ko_type="macros",
        content={"definition": "index=main", "args": "field1,field2"},
        app="search",
        owner="admin",
        sharing="app",
    )


@pytest.fixture
def sample_savedsearch() -> KnowledgeObject:
    """Sample savedsearch for testing."""
    return KnowledgeObject(
        name="test_alert",
        ko_type="savedsearches",
        content={
            "search": "index=main | stats count",
            "dispatch.earliest_time": "-1h",
            "dispatch.latest_time": "now",
            "cron_schedule": "0 */6 * * *",
            "is_scheduled": "1",
        },
        app="search",
        owner="admin",
        sharing="app",
    )


@pytest.fixture
def sample_eventtype() -> KnowledgeObject:
    """Sample eventtype for testing."""
    return KnowledgeObject(
        name="test_eventtype",
        ko_type="eventtypes",
        content={"search": "index=main source=test", "priority": "1", "disabled": "0"},
        app="search",
        owner="admin",
        sharing="app",
    )


@pytest.fixture
def sample_acl() -> ACL:
    """Sample ACL for testing."""
    return ACL(
        owner="admin",
        app="search",
        sharing=SharingLevel.APP,
        permissions=Permission(read={"*"}, write={"admin", "power"}),
        modifiable=True,
        removable=True,
    )


@pytest.fixture
def mock_splunk_service():
    """Mock Splunk service for testing."""
    service = Mock()
    service.token = "mock-token"
    service.info = {
        "version": "8.2.0",
        "build": "12345",
        "server_name": "mock-server",
        "license_state": "OK",
    }
    service.apps = {}
    service.confs = {}
    service.namespace = Mock()
    service.namespace.app = "search"
    service.namespace.owner = "admin"
    return service


@pytest.fixture
def mock_splunk_conf():
    """Mock Splunk configuration object."""
    conf = Mock()
    conf.name = "test_conf"

    # Mock stanza
    stanza = Mock()
    stanza.name = "test_stanza"
    stanza.content = {"definition": "index=main", "args": "field1,field2"}
    stanza.access = Mock()
    stanza.access.owner = "admin"
    stanza.access.app = "search"
    stanza.access.sharing = "app"
    stanza.access.modifiable = True
    stanza.access.removable = True

    conf.__iter__ = Mock(return_value=iter([stanza]))
    conf.__getitem__ = Mock(return_value=stanza)

    return conf


@pytest.fixture
def sample_conf_file_content() -> str:
    """Sample .conf file content for testing."""
    return """[test_macro]
definition = index=main
args = field1,field2

[another_macro]
definition = index=security
args = user,action
"""


@pytest.fixture
def sample_savedsearches_conf_content() -> str:
    """Sample savedsearches.conf content for testing."""
    return """[Test Alert]
search = index=main | stats count
dispatch.earliest_time = -1h
dispatch.latest_time = now
cron_schedule = 0 */6 * * *
is_scheduled = 1
alert.track = 1

[Test Report]
search = index=main | stats count by host
dispatch.earliest_time = -24h
dispatch.latest_time = now
is_scheduled = 0
"""


@pytest.fixture
def mock_config_file(temp_dir, sample_config_data):
    """Create a mock configuration file."""
    config_file = temp_dir / "test_config.conf"

    # Write configuration in INI format
    config_content = """[splunk]
host = localhost
port = 8089
scheme = https
username = admin
password = changeme
app = search
verify_ssl = true
timeout = 60

[knowledge_objects]
types = macros,savedsearches,eventtypes
savedsearches_allowlist = .*
email_actions_allowed = false
rbac_enabled = true

mode = push
dry_run = false
apps_path = ./apps
target_app = search
log_level = INFO
"""

    config_file.write_text(config_content)
    return config_file


@pytest.fixture
def mock_apps_directory(temp_dir):
    """Create a mock apps directory structure."""
    apps_dir = temp_dir / "apps"
    apps_dir.mkdir()

    # Create sample app structure
    test_app = apps_dir / "test_app" / "local"
    test_app.mkdir(parents=True)

    # Create sample conf files
    macros_conf = test_app / "macros.conf"
    macros_conf.write_text(
        """[test_macro]
definition = index=main
args = field1,field2
"""
    )

    savedsearches_conf = test_app / "savedsearches.conf"
    savedsearches_conf.write_text(
        """[Test Alert]
search = index=main | stats count
dispatch.earliest_time = -1h
dispatch.latest_time = now
"""
    )

    return apps_dir


@pytest.fixture
def mock_server_info() -> Dict[str, Any]:
    """Mock server info response."""
    return {
        "version": "8.2.0",
        "build": "12345",
        "server_name": "mock-server",
        "license_state": "OK",
        "license_labels": ["Enterprise"],
        "max_users": "100",
        "cpu_arch": "x86_64",
        "os_name": "Linux",
        "os_version": "4.15.0",
    }


@pytest.fixture
def mock_app_info() -> Dict[str, Any]:
    """Mock app info response."""
    return {
        "name": "search",
        "label": "Search & Reporting",
        "version": "8.2.0",
        "description": "The Search & Reporting app",
        "author": "Splunk",
        "visible": True,
        "configured": True,
        "access": {
            "owner": "admin",
            "app": "search",
            "sharing": "app",
            "modifiable": True,
            "removable": False,
        },
    }


@pytest.fixture
def mock_knowledge_objects_response() -> List[Dict[str, Any]]:
    """Mock knowledge objects API response."""
    return [
        {
            "name": "test_macro",
            "content": {"definition": "index=main", "args": "field1,field2"},
            "access": {
                "owner": "admin",
                "app": "search",
                "sharing": "app",
                "modifiable": True,
                "removable": True,
            },
            "metadata": {
                "eai:acl": {},
                "eai:attributes": {},
                "updated": "2023-01-01T00:00:00Z",
            },
        },
        {
            "name": "test_alert",
            "content": {
                "search": "index=main | stats count",
                "dispatch.earliest_time": "-1h",
                "dispatch.latest_time": "now",
                "cron_schedule": "0 */6 * * *",
                "is_scheduled": "1",
            },
            "access": {
                "owner": "admin",
                "app": "search",
                "sharing": "app",
                "modifiable": True,
                "removable": True,
            },
            "metadata": {
                "eai:acl": {},
                "eai:attributes": {},
                "updated": "2023-01-01T00:00:00Z",
            },
        },
    ]


@pytest.fixture
def mock_environment_variables():
    """Mock environment variables for testing."""
    env_vars = {
        "SPLUNK_HOST": "test.splunk.com",
        "SPLUNK_TOKEN": "test-token",
        "SPLUNK_APP": "test_app",
        "SAVEDSEARCHES_ALLOWLIST": "Alert.*",
        "DRY_RUN": "true",
        "DEBUG": "false",
        "LOG_LEVEL": "INFO",
    }

    # Set environment variables
    for key, value in env_vars.items():
        os.environ[key] = value

    yield env_vars

    # Clean up
    for key in env_vars.keys():
        if key in os.environ:
            del os.environ[key]


@pytest.fixture
def mock_logger():
    """Mock logger for testing."""
    logger = Mock()
    logger.debug = Mock()
    logger.info = Mock()
    logger.warning = Mock()
    logger.error = Mock()
    logger.critical = Mock()
    logger.exception = Mock()
    return logger


class MockSplunkResponse:
    """Mock Splunk API response."""

    def __init__(
        self, status_code: int = 200, content: str = "", headers: Dict[str, str] = None
    ):
        self.status_code = status_code
        self.content = content
        self.headers = headers or {}
        self.text = content

    def json(self):
        """Return JSON content."""
        import json

        return json.loads(self.content)


@pytest.fixture
def mock_splunk_response():
    """Factory for creating mock Splunk responses."""
    return MockSplunkResponse


# Test data collections
@pytest.fixture
def sample_test_data():
    """Collection of sample test data."""
    return {
        "macros": [
            {
                "name": "test_macro",
                "content": {"definition": "index=main", "args": "field1,field2"},
            },
            {
                "name": "search_macro",
                "content": {
                    "definition": "index=security | search $field$=$value$",
                    "args": "field,value",
                },
            },
        ],
        "savedsearches": [
            {
                "name": "Test Alert",
                "content": {
                    "search": "index=main | stats count",
                    "dispatch.earliest_time": "-1h",
                    "dispatch.latest_time": "now",
                    "cron_schedule": "0 */6 * * *",
                    "is_scheduled": "1",
                },
            },
            {
                "name": "Test Report",
                "content": {
                    "search": "index=main | stats count by host",
                    "dispatch.earliest_time": "-24h",
                    "dispatch.latest_time": "now",
                    "is_scheduled": "0",
                },
            },
        ],
        "eventtypes": [
            {
                "name": "test_eventtype",
                "content": {
                    "search": "index=main source=test",
                    "priority": "1",
                    "disabled": "0",
                },
            }
        ],
    }


# Utility functions for tests
def create_mock_stanza(
    name: str, content: Dict[str, Any], access: Dict[str, Any] = None
):
    """Create a mock Splunk stanza object."""
    stanza = Mock()
    stanza.name = name
    stanza.content = content

    if access is None:
        access = {
            "owner": "admin",
            "app": "search",
            "sharing": "app",
            "modifiable": True,
            "removable": True,
        }

    stanza.access = Mock()
    for key, value in access.items():
        setattr(stanza.access, key, value)

    stanza.update = Mock()
    stanza.delete = Mock()
    stanza.acl = Mock()
    stanza.acl.update = Mock()

    return stanza


def create_mock_conf(stanzas: List[Dict[str, Any]]):
    """Create a mock Splunk configuration object with stanzas."""
    conf = Mock()

    mock_stanzas = []
    for stanza_data in stanzas:
        mock_stanza = create_mock_stanza(
            stanza_data["name"], stanza_data["content"], stanza_data.get("access")
        )
        mock_stanzas.append(mock_stanza)

    conf.__iter__ = Mock(return_value=iter(mock_stanzas))
    conf.__getitem__ = Mock(
        side_effect=lambda name: next(
            (s for s in mock_stanzas if s.name == name),
            Mock(side_effect=KeyError(name)),
        )
    )
    conf.create = Mock()

    return conf
