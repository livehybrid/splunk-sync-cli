"""
Unit tests for Splunk client module.

This module tests the Splunk client connection, authentication,
and API interaction functionality.
"""

import ssl
from unittest.mock import MagicMock, Mock, patch

import pytest
from splunklib.binding import HTTPError
from splunklib.client import Service

from splunk_sync.client import SplunkClient
from splunk_sync.config import ProxyConfig, SplunkConnectionConfig
from splunk_sync.exceptions import (APIError, AuthenticationError,
                                    AuthorizationError, ConnectionError,
                                    RetryExhaustedError, SplunkSyncError)


class TestSplunkClient:
    """Test SplunkClient class."""

    def test_init_with_config(self, splunk_connection_config):
        """Test client initialization with configuration."""
        client = SplunkClient(splunk_connection_config)

        assert client.config == splunk_connection_config
        assert client.proxy_config is None
        assert client._service is None
        assert client._session_key is None
        assert isinstance(client.ssl_context, ssl.SSLContext)

    def test_init_with_proxy_config(self, splunk_connection_config, proxy_config):
        """Test client initialization with proxy configuration."""
        client = SplunkClient(splunk_connection_config, proxy_config)

        assert client.config == splunk_connection_config
        assert client.proxy_config == proxy_config

    def test_init_ssl_verification_disabled(self):
        """Test SSL verification disabled."""
        config = SplunkConnectionConfig(
            host="localhost", token="test-token", verify_ssl=False
        )

        client = SplunkClient(config)
        assert client.ssl_context.check_hostname is False
        assert client.ssl_context.verify_mode == ssl.CERT_NONE

    def test_build_connection_params_with_token(self, splunk_connection_config):
        """Test building connection parameters with token."""
        client = SplunkClient(splunk_connection_config)
        params = client._build_connection_params()

        assert params["host"] == "localhost"
        assert params["port"] == 8089
        assert params["scheme"] == "https"
        assert params["app"] == "search"
        assert params["owner"] == "admin"
        assert params["token"] == "changeme"  # Set in fixture
        assert params["timeout"] == 60
        assert "context" in params

    def test_build_connection_params_with_username_password(self):
        """Test building connection parameters with username/password."""
        config = SplunkConnectionConfig(
            host="localhost", username="admin", password="changeme"
        )

        client = SplunkClient(config)
        params = client._build_connection_params()

        assert params["username"] == "admin"
        assert params["password"] == "changeme"
        assert "token" not in params

    @patch("splunk_sync.client.connect")
    def test_connect_success(self, mock_connect, splunk_connection_config):
        """Test successful connection."""
        mock_service = Mock()
        mock_service.token = "session-token"
        mock_service.info = {"version": "8.2.0"}
        mock_connect.return_value = mock_service

        client = SplunkClient(splunk_connection_config)
        client.connect()

        assert client._service == mock_service
        assert client._session_key == "session-token"
        mock_connect.assert_called_once()

    @patch("splunk_sync.client.connect")
    def test_connect_authentication_error(self, mock_connect, splunk_connection_config):
        """Test connection with authentication error."""
        mock_connect.side_effect = HTTPError("", 401, "Unauthorized")

        client = SplunkClient(splunk_connection_config)

        with pytest.raises(AuthenticationError) as exc_info:
            client.connect()

        assert "Authentication failed" in str(exc_info.value)
        assert exc_info.value.username == "admin"

    @patch("splunk_sync.client.connect")
    def test_connect_authorization_error(self, mock_connect, splunk_connection_config):
        """Test connection with authorization error."""
        mock_connect.side_effect = HTTPError("", 403, "Forbidden")

        client = SplunkClient(splunk_connection_config)

        with pytest.raises(AuthorizationError) as exc_info:
            client.connect()

        assert "Authorization failed" in str(exc_info.value)

    @patch("splunk_sync.client.connect")
    @patch("time.sleep")
    def test_connect_retry_logic(
        self, mock_sleep, mock_connect, splunk_connection_config
    ):
        """Test connection retry logic."""
        # First two attempts fail, third succeeds
        mock_service = Mock()
        mock_service.token = "session-token"
        mock_service.info = {"version": "8.2.0"}

        mock_connect.side_effect = [
            HTTPError("", 500, "Internal Server Error"),
            HTTPError("", 500, "Internal Server Error"),
            mock_service,
        ]

        client = SplunkClient(splunk_connection_config)
        client.connect()

        assert client._service == mock_service
        assert mock_connect.call_count == 3
        assert mock_sleep.call_count == 2

    @patch("splunk_sync.client.connect")
    def test_connect_retry_exhausted(self, mock_connect, splunk_connection_config):
        """Test connection retry exhausted."""
        mock_connect.side_effect = HTTPError("", 500, "Internal Server Error")

        client = SplunkClient(splunk_connection_config)

        with pytest.raises(RetryExhaustedError) as exc_info:
            client.connect()

        assert "Failed to connect after" in str(exc_info.value)
        assert exc_info.value.attempts == 3

    def test_disconnect_success(self, splunk_connection_config):
        """Test successful disconnection."""
        client = SplunkClient(splunk_connection_config)

        mock_service = Mock()
        client._service = mock_service
        client._session_key = "session-token"

        client.disconnect()

        mock_service.logout.assert_called_once()
        assert client._service is None
        assert client._session_key is None

    def test_disconnect_with_exception(self, splunk_connection_config):
        """Test disconnection with exception."""
        client = SplunkClient(splunk_connection_config)

        mock_service = Mock()
        mock_service.logout.side_effect = Exception("Logout failed")
        client._service = mock_service

        # Should not raise exception
        client.disconnect()

        assert client._service is None
        assert client._session_key is None

    def test_context_manager(self, splunk_connection_config):
        """Test context manager functionality."""
        with patch.object(SplunkClient, "connect") as mock_connect, patch.object(
            SplunkClient, "disconnect"
        ) as mock_disconnect:

            with SplunkClient(splunk_connection_config) as client:
                assert isinstance(client, SplunkClient)

            mock_connect.assert_called_once()
            mock_disconnect.assert_called_once()

    def test_service_property_connected(self, splunk_connection_config):
        """Test service property when connected."""
        client = SplunkClient(splunk_connection_config)
        mock_service = Mock()
        client._service = mock_service

        assert client.service == mock_service

    def test_service_property_not_connected(self, splunk_connection_config):
        """Test service property when not connected."""
        client = SplunkClient(splunk_connection_config)

        with pytest.raises(SplunkSyncError, match="Not connected to Splunk"):
            client.service

    def test_get_app_info_success(self, splunk_connection_config):
        """Test getting app info successfully."""
        client = SplunkClient(splunk_connection_config)

        mock_app = Mock()
        mock_app.name = "search"
        mock_app.content = {
            "label": "Search & Reporting",
            "version": "8.2.0",
            "description": "Search app",
        }
        mock_app.access = Mock()
        mock_app.access.owner = "admin"
        mock_app.access.app = "search"
        mock_app.access.sharing = "app"
        mock_app.access.modifiable = True
        mock_app.access.removable = False

        mock_service = Mock()
        mock_service.apps = {"search": mock_app}
        client._service = mock_service

        info = client.get_app_info("search")

        assert info["name"] == "search"
        assert info["label"] == "Search & Reporting"
        assert info["version"] == "8.2.0"
        assert info["access"]["owner"] == "admin"

    def test_get_app_info_not_found(self, splunk_connection_config):
        """Test getting info for non-existent app."""
        client = SplunkClient(splunk_connection_config)

        mock_service = Mock()
        mock_service.apps = {}
        client._service = mock_service

        with pytest.raises(SplunkSyncError, match="App 'nonexistent' not found"):
            client.get_app_info("nonexistent")

    def test_list_knowledge_objects_success(self, splunk_connection_config):
        """Test listing knowledge objects successfully."""
        client = SplunkClient(splunk_connection_config)

        mock_stanza = Mock()
        mock_stanza.name = "test_macro"
        mock_stanza.content = {"definition": "index=main"}
        mock_stanza.access = Mock()
        mock_stanza.access.owner = "admin"
        mock_stanza.access.app = "search"
        mock_stanza.access.sharing = "app"
        mock_stanza.access.modifiable = True
        mock_stanza.access.removable = True

        mock_conf = Mock()
        mock_conf.__iter__ = Mock(return_value=iter([mock_stanza]))

        mock_service = Mock()
        mock_service.confs = {"macros": mock_conf}
        mock_service.namespace = Mock()
        client._service = mock_service

        objects = client.list_knowledge_objects("macros")

        assert len(objects) == 1
        assert objects[0]["name"] == "test_macro"
        assert objects[0]["content"] == {"definition": "index=main"}
        assert objects[0]["access"]["owner"] == "admin"

    def test_list_knowledge_objects_with_app_context(self, splunk_connection_config):
        """Test listing knowledge objects with app context."""
        client = SplunkClient(splunk_connection_config)

        mock_conf = Mock()
        mock_conf.__iter__ = Mock(return_value=iter([]))

        mock_service = Mock()
        mock_service.confs = {"macros": mock_conf}
        mock_service.namespace = Mock()
        client._service = mock_service

        client.list_knowledge_objects("macros", app="test_app", owner="test_user")

        assert mock_service.namespace.app == "test_app"
        assert mock_service.namespace.owner == "test_user"

    def test_list_knowledge_objects_not_found(self, splunk_connection_config):
        """Test listing non-existent knowledge object type."""
        client = SplunkClient(splunk_connection_config)

        mock_service = Mock()
        mock_service.confs = {}
        client._service = mock_service

        with pytest.raises(
            SplunkSyncError, match="Knowledge object type 'nonexistent' not found"
        ):
            client.list_knowledge_objects("nonexistent")

    def test_get_knowledge_object_success(self, splunk_connection_config):
        """Test getting specific knowledge object successfully."""
        client = SplunkClient(splunk_connection_config)

        mock_stanza = Mock()
        mock_stanza.name = "test_macro"
        mock_stanza.content = {"definition": "index=main"}
        mock_stanza.access = Mock()
        mock_stanza.access.owner = "admin"
        mock_stanza.access.app = "search"
        mock_stanza.access.sharing = "app"
        mock_stanza.access.modifiable = True
        mock_stanza.access.removable = True

        mock_conf = Mock()
        mock_conf.__getitem__ = Mock(return_value=mock_stanza)

        mock_service = Mock()
        mock_service.confs = {"macros": mock_conf}
        mock_service.namespace = Mock()
        client._service = mock_service

        obj = client.get_knowledge_object("macros", "test_macro")

        assert obj["name"] == "test_macro"
        assert obj["content"] == {"definition": "index=main"}
        assert obj["access"]["owner"] == "admin"

    def test_get_knowledge_object_not_found(self, splunk_connection_config):
        """Test getting non-existent knowledge object."""
        client = SplunkClient(splunk_connection_config)

        mock_conf = Mock()
        mock_conf.__getitem__ = Mock(side_effect=KeyError("test_macro"))

        mock_service = Mock()
        mock_service.confs = {"macros": mock_conf}
        client._service = mock_service

        with pytest.raises(
            SplunkSyncError, match="Knowledge object 'test_macro' not found"
        ):
            client.get_knowledge_object("macros", "test_macro")

    def test_create_knowledge_object_success(self, splunk_connection_config):
        """Test creating knowledge object successfully."""
        client = SplunkClient(splunk_connection_config)

        mock_stanza = Mock()
        mock_conf = Mock()
        mock_conf.create = Mock(return_value=mock_stanza)

        mock_service = Mock()
        mock_service.confs = {"macros": mock_conf}
        mock_service.namespace = Mock()
        client._service = mock_service

        content = {"definition": "index=main"}
        client.create_knowledge_object("macros", "test_macro", content)

        mock_conf.create.assert_called_once_with("test_macro", **content)

    def test_create_knowledge_object_with_app(self, splunk_connection_config):
        """Test creating knowledge object with app context."""
        client = SplunkClient(splunk_connection_config)

        mock_conf = Mock()
        mock_conf.create = Mock()

        mock_service = Mock()
        mock_service.confs = {"macros": mock_conf}
        mock_service.namespace = Mock()
        client._service = mock_service

        content = {"definition": "index=main"}
        client.create_knowledge_object("macros", "test_macro", content, app="test_app")

        assert mock_service.namespace.app == "test_app"
        mock_conf.create.assert_called_once_with("test_macro", **content)

    def test_create_knowledge_object_failure(self, splunk_connection_config):
        """Test creating knowledge object with failure."""
        client = SplunkClient(splunk_connection_config)

        mock_conf = Mock()
        mock_conf.create = Mock(side_effect=Exception("Creation failed"))

        mock_service = Mock()
        mock_service.confs = {"macros": mock_conf}
        client._service = mock_service

        with pytest.raises(APIError, match="Failed to create macros/test_macro"):
            client.create_knowledge_object("macros", "test_macro", {})

    def test_update_knowledge_object_success(self, splunk_connection_config):
        """Test updating knowledge object successfully."""
        client = SplunkClient(splunk_connection_config)

        mock_stanza = Mock()
        mock_stanza.update = Mock()

        mock_conf = Mock()
        mock_conf.__getitem__ = Mock(return_value=mock_stanza)

        mock_service = Mock()
        mock_service.confs = {"macros": mock_conf}
        mock_service.namespace = Mock()
        client._service = mock_service

        content = {"definition": "index=security"}
        client.update_knowledge_object("macros", "test_macro", content)

        mock_stanza.update.assert_called_once_with(**content)

    def test_update_knowledge_object_not_found(self, splunk_connection_config):
        """Test updating non-existent knowledge object."""
        client = SplunkClient(splunk_connection_config)

        mock_conf = Mock()
        mock_conf.__getitem__ = Mock(side_effect=KeyError("test_macro"))

        mock_service = Mock()
        mock_service.confs = {"macros": mock_conf}
        client._service = mock_service

        with pytest.raises(
            SplunkSyncError, match="Knowledge object 'test_macro' not found"
        ):
            client.update_knowledge_object("macros", "test_macro", {})

    def test_delete_knowledge_object_success(self, splunk_connection_config):
        """Test deleting knowledge object successfully."""
        client = SplunkClient(splunk_connection_config)

        mock_stanza = Mock()
        mock_stanza.delete = Mock()

        mock_conf = Mock()
        mock_conf.__getitem__ = Mock(return_value=mock_stanza)

        mock_service = Mock()
        mock_service.confs = {"macros": mock_conf}
        mock_service.namespace = Mock()
        client._service = mock_service

        client.delete_knowledge_object("macros", "test_macro")

        mock_stanza.delete.assert_called_once()

    def test_delete_knowledge_object_not_found(self, splunk_connection_config):
        """Test deleting non-existent knowledge object."""
        client = SplunkClient(splunk_connection_config)

        mock_conf = Mock()
        mock_conf.__getitem__ = Mock(side_effect=KeyError("test_macro"))

        mock_service = Mock()
        mock_service.confs = {"macros": mock_conf}
        client._service = mock_service

        with pytest.raises(
            SplunkSyncError, match="Knowledge object 'test_macro' not found"
        ):
            client.delete_knowledge_object("macros", "test_macro")

    def test_update_object_permissions_success(self, splunk_connection_config):
        """Test updating object permissions successfully."""
        client = SplunkClient(splunk_connection_config)

        mock_acl = Mock()
        mock_acl.update = Mock()

        mock_stanza = Mock()
        mock_stanza.access = Mock()
        mock_stanza.access.owner = "admin"
        mock_stanza.access.sharing = "app"
        mock_stanza.acl = mock_acl

        mock_conf = Mock()
        mock_conf.__getitem__ = Mock(return_value=mock_stanza)

        mock_service = Mock()
        mock_service.confs = {"macros": mock_conf}
        mock_service.namespace = Mock()
        client._service = mock_service

        permissions = {
            "owner": "newowner",
            "sharing": "global",
            "read": "*",
            "write": "admin",
        }

        client.update_object_permissions("macros", "test_macro", permissions)

        mock_acl.update.assert_called_once()
        call_args = mock_acl.update.call_args[1]
        assert call_args["owner"] == "newowner"
        assert call_args["sharing"] == "global"
        assert call_args["perms.read"] == "*"
        assert call_args["perms.write"] == "admin"

    def test_update_object_permissions_with_roles(self, splunk_connection_config):
        """Test updating object permissions with roles."""
        client = SplunkClient(splunk_connection_config)

        mock_acl = Mock()
        mock_acl.update = Mock()

        mock_stanza = Mock()
        mock_stanza.access = Mock()
        mock_stanza.access.owner = "admin"
        mock_stanza.access.sharing = "app"
        mock_stanza.acl = mock_acl

        mock_conf = Mock()
        mock_conf.__getitem__ = Mock(return_value=mock_stanza)

        mock_service = Mock()
        mock_service.confs = {"macros": mock_conf}
        mock_service.namespace = Mock()
        client._service = mock_service

        permissions = {"roles": ["role1", "role2"]}

        client.update_object_permissions("macros", "test_macro", permissions)

        mock_acl.update.assert_called_once()
        call_args = mock_acl.update.call_args[1]
        assert "perms.role1" in call_args
        assert "perms.role2" in call_args

    def test_test_connection_success(self, splunk_connection_config):
        """Test connection test success."""
        client = SplunkClient(splunk_connection_config)

        with patch.object(client, "connect") as mock_connect, patch.object(
            client, "disconnect"
        ) as mock_disconnect:

            mock_service = Mock()
            mock_service.info = {"version": "8.2.0"}
            client._service = mock_service

            result = client.test_connection()

            assert result is True
            mock_connect.assert_called_once()
            mock_disconnect.assert_called_once()

    def test_test_connection_failure(self, splunk_connection_config):
        """Test connection test failure."""
        client = SplunkClient(splunk_connection_config)

        with patch.object(
            client, "connect", side_effect=Exception("Connection failed")
        ), patch.object(client, "disconnect") as mock_disconnect:

            result = client.test_connection()

            assert result is False
            mock_disconnect.assert_called_once()

    def test_get_server_info_success(self, splunk_connection_config):
        """Test getting server info successfully."""
        client = SplunkClient(splunk_connection_config)

        mock_service = Mock()
        mock_service.info = {
            "version": "8.2.0",
            "build": "12345",
            "server_name": "test-server",
            "license_state": "OK",
        }
        client._service = mock_service

        info = client.get_server_info()

        assert info["version"] == "8.2.0"
        assert info["build"] == "12345"
        assert info["server_name"] == "test-server"
        assert info["license_state"] == "OK"

    def test_get_server_info_failure(self, splunk_connection_config):
        """Test getting server info with failure."""
        client = SplunkClient(splunk_connection_config)

        mock_service = Mock()
        mock_service.info = Mock(side_effect=Exception("Info failed"))
        client._service = mock_service

        with pytest.raises(APIError, match="Failed to get server info"):
            client.get_server_info()


class TestSplunkClientIntegration:
    """Integration tests for SplunkClient."""

    @patch("splunk_sync.client.connect")
    def test_full_workflow(self, mock_connect, splunk_connection_config):
        """Test full client workflow."""
        # Mock service setup
        mock_service = Mock()
        mock_service.token = "session-token"
        mock_service.info = {"version": "8.2.0"}

        # Mock app
        mock_app = Mock()
        mock_app.name = "search"
        mock_app.content = {"label": "Search"}
        mock_app.access = Mock()
        mock_app.access.owner = "admin"
        mock_service.apps = {"search": mock_app}

        # Mock knowledge objects
        mock_stanza = Mock()
        mock_stanza.name = "test_macro"
        mock_stanza.content = {"definition": "index=main"}
        mock_stanza.access = Mock()
        mock_stanza.access.owner = "admin"
        mock_stanza.access.app = "search"
        mock_stanza.access.sharing = "app"
        mock_stanza.access.modifiable = True
        mock_stanza.access.removable = True
        mock_stanza.update = Mock()
        mock_stanza.delete = Mock()

        mock_conf = Mock()
        mock_conf.__iter__ = Mock(return_value=iter([mock_stanza]))
        mock_conf.__getitem__ = Mock(return_value=mock_stanza)
        mock_conf.create = Mock(return_value=mock_stanza)

        mock_service.confs = {"macros": mock_conf}
        mock_service.namespace = Mock()
        mock_connect.return_value = mock_service

        # Test workflow
        with SplunkClient(splunk_connection_config) as client:
            # Test app info
            app_info = client.get_app_info("search")
            assert app_info["name"] == "search"

            # Test list objects
            objects = client.list_knowledge_objects("macros")
            assert len(objects) == 1
            assert objects[0]["name"] == "test_macro"

            # Test get object
            obj = client.get_knowledge_object("macros", "test_macro")
            assert obj["name"] == "test_macro"

            # Test create object
            client.create_knowledge_object(
                "macros", "new_macro", {"definition": "index=new"}
            )
            mock_conf.create.assert_called_once()

            # Test update object
            client.update_knowledge_object(
                "macros", "test_macro", {"definition": "index=updated"}
            )
            mock_stanza.update.assert_called_once()

            # Test delete object
            client.delete_knowledge_object("macros", "test_macro")
            mock_stanza.delete.assert_called_once()

            # Test server info
            server_info = client.get_server_info()
            assert server_info["version"] == "8.2.0"

        # Verify connect and disconnect were called
        mock_connect.assert_called_once()
        mock_service.logout.assert_called_once()
