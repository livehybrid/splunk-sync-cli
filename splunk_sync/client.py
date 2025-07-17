"""
Splunk client for handling API connections and operations.

This module provides a modern, robust client for interacting with Splunk
servers through REST API calls with proper error handling and retry logic.
"""

import logging
import ssl
import time
from typing import Any, Dict, List, Optional

import splunklib.binding as binding  # type: ignore[import]
from splunklib.client import Service, connect  # type: ignore[import]

from .config import ProxyConfig, SplunkConnectionConfig
from .exceptions import (APIError, AuthenticationError, AuthorizationError,
                         HTTPError, RetryExhaustedError, SplunkSyncError)

SplunklibHTTPError = binding.HTTPError

logger = logging.getLogger(__name__)


class SplunkClient:
    """Modern Splunk client with enhanced error handling and retry logic."""

    def __init__(
        self, config: SplunkConnectionConfig, proxy_config: Optional[ProxyConfig] = None
    ):
        """Initialize Splunk client with configuration."""
        self.config = config
        self.proxy_config = proxy_config
        self._service: Optional[Service] = None
        self._session_key: Optional[str] = None

        # Create SSL context
        self.ssl_context = ssl.create_default_context()
        if not config.verify_ssl:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
            logger.warning("SSL verification disabled - not recommended for production")

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()

    def connect(self) -> None:
        """Establish connection to Splunk server."""
        if self._service is not None:
            return

        connection_params = self._build_connection_params()

        for attempt in range(self.config.retry_count + 1):
            try:
                logger.info(
                    f"Connecting to Splunk at {self.config.base_url} (attempt {attempt + 1})"
                )

                self._service = connect(**connection_params)

                # Verify connection by getting server info
                server_info = self._service.info
                logger.info(
                    f"Connected to Splunk {server_info.get('version', 'unknown version')}"
                )

                # Store session key for custom operations
                self._session_key = self._service.token

                return

            except (HTTPError, SplunklibHTTPError) as e:
                if e.status == 401:
                    raise AuthenticationError(
                        "Authentication failed - check credentials",
                        username=self.config.username,
                        context={"status_code": e.status, "message": str(e)},
                    )
                elif e.status == 403:
                    raise AuthorizationError(
                        "Authorization failed - insufficient permissions",
                        context={"status_code": e.status, "message": str(e)},
                    )
                else:
                    error_msg = f"HTTP error during connection: {e.status}"
                    if attempt < self.config.retry_count:
                        logger.warning(
                            f"{error_msg}, retrying in {self.config.retry_delay}s..."
                        )
                        time.sleep(self.config.retry_delay)
                        continue
                    raise RetryExhaustedError(
                        f"Failed to connect after {self.config.retry_count + 1} attempts",
                        attempts=self.config.retry_count + 1,
                        last_error=e,
                        context={"status_code": e.status, "message": str(e)},
                    )

            except Exception as e:
                error_msg = f"Failed to connect to Splunk: {str(e)}"
                if attempt < self.config.retry_count:
                    logger.warning(
                        f"{error_msg}, retrying in {self.config.retry_delay}s..."
                    )
                    time.sleep(self.config.retry_delay)
                    continue

                raise RetryExhaustedError(
                    f"Failed to connect after {self.config.retry_count + 1} attempts",
                    attempts=self.config.retry_count + 1,
                    last_error=e,
                    context={"original_error": str(e)},
                )

        raise RetryExhaustedError(
            f"Failed to connect after {self.config.retry_count + 1} attempts",
            attempts=self.config.retry_count + 1,
            last_error=Exception("Connection failed"),
        )

    def disconnect(self) -> None:
        """Disconnect from Splunk server."""
        if self._service is not None:
            try:
                self._service.logout()
            except Exception as e:
                logger.warning(f"Error during logout: {e}")
            finally:
                self._service = None
                self._session_key = None
                logger.info("Disconnected from Splunk")

    def _build_connection_params(self) -> Dict[str, Any]:
        """Build connection parameters for Splunk SDK."""
        params = {
            "host": self.config.host,
            "port": self.config.port,
            "scheme": self.config.scheme,
            "app": self.config.app,
            "owner": self.config.owner,
            "timeout": self.config.timeout,
            "context": self.ssl_context,
        }

        # Authentication
        if self.config.token:
            params["token"] = self.config.token
        else:
            params["username"] = self.config.username
            params["password"] = self.config.password

        # Proxy configuration
        if self.proxy_config and self.proxy_config.enabled:
            params["handler"] = self._create_proxy_handler()

        return params

    def _create_proxy_handler(self):
        """Create proxy handler for requests."""
        # This would typically integrate with urllib3 or requests
        # For now, we'll use a simple approach
        logger.info(f"Using proxy: {self.proxy_config.host}:{self.proxy_config.port}")
        return None  # Placeholder for actual proxy implementation

    @property
    def service(self) -> Service:
        """Get the underlying Splunk service object."""
        if self._service is None:
            raise SplunkSyncError("Not connected to Splunk. Call connect() first.")
        return self._service

    def get_app_info(self, app_name: str) -> Dict[str, Any]:
        """Get information about a specific app."""
        try:
            app = self.service.apps[app_name]
            return {
                "name": app.name,
                "label": app.content.get("label", app.name),
                "version": app.content.get("version", "unknown"),
                "description": app.content.get("description", ""),
                "author": app.content.get("author", ""),
                "visible": app.content.get("visible", True),
                "configured": app.content.get("configured", False),
                "state_change_requires_restart": app.content.get(
                    "state_change_requires_restart", False
                ),
                "access": {
                    "owner": app.access.owner,
                    "app": app.access.app,
                    "sharing": app.access.sharing,
                    "modifiable": app.access.modifiable,
                    "removable": app.access.removable,
                },
            }
        except KeyError:
            raise SplunkSyncError(f"App '{app_name}' not found")

    def list_knowledge_objects(
        self, ko_type: str, app: Optional[str] = None, owner: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List knowledge objects of a specific type."""
        try:
            if app:
                # Set app context
                self.service.namespace.app = app
            if owner:
                self.service.namespace.owner = owner

            conf = self.service.confs[ko_type]
            objects = []

            for stanza in conf:
                obj_info = {
                    "name": stanza.name,
                    "content": dict(stanza.content),
                    "access": {
                        "owner": stanza.access.owner,
                        "app": stanza.access.app,
                        "sharing": stanza.access.sharing,
                        "modifiable": stanza.access.modifiable,
                        "removable": stanza.access.removable,
                    },
                    "metadata": {
                        "eai:acl": getattr(stanza, "eai:acl", {}),
                        "eai:attributes": getattr(stanza, "eai:attributes", {}),
                        "updated": getattr(stanza, "updated", None),
                    },
                }
                objects.append(obj_info)

            return objects

        except KeyError as e:
            raise SplunkSyncError(f"Knowledge object type '{ko_type}' not found: {e}")
        except Exception as e:
            raise APIError(
                f"Failed to list {ko_type} objects: {e}",
                status_code=0,
                endpoint=f"/servicesNS/-/-/configs/conf-{ko_type}",
            )

    def get_knowledge_object(
        self, ko_type: str, stanza_name: str, app: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get a specific knowledge object."""
        try:
            if app:
                self.service.namespace.app = app

            conf = self.service.confs[ko_type]
            stanza = conf[stanza_name]

            return {
                "name": stanza.name,
                "content": dict(stanza.content),
                "access": {
                    "owner": stanza.access.owner,
                    "app": stanza.access.app,
                    "sharing": stanza.access.sharing,
                    "modifiable": stanza.access.modifiable,
                    "removable": stanza.access.removable,
                },
                "metadata": {
                    "eai:acl": getattr(stanza, "eai:acl", {}),
                    "eai:attributes": getattr(stanza, "eai:attributes", {}),
                    "updated": getattr(stanza, "updated", None),
                },
            }

        except KeyError:
            raise SplunkSyncError(
                f"Knowledge object '{stanza_name}' not found in {ko_type}"
            )
        except Exception as e:
            raise APIError(
                f"Failed to get {ko_type}/{stanza_name}: {e}",
                status_code=0,
                endpoint=f"/servicesNS/-/-/configs/conf-{ko_type}/{stanza_name}",
            )

    def create_knowledge_object(
        self,
        ko_type: str,
        stanza_name: str,
        content: Dict[str, Any],
        app: Optional[str] = None,
    ) -> None:
        """Create a new knowledge object."""
        try:
            if app:
                self.service.namespace.app = app

            conf = self.service.confs[ko_type]
            conf.create(stanza_name, **content)

            logger.info(f"Created {ko_type}/{stanza_name}")

        except Exception as e:
            raise APIError(
                f"Failed to create {ko_type}/{stanza_name}: {e}",
                status_code=0,
                endpoint=f"/servicesNS/-/-/configs/conf-{ko_type}",
            )

    def update_knowledge_object(
        self,
        ko_type: str,
        stanza_name: str,
        content: Dict[str, Any],
        app: Optional[str] = None,
    ) -> None:
        """Update an existing knowledge object."""
        try:
            if app:
                self.service.namespace.app = app

            conf = self.service.confs[ko_type]
            stanza = conf[stanza_name]
            stanza.update(**content)

            logger.info(f"Updated {ko_type}/{stanza_name}")

        except KeyError:
            raise SplunkSyncError(
                f"Knowledge object '{stanza_name}' not found in {ko_type}"
            )
        except Exception as e:
            raise APIError(
                f"Failed to update {ko_type}/{stanza_name}: {e}",
                status_code=0,
                endpoint=f"/servicesNS/-/-/configs/conf-{ko_type}/{stanza_name}",
            )

    def delete_knowledge_object(
        self, ko_type: str, stanza_name: str, app: Optional[str] = None
    ) -> None:
        """Delete a knowledge object."""
        try:
            if app:
                self.service.namespace.app = app

            conf = self.service.confs[ko_type]
            stanza = conf[stanza_name]
            stanza.delete()

            logger.info(f"Deleted {ko_type}/{stanza_name}")

        except KeyError:
            raise SplunkSyncError(
                f"Knowledge object '{stanza_name}' not found in {ko_type}"
            )
        except Exception as e:
            raise APIError(
                f"Failed to delete {ko_type}/{stanza_name}: {e}",
                status_code=0,
                endpoint=f"/servicesNS/-/-/configs/conf-{ko_type}/{stanza_name}",
            )

    def update_object_permissions(
        self,
        ko_type: str,
        stanza_name: str,
        permissions: Dict[str, Any],
        app: Optional[str] = None,
    ) -> None:
        """Update permissions for a knowledge object."""
        try:
            if app:
                self.service.namespace.app = app

            conf = self.service.confs[ko_type]
            stanza = conf[stanza_name]

            # Update ACL
            acl_data = {
                "owner": permissions.get("owner", stanza.access.owner),
                "sharing": permissions.get("sharing", stanza.access.sharing),
                "perms.read": permissions.get("read", "*"),
                "perms.write": permissions.get("write", "*"),
            }

            # Add role-specific permissions
            if "roles" in permissions:
                for role in permissions["roles"]:
                    acl_data[f"perms.{role}"] = "read"

            stanza.acl.update(**acl_data)

            logger.info(f"Updated permissions for {ko_type}/{stanza_name}")

        except KeyError:
            raise SplunkSyncError(
                f"Knowledge object '{stanza_name}' not found in {ko_type}"
            )
        except Exception as e:
            raise APIError(
                f"Failed to update permissions for {ko_type}/{stanza_name}: {e}",
                status_code=0,
                endpoint=f"/servicesNS/-/-/configs/conf-{ko_type}/{stanza_name}/acl",
            )

    def test_connection(self) -> bool:
        """Test connection to Splunk server."""
        try:
            self.connect()
            server_info = self.service.info
            logger.info(
                f"Connection test successful: {server_info.get('version', 'unknown')}"
            )
            return True
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False
        finally:
            self.disconnect()

    def get_server_info(self) -> Dict[str, Any]:
        """Get server information."""
        try:
            info = self.service.info
            return {
                "version": info.get("version", "unknown"),
                "build": info.get("build", "unknown"),
                "server_name": info.get("server_name", "unknown"),
                "license_state": info.get("license_state", "unknown"),
                "license_labels": info.get("license_labels", []),
                "max_users": info.get("max_users", "unknown"),
                "cpu_arch": info.get("cpu_arch", "unknown"),
                "os_name": info.get("os_name", "unknown"),
                "os_version": info.get("os_version", "unknown"),
            }
        except Exception as e:
            raise APIError(
                f"Failed to get server info: {e}",
                status_code=0,
                endpoint="/services/server/info",
            )
