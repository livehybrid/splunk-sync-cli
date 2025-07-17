"""
Custom exceptions for Splunk synchronization operations.

This module defines a hierarchy of exceptions that provide detailed
error information for different failure scenarios.
"""

from typing import Any, Dict, Optional


class SplunkSyncError(Exception):
    """Base exception for all Splunk sync operations."""

    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        """Initialize with message and optional context."""
        super().__init__(message)
        self.context = context or {}

    def __str__(self) -> str:
        """String representation including context if available."""
        base_msg = super().__str__()
        if self.context:
            context_str = ", ".join(f"{k}={v}" for k, v in self.context.items())
            return f"{base_msg} (Context: {context_str})"
        return base_msg


class ConfigurationError(SplunkSyncError):
    """Raised when configuration is invalid or missing."""

    pass


class ConnectionError(SplunkSyncError):
    """Raised when unable to connect to Splunk server."""

    def __init__(
        self,
        message: str,
        host: str,
        port: int,
        context: Optional[Dict[str, Any]] = None,
    ):
        """Initialize with connection details."""
        super().__init__(message, context)
        self.host = host
        self.port = port


class AuthenticationError(SplunkSyncError):
    """Raised when authentication fails."""

    def __init__(
        self,
        message: str,
        username: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ):
        """Initialize with authentication details."""
        super().__init__(message, context)
        self.username = username


class AuthorizationError(SplunkSyncError):
    """Raised when user lacks required permissions."""

    def __init__(
        self,
        message: str,
        required_permission: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ):
        """Initialize with permission details."""
        super().__init__(message, context)
        self.required_permission = required_permission


class KnowledgeObjectError(SplunkSyncError):
    """Base exception for knowledge object operations."""

    def __init__(
        self,
        message: str,
        ko_type: str,
        stanza_name: str,
        context: Optional[Dict[str, Any]] = None,
    ):
        """Initialize with knowledge object details."""
        super().__init__(message, context)
        self.ko_type = ko_type
        self.stanza_name = stanza_name


class ValidationError(KnowledgeObjectError):
    """Raised when knowledge object validation fails."""

    def __init__(
        self,
        message: str,
        ko_type: str,
        stanza_name: str,
        field: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ):
        """Initialize with validation details."""
        super().__init__(message, ko_type, stanza_name, context)
        self.field = field


class SyncConflictError(KnowledgeObjectError):
    """Raised when there's a conflict during synchronization."""

    def __init__(
        self,
        message: str,
        ko_type: str,
        stanza_name: str,
        local_value: Any,
        remote_value: Any,
        context: Optional[Dict[str, Any]] = None,
    ):
        """Initialize with conflict details."""
        super().__init__(message, ko_type, stanza_name, context)
        self.local_value = local_value
        self.remote_value = remote_value


class PermissionError(KnowledgeObjectError):
    """Raised when RBAC permission operations fail."""

    def __init__(
        self,
        message: str,
        ko_type: str,
        stanza_name: str,
        permission_type: str,
        context: Optional[Dict[str, Any]] = None,
    ):
        """Initialize with permission details."""
        super().__init__(message, ko_type, stanza_name, context)
        self.permission_type = permission_type


class APIError(SplunkSyncError):
    """Raised when Splunk API calls fail."""

    def __init__(
        self,
        message: str,
        status_code: int,
        endpoint: str,
        context: Optional[Dict[str, Any]] = None,
    ):
        """Initialize with API error details."""
        super().__init__(message, context)
        self.status_code = status_code
        self.endpoint = endpoint


class RetryExhaustedError(SplunkSyncError):
    """Raised when retry attempts are exhausted."""

    def __init__(
        self,
        message: str,
        attempts: int,
        last_error: Exception,
        context: Optional[Dict[str, Any]] = None,
    ):
        """Initialize with retry details."""
        super().__init__(message, context)
        self.attempts = attempts
        self.last_error = last_error


class FileOperationError(SplunkSyncError):
    """Raised when file operations fail."""

    def __init__(
        self,
        message: str,
        file_path: str,
        operation: str,
        context: Optional[Dict[str, Any]] = None,
    ):
        """Initialize with file operation details."""
        super().__init__(message, context)
        self.file_path = file_path
        self.operation = operation


class FilterError(SplunkSyncError):
    """Raised when filtering operations fail."""

    def __init__(
        self,
        message: str,
        filter_pattern: str,
        context: Optional[Dict[str, Any]] = None,
    ):
        """Initialize with filter details."""
        super().__init__(message, context)
        self.filter_pattern = filter_pattern


class HTTPError(SplunkSyncError):
    """Custom HTTPError for testing and compatibility with splunklib.binding.HTTPError."""

    def __init__(self, *args, **kwargs):
        if len(args) >= 3:
            message, status, reason = args[:3]
            super().__init__(message)
            self.status = status
            self.reason = reason
        elif len(args) == 2:
            message, response = args
            super().__init__(message)
            self.status = getattr(response, "status", None)
            self.reason = getattr(response, "reason", None)
        elif len(args) == 1:
            super().__init__(args[0])
            self.status = None
            self.reason = None
        else:
            super().__init__("HTTPError")
            self.status = None
            self.reason = None
