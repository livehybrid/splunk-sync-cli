"""
Logging configuration and utilities for Splunk synchronization.

This module provides a comprehensive logging system with structured logging,
multiple handlers, and proper formatting for operational visibility.
"""

import json
import logging
import logging.config
import logging.handlers
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


class StructuredFormatter(logging.Formatter):
    """Custom formatter that outputs structured JSON logs."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON."""
        # Base log data
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add thread info if available
        if record.thread:
            log_data["thread"] = record.thread

        # Add process info
        log_data["process"] = record.process

        # Add exception info if present
        if record.exc_info:
            exc_type = record.exc_info[0]
            log_data["exception"] = {
                "type": exc_type.__name__ if exc_type else "Unknown",
                "message": str(record.exc_info[1]),
                "traceback": traceback.format_exception(*record.exc_info),
            }

        # Add custom fields from extra
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)

        # Add operation context if available
        if hasattr(record, "operation"):
            log_data["operation"] = record.operation

        if hasattr(record, "ko_type"):
            log_data["ko_type"] = record.ko_type

        if hasattr(record, "stanza_name"):
            log_data["stanza_name"] = record.stanza_name

        return json.dumps(log_data)


class ColoredConsoleFormatter(logging.Formatter):
    """Colored console formatter for better readability."""

    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
        "RESET": "\033[0m",  # Reset
    }

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors."""
        color = self.COLORS.get(record.levelname, self.COLORS["RESET"])
        reset = self.COLORS["RESET"]

        # Format timestamp
        timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")

        # Create base message
        base_msg = (
            f"{color}[{timestamp}] {record.levelname:<8}{reset} "
            f"{record.name}: {record.getMessage()}"
        )

        # Add context if available
        context_parts = []
        if hasattr(record, "ko_type") and record.ko_type:
            context_parts.append(f"type={record.ko_type}")

        if hasattr(record, "stanza_name") and record.stanza_name:
            context_parts.append(f"stanza={record.stanza_name}")

        if hasattr(record, "operation") and record.operation:
            context_parts.append(f"op={record.operation}")

        if context_parts:
            base_msg += f" ({', '.join(context_parts)})"

        # Add exception info if present
        if record.exc_info:
            base_msg += f"\n{self.formatException(record.exc_info)}"

        return base_msg


class SplunkSyncLogger:
    """Enhanced logger with context management for Splunk sync operations."""

    def __init__(self, logger: logging.Logger):
        """Initialize with base logger."""
        self.logger = logger
        self.context: dict = {}

    def set_context(self, **kwargs):
        """Set context for all subsequent log messages."""
        self.context.update(kwargs)

    def clear_context(self):
        """Clear logging context."""
        self.context.clear()

    def _add_context(self, extra: Optional[dict] = None) -> dict:
        """Add context to log message."""
        log_extra = self.context.copy()
        if extra:
            log_extra.update(extra)
        return log_extra

    def debug(self, message: str, **kwargs):
        """Log debug message with context."""
        self.logger.debug(message, extra=self._add_context(kwargs))

    def info(self, message: str, **kwargs):
        """Log info message with context."""
        self.logger.info(message, extra=self._add_context(kwargs))

    def warning(self, message: str, **kwargs):
        """Log warning message with context."""
        self.logger.warning(message, extra=self._add_context(kwargs))

    def error(self, message: str, **kwargs):
        """Log error message with context."""
        self.logger.error(message, extra=self._add_context(kwargs))

    def critical(self, message: str, **kwargs):
        """Log critical message with context."""
        self.logger.critical(message, extra=self._add_context(kwargs))

    def exception(self, message: str, **kwargs):
        """Log exception with context."""
        self.logger.exception(message, extra=self._add_context(kwargs))

    def operation_start(self, operation: str, **kwargs):
        """Log operation start."""
        self.info(f"Starting {operation}", operation=operation, **kwargs)

    def operation_end(self, operation: str, success: bool = True, **kwargs):
        """Log operation end."""
        status = "completed" if success else "failed"
        level = self.info if success else self.error
        level(
            f"Operation {operation} {status}",
            operation=operation,
            success=success,
            **kwargs,
        )

    def ko_operation(
        self, operation: str, ko_type: str, stanza_name: str, message: str, **kwargs
    ):
        """Log knowledge object operation."""
        self.info(
            message,
            operation=operation,
            ko_type=ko_type,
            stanza_name=stanza_name,
            **kwargs,
        )

    def sync_stats(self, stats: dict):
        """Log synchronization statistics."""
        self.info("Synchronization statistics", operation="sync_stats", **stats)


class LoggingManager:
    """Manages logging configuration and setup."""

    def __init__(self):
        """Initialize logging manager."""
        self.configured = False
        self.loggers: dict = {}

    def configure_logging(
        self,
        level: str = "INFO",
        log_file: Optional[str] = None,
        structured: bool = False,
        debug: bool = False,
        max_bytes: int = 10485760,  # 10MB
        backup_count: int = 5,
    ) -> None:
        """Configure logging with specified options."""

        # Convert level string to logging level
        log_level = getattr(logging, level.upper(), logging.INFO)

        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)

        # Clear existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)

        if structured:
            console_formatter: logging.Formatter = StructuredFormatter()
        else:
            console_formatter = ColoredConsoleFormatter()

        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

        # File handler if specified
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=max_bytes, backupCount=backup_count
            )
            file_handler.setLevel(log_level)

            # Always use structured format for file logs
            file_formatter = StructuredFormatter()
            file_handler.setFormatter(file_formatter)
            root_logger.addHandler(file_handler)

        # Configure third-party loggers
        self._configure_third_party_loggers(debug)

        self.configured = True

    def _configure_third_party_loggers(self, debug: bool = False):
        """Configure third-party library loggers."""
        # Splunk SDK logging
        splunk_logger = logging.getLogger("splunklib")
        splunk_logger.setLevel(logging.DEBUG if debug else logging.WARNING)

        # HTTP libraries
        for lib in ["urllib3", "requests", "httpx"]:
            logger = logging.getLogger(lib)
            logger.setLevel(logging.WARNING)

        # Disable most verbose logs unless debug is enabled
        if not debug:
            logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)

    def get_logger(self, name: str) -> SplunkSyncLogger:
        """Get or create a logger with the specified name."""
        if name not in self.loggers:
            base_logger = logging.getLogger(name)
            self.loggers[name] = SplunkSyncLogger(base_logger)

        return self.loggers[name]

    def configure_from_dict(self, config: dict) -> None:
        """Configure logging from dictionary configuration."""
        self.configure_logging(
            level=config.get("log_level", "INFO"),
            log_file=config.get("log_file"),
            structured=config.get("structured_logging", False),
            debug=config.get("debug", False),
        )

    def create_operation_logger(self, operation: str) -> SplunkSyncLogger:
        """Create a logger for a specific operation."""
        logger = self.get_logger(f"splunk_sync.{operation}")
        logger.set_context(operation=operation)
        return logger

    def create_ko_logger(self, ko_type: str) -> SplunkSyncLogger:
        """Create a logger for a specific knowledge object type."""
        logger = self.get_logger(f"splunk_sync.{ko_type}")
        logger.set_context(ko_type=ko_type)
        return logger

    def log_system_info(self):
        """Log system information."""
        logger = self.get_logger("splunk_sync.system")

        import platform
        import sys

        system_info = {
            "python_version": sys.version,
            "platform": platform.platform(),
            "architecture": platform.architecture()[0],
            "processor": platform.processor(),
            "hostname": platform.node(),
        }

        logger.info("System information", **system_info)

    def log_configuration(self, config: dict):
        """Log configuration (sanitized)."""
        logger = self.get_logger("splunk_sync.config")

        # Create sanitized config (remove sensitive data)
        sanitized_config = self._sanitize_config(config)
        logger.info("Configuration loaded", **sanitized_config)

    def _sanitize_config(self, config: dict) -> dict:
        """Remove sensitive information from configuration."""
        sanitized: Dict[str, Any] = {}

        sensitive_keys = {
            "password",
            "token",
            "auth",
            "secret",
            "key",
            "credential",
            "pass",
            "pwd",
        }

        for key, value in config.items():
            if isinstance(value, dict):
                sanitized[key] = self._sanitize_config(value)
            elif any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = "***REDACTED***"
            else:
                sanitized[key] = value

        return sanitized

    def setup_exception_logging(self):
        """Set up global exception logging."""

        def handle_exception(exc_type, exc_value, exc_traceback):
            if issubclass(exc_type, KeyboardInterrupt):
                sys.__excepthook__(exc_type, exc_value, exc_traceback)
                return

            logger = self.get_logger("splunk_sync.exceptions")
            logger.critical(
                "Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback)
            )

        sys.excepthook = handle_exception


# Global logging manager instance
logging_manager = LoggingManager()


def get_logger(name: str) -> SplunkSyncLogger:
    """Get a logger instance."""
    return logging_manager.get_logger(name)


def configure_logging(**kwargs) -> None:
    """Configure logging with specified options."""
    logging_manager.configure_logging(**kwargs)


def log_operation(operation: str):
    """Decorator to log operation start/end."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            logger = logging_manager.create_operation_logger(operation)
            logger.operation_start(operation)

            try:
                result = func(*args, **kwargs)
                logger.operation_end(operation, success=True)
                return result
            except Exception as e:
                logger.operation_end(operation, success=False, error=str(e))
                raise

        return wrapper

    return decorator


def log_ko_operation(ko_type: str, stanza_name: str, operation: str):
    """Decorator to log knowledge object operations."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            logger = logging_manager.create_ko_logger(ko_type)
            logger.ko_operation(
                operation, ko_type, stanza_name, f"Starting {operation}"
            )

            try:
                result = func(*args, **kwargs)
                logger.ko_operation(
                    operation, ko_type, stanza_name, f"Completed {operation}"
                )
                return result
            except Exception as e:
                logger.ko_operation(
                    operation, ko_type, stanza_name, f"Failed {operation}: {e}"
                )
                raise

        return wrapper

    return decorator
