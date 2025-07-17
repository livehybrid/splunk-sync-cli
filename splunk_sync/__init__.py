"""
Splunk Synchronization Tool

A modern, extensible tool for synchronizing Splunk knowledge objects
between Git repositories and Splunk servers.
"""

__version__ = "2.0.0"
__author__ = "Splunk Sync Team"
__email__ = "support@example.com"

from .client import SplunkClient
from .config import ConfigManager, SyncConfig, SyncMode
from .exceptions import SplunkSyncError
from .knowledge_objects import KnowledgeObject, KnowledgeObjectManager
from .logging import configure_logging, get_logger
from .rbac import ACL, RBACManager
from .sync import SplunkSynchronizer

__all__ = [
    "SyncConfig",
    "ConfigManager",
    "SyncMode",
    "SplunkSyncError",
    "SplunkClient",
    "SplunkSynchronizer",
    "KnowledgeObject",
    "KnowledgeObjectManager",
    "RBACManager",
    "ACL",
    "get_logger",
    "configure_logging",
]
