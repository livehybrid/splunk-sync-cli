"""
Splunk Synchronization Tool

A modern, extensible tool for synchronizing Splunk knowledge objects
between Git repositories and Splunk servers.
"""

__version__ = "2.0.0"
__author__ = "Splunk Sync Team"
__email__ = "support@example.com"

from .config import SyncConfig, ConfigManager, SyncMode
from .exceptions import SplunkSyncError
from .client import SplunkClient
from .sync import SplunkSynchronizer
from .knowledge_objects import KnowledgeObject, KnowledgeObjectManager
from .rbac import RBACManager, ACL
from .logging import get_logger, configure_logging

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
