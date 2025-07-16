"""
Main synchronization orchestrator for Splunk knowledge objects.

This module coordinates the synchronization process between local Git repositories
and remote Splunk servers with comprehensive error handling and progress tracking.
"""

import re
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio

from .config import SyncConfig, SyncMode
from .client import SplunkClient
from .knowledge_objects import KnowledgeObjectManager, KnowledgeObject
from .rbac import RBACManager
from .logging import get_logger, log_operation, log_ko_operation
from .exceptions import (
    SplunkSyncError,
    ValidationError,
    SyncConflictError,
    FileOperationError,
    FilterError,
)

logger = get_logger(__name__)


@dataclass
class SyncStatistics:
    """Statistics for synchronization operations."""

    total_objects: int = 0
    created: int = 0
    updated: int = 0
    deleted: int = 0
    skipped: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None

    def finish(self):
        """Mark synchronization as finished."""
        self.end_time = time.time()

    @property
    def duration(self) -> float:
        """Get synchronization duration."""
        if self.end_time is None:
            return time.time() - self.start_time
        return self.end_time - self.start_time

    def to_dict(self) -> Dict[str, Any]:
        """Convert statistics to dictionary."""
        return {
            "total_objects": self.total_objects,
            "created": self.created,
            "updated": self.updated,
            "deleted": self.deleted,
            "skipped": self.skipped,
            "errors": self.errors,
            "duration": self.duration,
            "success_rate": (self.total_objects - self.errors)
            / max(self.total_objects, 1)
            * 100,
        }


@dataclass
class SyncResult:
    """Result of a synchronization operation."""

    success: bool
    statistics: SyncStatistics
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add_error(self, error: str):
        """Add error to result."""
        self.errors.append(error)
        self.statistics.errors += 1

    def add_warning(self, warning: str):
        """Add warning to result."""
        self.warnings.append(warning)


class SplunkSynchronizer:
    """Main synchronization orchestrator."""

    def __init__(self, config: SyncConfig):
        """Initialize synchronizer with configuration."""
        self.config = config
        self.ko_manager = KnowledgeObjectManager(config.knowledge_objects)
        self.rbac_manager = RBACManager(
            config.knowledge_objects.default_permissions,
            config.knowledge_objects.rbac_enabled,
        )
        self._client: Optional[SplunkClient] = None

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()

    def connect(self):
        """Connect to Splunk server."""
        if self._client is None:
            self._client = SplunkClient(self.config.splunk, self.config.proxy)
            self._client.connect()
            logger.info("Connected to Splunk server")

    def disconnect(self):
        """Disconnect from Splunk server."""
        if self._client:
            self._client.disconnect()
            self._client = None
            logger.info("Disconnected from Splunk server")

    @property
    def client(self) -> SplunkClient:
        """Get Splunk client."""
        if self._client is None:
            raise SplunkSyncError(
                "Not connected to Splunk. Use context manager or call connect()"
            )
        return self._client

    @log_operation("sync")
    def sync(self) -> SyncResult:
        """Perform synchronization based on configuration."""
        result = SyncResult(success=True, statistics=SyncStatistics())

        try:
            logger.info(f"Starting synchronization in {self.config.mode.value} mode")

            if self.config.mode == SyncMode.PUSH:
                result = self._sync_push()
            elif self.config.mode == SyncMode.PULL:
                result = self._sync_pull()
            elif self.config.mode == SyncMode.SYNC:
                result = self._sync_bidirectional()

            result.statistics.finish()
            logger.sync_stats(result.statistics.to_dict())

        except Exception as e:
            logger.exception(f"Synchronization failed: {e}")
            result.success = False
            result.add_error(str(e))

        return result

    def _sync_push(self) -> SyncResult:
        """Push local changes to Splunk."""
        result = SyncResult(success=True, statistics=SyncStatistics())

        # Load local knowledge objects
        local_objects = self._load_local_objects()
        result.statistics.total_objects = len(local_objects)

        # Get remote objects for comparison
        remote_objects = self._load_remote_objects()

        # Process each knowledge object type
        for ko_type in self.config.knowledge_objects.types:
            type_objects = [ko for ko in local_objects if ko.ko_type == ko_type]
            if not type_objects:
                continue

            logger.info(f"Processing {len(type_objects)} {ko_type} objects")

            # Filter objects based on allowlist
            filtered_objects = self._filter_objects(type_objects)

            # Sync objects
            self._sync_objects_to_remote(filtered_objects, remote_objects, result)

        return result

    def _sync_pull(self) -> SyncResult:
        """Pull remote changes to local."""
        result = SyncResult(success=True, statistics=SyncStatistics())

        # Load remote knowledge objects
        remote_objects = self._load_remote_objects()
        result.statistics.total_objects = len(remote_objects)

        # Load local objects for comparison
        local_objects = self._load_local_objects()

        # Process each knowledge object type
        for ko_type in self.config.knowledge_objects.types:
            type_objects = [ko for ko in remote_objects if ko.ko_type == ko_type]
            if not type_objects:
                continue

            logger.info(f"Processing {len(type_objects)} {ko_type} objects")

            # Filter objects based on allowlist
            filtered_objects = self._filter_objects(type_objects)

            # Sync objects
            self._sync_objects_to_local(filtered_objects, local_objects, result)

        return result

    def _sync_bidirectional(self) -> SyncResult:
        """Perform bidirectional synchronization."""
        result = SyncResult(success=True, statistics=SyncStatistics())

        # Load both local and remote objects
        local_objects = self._load_local_objects()
        remote_objects = self._load_remote_objects()

        result.statistics.total_objects = len(local_objects) + len(remote_objects)

        # Perform conflict resolution and sync
        self._sync_bidirectional_objects(local_objects, remote_objects, result)

        return result

    def _load_local_objects(self) -> List[KnowledgeObject]:
        """Load knowledge objects from local files."""
        objects = []

        apps_path = Path(self.config.apps_path)
        if not apps_path.exists():
            raise FileOperationError(
                f"Apps path not found: {apps_path}", str(apps_path), "read"
            )

        # Look for app directories
        for app_dir in apps_path.iterdir():
            if not app_dir.is_dir():
                continue

            app_name = app_dir.name
            local_dir = app_dir / "local"

            if not local_dir.exists():
                continue

            # Load each knowledge object type
            for ko_type in self.config.knowledge_objects.types:
                conf_file = local_dir / f"{ko_type}.conf"
                if conf_file.exists():
                    try:
                        ko_objects = self.ko_manager.load_from_file(
                            conf_file, ko_type, app_name
                        )
                        objects.extend(ko_objects)
                    except Exception as e:
                        logger.error(f"Failed to load {ko_type} from {conf_file}: {e}")

        logger.info(f"Loaded {len(objects)} local knowledge objects")
        return objects

    def _load_remote_objects(self) -> List[KnowledgeObject]:
        """Load knowledge objects from remote Splunk server."""
        objects = []

        for ko_type in self.config.knowledge_objects.types:
            try:
                remote_objects = self.client.list_knowledge_objects(
                    ko_type, app=self.config.target_app
                )

                for obj_data in remote_objects:
                    # Filter by app if specified
                    if obj_data["access"]["app"] != self.config.target_app:
                        continue

                    ko = KnowledgeObject(
                        name=obj_data["name"],
                        ko_type=ko_type,
                        content=obj_data["content"],
                        app=obj_data["access"]["app"],
                        owner=obj_data["access"]["owner"],
                        sharing=obj_data["access"]["sharing"],
                    )
                    objects.append(ko)

            except Exception as e:
                logger.error(f"Failed to load remote {ko_type}: {e}")

        logger.info(f"Loaded {len(objects)} remote knowledge objects")
        return objects

    def _filter_objects(self, objects: List[KnowledgeObject]) -> List[KnowledgeObject]:
        """Filter objects based on configuration."""
        filtered = []

        for ko in objects:
            if self.ko_manager.should_process_object(ko):
                filtered.append(ko)

        if len(filtered) < len(objects):
            logger.info(
                f"Filtered {len(objects) - len(filtered)} objects based on configuration"
            )

        return filtered

    def _sync_objects_to_remote(
        self,
        local_objects: List[KnowledgeObject],
        remote_objects: List[KnowledgeObject],
        result: SyncResult,
    ):
        """Sync local objects to remote Splunk."""
        # Create lookup for remote objects
        remote_lookup = {(ko.ko_type, ko.name): ko for ko in remote_objects}

        for ko in local_objects:
            try:
                remote_ko = remote_lookup.get((ko.ko_type, ko.name))

                if remote_ko is None:
                    # Create new object
                    self._create_remote_object(ko, result)
                else:
                    # Update existing object
                    self._update_remote_object(ko, remote_ko, result)

            except Exception as e:
                logger.error(f"Failed to sync {ko.ko_type}/{ko.name}: {e}")
                result.add_error(f"{ko.ko_type}/{ko.name}: {e}")

        # Handle deletions if in sync mode
        if self.config.mode == SyncMode.SYNC:
            self._handle_remote_deletions(local_objects, remote_objects, result)

    def _sync_objects_to_local(
        self,
        remote_objects: List[KnowledgeObject],
        local_objects: List[KnowledgeObject],
        result: SyncResult,
    ):
        """Sync remote objects to local files."""
        # Create lookup for local objects
        local_lookup = {(ko.ko_type, ko.name): ko for ko in local_objects}

        # Group by app and type for efficient file operations
        objects_by_app_type = {}

        for ko in remote_objects:
            try:
                local_ko = local_lookup.get((ko.ko_type, ko.name))

                if local_ko is None:
                    # Create new object
                    self._create_local_object(ko, result)
                else:
                    # Update existing object
                    self._update_local_object(ko, local_ko, result)

            except Exception as e:
                logger.error(f"Failed to sync {ko.ko_type}/{ko.name}: {e}")
                result.add_error(f"{ko.ko_type}/{ko.name}: {e}")

    def _create_remote_object(self, ko: KnowledgeObject, result: SyncResult):
        """Create a knowledge object on remote Splunk."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would create {ko.ko_type}/{ko.name}")
            result.statistics.created += 1
            return

        try:
            # Transform object for sync
            content = self.ko_manager.transform_object(ko)

            # Create object
            self.client.create_knowledge_object(ko.ko_type, ko.name, content, ko.app)

            # Update permissions if RBAC is enabled
            if self.rbac_manager.is_enabled():
                permissions = self.rbac_manager.apply_default_permissions(ko)
                if permissions:
                    self.client.update_object_permissions(
                        ko.ko_type, ko.name, permissions, ko.app
                    )

            logger.info(f"Created {ko.ko_type}/{ko.name}")
            result.statistics.created += 1

        except Exception as e:
            logger.error(f"Failed to create {ko.ko_type}/{ko.name}: {e}")
            result.add_error(f"{ko.ko_type}/{ko.name}: {e}")

    def _update_remote_object(
        self, local_ko: KnowledgeObject, remote_ko: KnowledgeObject, result: SyncResult
    ):
        """Update a knowledge object on remote Splunk."""
        # Check if update is needed
        local_content = self.ko_manager.transform_object(local_ko)

        if local_content == remote_ko.content:
            logger.debug(f"No changes needed for {local_ko.ko_type}/{local_ko.name}")
            result.statistics.skipped += 1
            return

        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would update {local_ko.ko_type}/{local_ko.name}")
            result.statistics.updated += 1
            return

        try:
            # Update object
            self.client.update_knowledge_object(
                local_ko.ko_type, local_ko.name, local_content, local_ko.app
            )

            logger.info(f"Updated {local_ko.ko_type}/{local_ko.name}")
            result.statistics.updated += 1

        except Exception as e:
            logger.error(f"Failed to update {local_ko.ko_type}/{local_ko.name}: {e}")
            result.add_error(f"{local_ko.ko_type}/{local_ko.name}: {e}")

    def _create_local_object(self, ko: KnowledgeObject, result: SyncResult):
        """Create a knowledge object in local files."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would create local {ko.ko_type}/{ko.name}")
            result.statistics.created += 1
            return

        try:
            # Determine file path
            apps_path = Path(self.config.apps_path)
            app_dir = apps_path / ko.app / "local"
            conf_file = app_dir / f"{ko.ko_type}.conf"

            # Load existing objects or create new list
            if conf_file.exists():
                existing_objects = self.ko_manager.load_from_file(
                    conf_file, ko.ko_type, ko.app
                )
            else:
                existing_objects = []

            # Add new object
            existing_objects.append(ko)

            # Save to file
            self.ko_manager.save_to_file(existing_objects, conf_file, ko.ko_type)

            logger.info(f"Created local {ko.ko_type}/{ko.name}")
            result.statistics.created += 1

        except Exception as e:
            logger.error(f"Failed to create local {ko.ko_type}/{ko.name}: {e}")
            result.add_error(f"{ko.ko_type}/{ko.name}: {e}")

    def _update_local_object(
        self, remote_ko: KnowledgeObject, local_ko: KnowledgeObject, result: SyncResult
    ):
        """Update a knowledge object in local files."""
        # Check if update is needed
        if remote_ko.content == local_ko.content:
            logger.debug(
                f"No changes needed for local {local_ko.ko_type}/{local_ko.name}"
            )
            result.statistics.skipped += 1
            return

        if self.config.dry_run:
            logger.info(
                f"[DRY RUN] Would update local {local_ko.ko_type}/{local_ko.name}"
            )
            result.statistics.updated += 1
            return

        try:
            # Update local object content
            local_ko.content = remote_ko.content

            # Save to file
            apps_path = Path(self.config.apps_path)
            app_dir = apps_path / local_ko.app / "local"
            conf_file = app_dir / f"{local_ko.ko_type}.conf"

            # Load all objects, update the specific one, and save
            all_objects = self.ko_manager.load_from_file(
                conf_file, local_ko.ko_type, local_ko.app
            )

            # Update the object in the list
            for i, obj in enumerate(all_objects):
                if obj.name == local_ko.name:
                    all_objects[i] = local_ko
                    break

            self.ko_manager.save_to_file(all_objects, conf_file, local_ko.ko_type)

            logger.info(f"Updated local {local_ko.ko_type}/{local_ko.name}")
            result.statistics.updated += 1

        except Exception as e:
            logger.error(
                f"Failed to update local {local_ko.ko_type}/{local_ko.name}: {e}"
            )
            result.add_error(f"{local_ko.ko_type}/{local_ko.name}: {e}")

    def _handle_remote_deletions(
        self,
        local_objects: List[KnowledgeObject],
        remote_objects: List[KnowledgeObject],
        result: SyncResult,
    ):
        """Handle deletion of objects that exist remotely but not locally."""
        local_lookup = {(ko.ko_type, ko.name) for ko in local_objects}

        for remote_ko in remote_objects:
            if (remote_ko.ko_type, remote_ko.name) not in local_lookup:
                # Object exists remotely but not locally - delete it
                self._delete_remote_object(remote_ko, result)

    def _delete_remote_object(self, ko: KnowledgeObject, result: SyncResult):
        """Delete a knowledge object from remote Splunk."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would delete {ko.ko_type}/{ko.name}")
            result.statistics.deleted += 1
            return

        try:
            self.client.delete_knowledge_object(ko.ko_type, ko.name, ko.app)

            logger.info(f"Deleted {ko.ko_type}/{ko.name}")
            result.statistics.deleted += 1

        except Exception as e:
            logger.error(f"Failed to delete {ko.ko_type}/{ko.name}: {e}")
            result.add_error(f"{ko.ko_type}/{ko.name}: {e}")

    def _sync_bidirectional_objects(
        self,
        local_objects: List[KnowledgeObject],
        remote_objects: List[KnowledgeObject],
        result: SyncResult,
    ):
        """Perform bidirectional synchronization with conflict resolution."""
        # Create lookups
        local_lookup = {(ko.ko_type, ko.name): ko for ko in local_objects}
        remote_lookup = {(ko.ko_type, ko.name): ko for ko in remote_objects}

        # Find all unique objects
        all_keys = set(local_lookup.keys()) | set(remote_lookup.keys())

        for key in all_keys:
            local_ko = local_lookup.get(key)
            remote_ko = remote_lookup.get(key)

            try:
                if local_ko and remote_ko:
                    # Both exist - check for conflicts
                    self._resolve_conflict(local_ko, remote_ko, result)
                elif local_ko:
                    # Only local exists - create remote
                    self._create_remote_object(local_ko, result)
                elif remote_ko:
                    # Only remote exists - create local
                    self._create_local_object(remote_ko, result)

            except Exception as e:
                logger.error(f"Failed to sync {key}: {e}")
                result.add_error(f"{key}: {e}")

    def _resolve_conflict(
        self, local_ko: KnowledgeObject, remote_ko: KnowledgeObject, result: SyncResult
    ):
        """Resolve conflicts between local and remote objects."""
        # Simple conflict resolution - local wins
        # In a more sophisticated implementation, this could:
        # - Check timestamps
        # - Merge changes
        # - Prompt user for resolution

        local_content = self.ko_manager.transform_object(local_ko)

        if local_content != remote_ko.content:
            logger.warning(
                f"Conflict detected for {local_ko.ko_type}/{local_ko.name}, local version wins"
            )
            result.add_warning(
                f"Conflict resolved for {local_ko.ko_type}/{local_ko.name}"
            )
            self._update_remote_object(local_ko, remote_ko, result)
        else:
            result.statistics.skipped += 1

    def validate_configuration(self) -> List[str]:
        """Validate synchronization configuration."""
        issues = []

        # Validate apps path
        apps_path = Path(self.config.apps_path)
        if not apps_path.exists():
            issues.append(f"Apps path does not exist: {apps_path}")

        # Validate knowledge object types
        for ko_type in self.config.knowledge_objects.types:
            if ko_type not in [
                "macros",
                "tags",
                "eventtypes",
                "savedsearches",
                "workflow_actions",
                "transforms",
                "props",
                "lookups",
            ]:
                issues.append(f"Invalid knowledge object type: {ko_type}")

        # Validate savedsearches allowlist regex
        try:
            re.compile(self.config.knowledge_objects.savedsearches_allowlist)
        except re.error as e:
            issues.append(f"Invalid savedsearches allowlist regex: {e}")

        return issues

    def test_connection(self) -> bool:
        """Test connection to Splunk server."""
        try:
            return self.client.test_connection()
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False

    def get_server_info(self) -> Dict[str, Any]:
        """Get Splunk server information."""
        return self.client.get_server_info()

    def get_app_info(self, app_name: str) -> Dict[str, Any]:
        """Get information about a specific app."""
        return self.client.get_app_info(app_name)
