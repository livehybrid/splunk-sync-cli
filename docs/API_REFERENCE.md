# API Reference

This document provides detailed API documentation for the Splunk Synchronization Tool modules.

## Configuration Module (`splunk_sync.config`)

### Classes

#### `SyncMode(Enum)`
Enumeration of synchronization modes.

**Values:**
- `PUSH`: Push local changes to Splunk
- `PULL`: Pull remote changes to local
- `SYNC`: Bidirectional synchronization

#### `SplunkConnectionConfig`
Configuration for Splunk server connection.

**Attributes:**
- `host` (str): Splunk server hostname
- `port` (int): Splunk server port (default: 8089)
- `scheme` (str): Connection scheme (default: "https")
- `username` (Optional[str]): Username for authentication
- `password` (Optional[str]): Password for authentication
- `token` (Optional[str]): Token for authentication
- `app` (str): Target app (default: "search")
- `owner` (str): Owner context (default: "admin")
- `verify_ssl` (bool): SSL verification (default: True)
- `timeout` (int): Connection timeout (default: 60)
- `retry_count` (int): Retry attempts (default: 3)
- `retry_delay` (float): Retry delay (default: 1.0)

**Properties:**
- `base_url` (str): Complete base URL for Splunk API

#### `KnowledgeObjectConfig`
Configuration for knowledge object processing.

**Attributes:**
- `types` (List[str]): Knowledge object types to process
- `ignored_keys` (List[str]): Keys to ignore during sync
- `savedsearches_allowlist` (str): Regex pattern for filtering
- `email_actions_allowed` (bool): Allow email actions
- `rbac_enabled` (bool): Enable RBAC management
- `default_permissions` (Dict[str, str]): Default permission settings

#### `ConfigManager`
Manages configuration loading and validation.

**Methods:**
- `load_config() -> SyncConfig`: Load configuration from file and environment
- `validate_config(config: SyncConfig) -> List[str]`: Validate configuration
- `create_sample_config(path: str) -> None`: Create sample configuration file

## Client Module (`splunk_sync.client`)

### Classes

#### `SplunkClient`
Modern Splunk client with enhanced error handling.

**Constructor:**
```python
SplunkClient(config: SplunkConnectionConfig, proxy_config: Optional[ProxyConfig] = None)
```

**Context Manager:**
```python
with SplunkClient(config) as client:
    # Use client
```

**Methods:**
- `connect() -> None`: Establish connection to Splunk
- `disconnect() -> None`: Disconnect from Splunk
- `get_app_info(app_name: str) -> Dict[str, Any]`: Get app information
- `list_knowledge_objects(ko_type: str, app: Optional[str] = None) -> List[Dict[str, Any]]`: List knowledge objects
- `get_knowledge_object(ko_type: str, stanza_name: str) -> Dict[str, Any]`: Get specific object
- `create_knowledge_object(ko_type: str, stanza_name: str, content: Dict[str, Any]) -> None`: Create object
- `update_knowledge_object(ko_type: str, stanza_name: str, content: Dict[str, Any]) -> None`: Update object
- `delete_knowledge_object(ko_type: str, stanza_name: str) -> None`: Delete object
- `update_object_permissions(ko_type: str, stanza_name: str, permissions: Dict[str, Any]) -> None`: Update permissions
- `test_connection() -> bool`: Test connection
- `get_server_info() -> Dict[str, Any]`: Get server information

## Knowledge Objects Module (`splunk_sync.knowledge_objects`)

### Classes

#### `KnowledgeObject`
Represents a Splunk knowledge object.

**Attributes:**
- `name` (str): Object name
- `ko_type` (str): Object type
- `content` (Dict[str, Any]): Object content
- `app` (str): App context
- `owner` (str): Owner (default: "admin")
- `sharing` (str): Sharing level (default: "app")

#### `KnowledgeObjectFilter`
Handles filtering of knowledge objects.

**Methods:**
- `should_process_object(ko: KnowledgeObject) -> bool`: Check if object should be processed
- `filter_content(ko: KnowledgeObject) -> Dict[str, Any]`: Filter object content

#### `KnowledgeObjectHandler` (Abstract Base Class)
Base class for knowledge object handlers.

**Methods:**
- `validate(ko: KnowledgeObject) -> List[str]`: Validate object
- `transform_for_sync(ko: KnowledgeObject) -> Dict[str, Any]`: Transform for sync
- `can_handle(ko_type: str) -> bool`: Check if can handle type

#### `KnowledgeObjectManager`
Manages knowledge objects with proper handlers.

**Methods:**
- `get_handler(ko_type: str) -> Optional[KnowledgeObjectHandler]`: Get handler for type
- `validate_object(ko: KnowledgeObject) -> List[str]`: Validate object
- `transform_object(ko: KnowledgeObject) -> Dict[str, Any]`: Transform object
- `should_process_object(ko: KnowledgeObject) -> bool`: Check if should process
- `load_from_file(file_path: Path, ko_type: str, app: str) -> List[KnowledgeObject]`: Load from file
- `save_to_file(objects: List[KnowledgeObject], file_path: Path, ko_type: str) -> None`: Save to file

### Handler Classes

#### `SavedSearchHandler`
Handles savedsearches knowledge objects.

**Validation Rules:**
- `search` field is required
- Search query cannot be empty
- Email actions validation
- Cron schedule validation

#### `MacroHandler`
Handles macros knowledge objects.

**Validation Rules:**
- `definition` field is required
- Definition cannot be empty
- Argument format validation

#### `EventTypeHandler`
Handles eventtypes knowledge objects.

**Validation Rules:**
- `search` field is required
- Search query cannot be empty
- Priority validation (1-10)

## RBAC Module (`splunk_sync.rbac`)

### Classes

#### `SharingLevel(Enum)`
Sharing levels for knowledge objects.

**Values:**
- `PRIVATE`: User-level sharing
- `APP`: App-level sharing
- `GLOBAL`: Global sharing

#### `Permission`
Represents permission settings.

**Attributes:**
- `read` (Set[str]): Read permissions
- `write` (Set[str]): Write permissions

#### `ACL`
Access Control List for knowledge objects.

**Attributes:**
- `owner` (str): Object owner
- `app` (str): App context
- `sharing` (SharingLevel): Sharing level
- `permissions` (Permission): Permission settings
- `modifiable` (bool): Can be modified
- `removable` (bool): Can be removed

**Methods:**
- `to_dict() -> Dict[str, Any]`: Convert to dictionary
- `from_dict(data: Dict[str, Any]) -> ACL`: Create from dictionary

#### `RBACManager`
Main RBAC management class.

**Methods:**
- `is_enabled() -> bool`: Check if RBAC is enabled
- `get_object_acl(ko: KnowledgeObject) -> ACL`: Get object ACL
- `update_object_permissions(ko: KnowledgeObject, permissions: Dict[str, Any]) -> ACL`: Update permissions
- `check_access(ko: KnowledgeObject, user_roles: List[str], operation: str) -> bool`: Check access
- `apply_default_permissions(ko: KnowledgeObject) -> Dict[str, Any]`: Apply default permissions

## Synchronization Module (`splunk_sync.sync`)

### Classes

#### `SyncStatistics`
Statistics for synchronization operations.

**Attributes:**
- `total_objects` (int): Total objects processed
- `created` (int): Objects created
- `updated` (int): Objects updated
- `deleted` (int): Objects deleted
- `skipped` (int): Objects skipped
- `errors` (int): Errors encountered
- `start_time` (float): Start timestamp
- `end_time` (Optional[float]): End timestamp

**Methods:**
- `finish() -> None`: Mark as finished
- `to_dict() -> Dict[str, Any]`: Convert to dictionary

**Properties:**
- `duration` (float): Operation duration
- `success_rate` (float): Success rate percentage

#### `SyncResult`
Result of synchronization operation.

**Attributes:**
- `success` (bool): Operation success
- `statistics` (SyncStatistics): Operation statistics
- `errors` (List[str]): Error messages
- `warnings` (List[str]): Warning messages

**Methods:**
- `add_error(error: str) -> None`: Add error
- `add_warning(warning: str) -> None`: Add warning

#### `SplunkSynchronizer`
Main synchronization orchestrator.

**Constructor:**
```python
SplunkSynchronizer(config: SyncConfig)
```

**Context Manager:**
```python
with SplunkSynchronizer(config) as synchronizer:
    # Use synchronizer
```

**Methods:**
- `connect() -> None`: Connect to Splunk
- `disconnect() -> None`: Disconnect from Splunk
- `sync() -> SyncResult`: Perform synchronization
- `validate_configuration() -> List[str]`: Validate configuration
- `test_connection() -> bool`: Test connection
- `get_server_info() -> Dict[str, Any]`: Get server info
- `get_app_info(app_name: str) -> Dict[str, Any]`: Get app info

## Logging Module (`splunk_sync.logging`)

### Classes

#### `StructuredFormatter`
Custom formatter for structured JSON logs.

#### `ColoredConsoleFormatter`
Colored console formatter for readability.

#### `SplunkSyncLogger`
Enhanced logger with context management.

**Methods:**
- `set_context(**kwargs) -> None`: Set logging context
- `clear_context() -> None`: Clear context
- `debug(message: str, **kwargs) -> None`: Log debug message
- `info(message: str, **kwargs) -> None`: Log info message
- `warning(message: str, **kwargs) -> None`: Log warning message
- `error(message: str, **kwargs) -> None`: Log error message
- `critical(message: str, **kwargs) -> None`: Log critical message
- `exception(message: str, **kwargs) -> None`: Log exception
- `operation_start(operation: str, **kwargs) -> None`: Log operation start
- `operation_end(operation: str, success: bool, **kwargs) -> None`: Log operation end
- `ko_operation(operation: str, ko_type: str, stanza_name: str, message: str, **kwargs) -> None`: Log KO operation
- `sync_stats(stats: Dict[str, Any]) -> None`: Log sync statistics

#### `LoggingManager`
Manages logging configuration.

**Methods:**
- `configure_logging(level: str, log_file: Optional[str], structured: bool, debug: bool) -> None`: Configure logging
- `get_logger(name: str) -> SplunkSyncLogger`: Get logger instance
- `create_operation_logger(operation: str) -> SplunkSyncLogger`: Create operation logger
- `create_ko_logger(ko_type: str) -> SplunkSyncLogger`: Create KO logger
- `log_system_info() -> None`: Log system information

### Functions

- `get_logger(name: str) -> SplunkSyncLogger`: Get logger instance
- `configure_logging(**kwargs) -> None`: Configure logging
- `log_operation(operation: str)`: Decorator to log operations
- `log_ko_operation(ko_type: str, stanza_name: str, operation: str)`: Decorator to log KO operations

## Exceptions Module (`splunk_sync.exceptions`)

### Exception Hierarchy

#### `SplunkSyncError`
Base exception for all Splunk sync operations.

**Attributes:**
- `context` (Dict[str, Any]): Error context

#### `ConfigurationError`
Raised when configuration is invalid.

#### `ConnectionError`
Raised when unable to connect to Splunk.

**Attributes:**
- `host` (str): Splunk host
- `port` (int): Splunk port

#### `AuthenticationError`
Raised when authentication fails.

**Attributes:**
- `username` (Optional[str]): Username

#### `AuthorizationError`
Raised when user lacks permissions.

**Attributes:**
- `required_permission` (Optional[str]): Required permission

#### `KnowledgeObjectError`
Base exception for knowledge object operations.

**Attributes:**
- `ko_type` (str): Knowledge object type
- `stanza_name` (str): Stanza name

#### `ValidationError`
Raised when validation fails.

**Attributes:**
- `field` (Optional[str]): Field name

#### `SyncConflictError`
Raised during synchronization conflicts.

**Attributes:**
- `local_value` (Any): Local value
- `remote_value` (Any): Remote value

#### `PermissionError`
Raised when RBAC operations fail.

**Attributes:**
- `permission_type` (str): Permission type

#### `APIError`
Raised when Splunk API calls fail.

**Attributes:**
- `status_code` (int): HTTP status code
- `endpoint` (str): API endpoint

#### `RetryExhaustedError`
Raised when retry attempts are exhausted.

**Attributes:**
- `attempts` (int): Number of attempts
- `last_error` (Exception): Last error

#### `FileOperationError`
Raised when file operations fail.

**Attributes:**
- `file_path` (str): File path
- `operation` (str): Operation type

#### `FilterError`
Raised when filtering operations fail.

**Attributes:**
- `filter_pattern` (str): Filter pattern

## CLI Module (`splunk_sync.cli`)

### Classes

#### `SplunkSyncCLI`
Command-line interface for Splunk synchronization.

**Methods:**
- `create_parser() -> argparse.ArgumentParser`: Create argument parser
- `run(args: Optional[List[str]]) -> int`: Run CLI application

**Private Methods:**
- `_build_config(args) -> SyncConfig`: Build configuration from arguments
- `_sync(config, mode: SyncMode) -> int`: Perform synchronization
- `_test_connection(config) -> int`: Test connection
- `_server_info(config) -> int`: Get server info
- `_validate(config) -> int`: Validate configuration
- `_generate_config(args) -> int`: Generate sample config
- `_print_sync_results(result) -> None`: Print sync results
- `_print_server_info(info: Dict[str, Any]) -> None`: Print server info

### Functions

- `main() -> None`: Main entry point

## Usage Examples

### Basic Configuration
```python
from splunk_sync import SyncConfig, SplunkConnectionConfig, ConfigManager

# Create configuration
config = SyncConfig(
    splunk=SplunkConnectionConfig(
        host="splunk.example.com",
        token="your-token"
    )
)

# Or load from file
config_manager = ConfigManager()
config = config_manager.load_config()
```

### Synchronization
```python
from splunk_sync import SplunkSynchronizer

with SplunkSynchronizer(config) as synchronizer:
    result = synchronizer.sync()
    print(f"Success: {result.success}")
    print(f"Statistics: {result.statistics.to_dict()}")
```

### Knowledge Object Management
```python
from splunk_sync import KnowledgeObjectManager, KnowledgeObject

manager = KnowledgeObjectManager(config.knowledge_objects)

# Create knowledge object
ko = KnowledgeObject(
    name="my_macro",
    ko_type="macros",
    content={"definition": "index=main"},
    app="search"
)

# Validate
issues = manager.validate_object(ko)
if not issues:
    # Transform for sync
    transformed = manager.transform_object(ko)
```

### RBAC Management
```python
from splunk_sync import RBACManager

rbac = RBACManager(default_permissions={"owner": "admin"})

# Check access
has_access = rbac.check_access(ko, ["admin"], "read")

# Apply permissions
permissions = rbac.apply_default_permissions(ko)
```

### Logging
```python
from splunk_sync import get_logger, configure_logging

# Configure logging
configure_logging(level="INFO", structured=True)

# Get logger
logger = get_logger(__name__)

# Log with context
logger.info("Processing object", ko_type="macros", stanza_name="my_macro")
```

## Error Handling

### Exception Handling Pattern
```python
from splunk_sync.exceptions import SplunkSyncError, ConnectionError

try:
    with SplunkSynchronizer(config) as synchronizer:
        result = synchronizer.sync()
except ConnectionError as e:
    logger.error(f"Connection failed: {e}")
    logger.error(f"Context: {e.context}")
except SplunkSyncError as e:
    logger.error(f"Sync error: {e}")
    logger.error(f"Context: {e.context}")
```

### Validation Error Handling
```python
from splunk_sync.exceptions import ValidationError

try:
    issues = manager.validate_object(ko)
    if issues:
        raise ValidationError(f"Validation failed: {issues}", ko.ko_type, ko.name)
except ValidationError as e:
    logger.error(f"Validation error for {e.ko_type}/{e.stanza_name}: {e}")
```