# Splunk Synchronization Tool

A modern, production-ready Python application for synchronizing Splunk knowledge objects between local filesystem and Splunk servers. 

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## 🚀 Features

### Core Functionality
- **Bidirectional Synchronization**: Push, pull, or sync knowledge objects between Git and Splunk
- **Knowledge Object Support**: Macros, tags, eventtypes, savedsearches, workflow actions, transforms, props, lookups
- **Filtering & Allowlists**: Regex-based filtering for selective synchronization
- **RBAC Management**: Comprehensive role-based access control with permission templates
- **Conflict Resolution**: Smart conflict detection and resolution strategies

### Modern Architecture
- **Modular Design**: Clean separation of concerns with focused, single-responsibility classes
- **Type Safety**: Full type hints throughout for better code quality and IDE support
- **Comprehensive Error Handling**: Rich exception hierarchy with detailed error context
- **Structured Logging**: JSON output support for monitoring and debugging
- **Configuration Management**: Flexible configuration with validation and environment variable support

### User Experience
- **Modern CLI**: Rich command-line interface with subcommands and helpful output
- **Dry Run Mode**: Test operations without making changes
- **Connection Testing**: Validate connectivity before synchronization
- **Progress Tracking**: Detailed statistics and progress reporting
- **Sample Generation**: Generate example configuration files

## 📋 Requirements

- Python 3.7 or higher
- Splunk SDK for Python
- Access to a Splunk server with appropriate permissions

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd splunk-sync-cli
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Make the script executable** (optional):
   ```bash
   chmod +x splunk-sync.py
   ```

## 🚀 Quick Start

### 1. Generate Configuration
```bash
python splunk-sync.py generate-config --output my-config.conf
```

### 2. Edit Configuration
Edit `my-config.conf` with your Splunk server details:
```ini
[splunk]
host = your-splunk-server.com
token = your-auth-token
app = your-target-app
```

### 3. Test Connection
```bash
python splunk-sync.py test-connection --config my-config.conf
```

### 4. Run Synchronization
```bash
# Dry run first to see what would happen
python splunk-sync.py push --config my-config.conf --dry-run

# Actual synchronization
python splunk-sync.py push --config my-config.conf
```

## 📖 Usage

### Command Structure
```bash
python splunk-sync.py [GLOBAL_OPTIONS] COMMAND [COMMAND_OPTIONS]
```

### Global Options
- `--config, -c`: Path to configuration file
- `--debug`: Enable debug logging
- `--log-level`: Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `--log-file`: Path to log file
- `--structured-logging`: Enable structured JSON logging
- `--dry-run`: Show what would be done without making changes
- `--version`: Show version information

### Commands

#### Push Mode
Push local changes to Splunk server:
```bash
python splunk-sync.py push --host splunk.example.com --token mytoken
```

#### Pull Mode
Pull remote changes from Splunk server:
```bash
python splunk-sync.py pull --config config.conf
```

#### Sync Mode
Bidirectional synchronization with conflict resolution:
```bash
python splunk-sync.py sync --savedsearches-allowlist "Alert.*" --dry-run
```

#### Test Connection
Validate connectivity to Splunk server:
```bash
python splunk-sync.py test-connection --host localhost --username admin --password changeme
```

#### Server Information
Get detailed Splunk server information:
```bash
python splunk-sync.py server-info --config config.conf
```

#### Validate Configuration
Validate configuration and local files:
```bash
python splunk-sync.py validate --config config.conf --debug
```

## 🔧 Configuration

### Configuration File Format
```ini
[splunk]
host = localhost
port = 8089
scheme = https
username = admin
password = changeme
# token = your-auth-token-here  # Preferred over username/password
app = search
verify_ssl = true
timeout = 60

[knowledge_objects]
types = macros,tags,eventtypes,savedsearches,workflow_actions,transforms,props,lookups
savedsearches_allowlist = .*
email_actions_allowed = false
rbac_enabled = true

# Sync settings
mode = push
dry_run = false
apps_path = ./apps
target_app = search
log_level = INFO
```

### Environment Variables
All configuration options can be overridden with environment variables:

```bash
export SPLUNK_HOST=splunk.example.com
export SPLUNK_TOKEN=your-token-here
export SAVEDSEARCHES_ALLOWLIST="Alert.*|Report.*"
export DRY_RUN=true
export DEBUG=true
```

## 🎯 Advanced Features

### Savedsearches Filtering
Filter savedsearches using regex patterns:

```bash
# Only alerts
--savedsearches-allowlist "Alert.*"

# Multiple prefixes
--savedsearches-allowlist "(Test|Prod|Dev).*"

# Exclude temporary items
--savedsearches-allowlist "^(?!.*temp).*$"

# Complex patterns
--savedsearches-allowlist "^(Alert|Report)_[A-Z]{3}_.*$"
```

### RBAC Management
The tool provides comprehensive role-based access control:

- **Permission Templates**: Default permissions for different object types
- **Role Validation**: Ensures roles exist before assignment
- **Access Control**: Granular read/write permissions
- **Sharing Levels**: Private, App, and Global sharing support

### Logging and Monitoring
```bash
# Structured JSON logging for monitoring systems
python splunk-sync.py push --structured-logging --log-file sync.log

# Debug mode with detailed output
python splunk-sync.py push --debug --log-level DEBUG

# Monitor sync operations
tail -f sync.log | jq '.message'
```

## 📁 Directory Structure

### Expected Directory Layout
```
your-project/
├── apps/
│   ├── your-app/
│   │   └── local/
│   │       ├── macros.conf
│   │       ├── savedsearches.conf
│   │       ├── eventtypes.conf
│   │       └── ...
│   └── another-app/
│       └── local/
│           └── ...
├── splunk_sync.conf
└── splunk-sync.py
```

### Knowledge Object Files
The tool synchronizes `.conf` files from the `local/` directory of each app:

- `macros.conf` - Search macros
- `savedsearches.conf` - Saved searches and alerts
- `eventtypes.conf` - Event type definitions
- `tags.conf` - Tag definitions
- `workflow_actions.conf` - Workflow action definitions
- `transforms.conf` - Field transformations
- `props.conf` - Props configuration
- `lookups.conf` - Lookup definitions

## 🔍 Examples

### Basic Synchronization
```bash
# Push all local changes to Splunk
python splunk-sync.py push \
  --host splunk.company.com \
  --token abc123 \
  --app myapp

# Pull all remote changes to local
python splunk-sync.py pull \
  --config production.conf \
  --apps-path /opt/splunk-apps

# Bidirectional sync with conflict resolution
python splunk-sync.py sync \
  --config config.conf \
  --dry-run
```

### Advanced Filtering
```bash
# Only sync production alerts
python splunk-sync.py push \
  --config config.conf \
  --savedsearches-allowlist "^PROD_Alert_.*$" \
  --ko-types savedsearches

# Exclude test objects
python splunk-sync.py push \
  --config config.conf \
  --savedsearches-allowlist "^(?!.*test).*$"
```

### Monitoring and Debugging
```bash
# JSON logging for monitoring
python splunk-sync.py push \
  --config config.conf \
  --structured-logging \
  --log-file /var/log/splunk-sync.log

# Debug mode with maximum verbosity
python splunk-sync.py push \
  --config config.conf \
  --debug \
  --log-level DEBUG
```

### CI/CD Integration
```bash
#!/bin/bash
# CI/CD pipeline script

# Set environment variables
export SPLUNK_HOST=$SPLUNK_PROD_HOST
export SPLUNK_TOKEN=$SPLUNK_PROD_TOKEN
export SAVEDSEARCHES_ALLOWLIST="^PROD_.*$"

# Validate configuration
python splunk-sync.py validate --config prod.conf
if [ $? -ne 0 ]; then
    echo "Configuration validation failed"
    exit 1
fi

# Test connection
python splunk-sync.py test-connection --config prod.conf
if [ $? -ne 0 ]; then
    echo "Connection test failed"
    exit 1
fi

# Deploy changes
python splunk-sync.py push --config prod.conf --log-file deploy.log
```

## 🚨 Error Handling

The tool provides comprehensive error handling with specific exception types:

### Connection Errors
```bash
# Connection failures
ERROR: ConnectionError: Failed to connect to splunk.example.com:8089
       Context: {'original_error': 'Connection refused'}

# Authentication failures
ERROR: AuthenticationError: Authentication failed - check credentials
       Context: {'username': 'admin', 'status_code': 401}
```

### Configuration Errors
```bash
# Invalid configuration
ERROR: ConfigurationError: Invalid savedsearches allowlist regex: unterminated character set

# Missing required fields
ERROR: ValidationError: Splunk host is required
```

### Sync Errors
```bash
# Conflict resolution
WARNING: Conflict detected for savedsearches/MyAlert, local version wins

# Permission errors
ERROR: PermissionError: Cannot update RBAC because of insufficient permissions
       Context: {'ko_type': 'savedsearches', 'stanza_name': 'MyAlert'}
```

## 🔧 Troubleshooting

### Common Issues

#### SSL Certificate Issues
```bash
# Disable SSL verification (not recommended for production)
python splunk-sync.py push --no-verify-ssl

# Or in configuration
[splunk]
verify_ssl = false
```

#### Permission Problems
```bash
# Check current permissions
python splunk-sync.py server-info --config config.conf

# Validate RBAC settings
python splunk-sync.py validate --config config.conf --debug
```

#### Sync Conflicts
```bash
# Use dry run to preview changes
python splunk-sync.py sync --dry-run --debug

# Check logs for conflict details
python splunk-sync.py sync --log-level DEBUG --log-file conflicts.log
```

### Debug Mode
Enable debug mode for detailed troubleshooting:
```bash
python splunk-sync.py push --debug --log-level DEBUG --structured-logging
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Run linting
flake8 splunk_sync/
black splunk_sync/
mypy splunk_sync/
```

## 📊 Performance

### Optimization Tips
- Use `--concurrent-requests` to increase parallelism
- Filter objects with `--savedsearches-allowlist` to reduce scope
- Use `--batch-size` to tune batch processing
- Enable structured logging for better monitoring

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built on the [Splunk SDK for Python](https://github.com/splunk/splunk-sdk-python)
- Thanks to the Splunk community for feedback and contributions

## 📞 Support

For questions, issues, or contributions:
- Create an issue on GitHub
- Check the [troubleshooting guide](#-troubleshooting)
- Review the [examples](#-examples) for common use cases

---

**Note**: This tool is designed for production use but should be tested thoroughly in development environments before deployment to production systems.
