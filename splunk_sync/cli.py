"""
Command-line interface for Splunk synchronization tool.

This module provides a modern, feature-rich CLI with proper argument parsing,
help text, and user-friendly output formatting.
"""

import argparse
import signal
import sys
from typing import Any, Dict, List, Optional

from .config import ConfigManager, SyncConfig, SyncMode
from .exceptions import ConfigurationError, SplunkSyncError
from .logging import get_logger, logging_manager
from .sync import SplunkSynchronizer

logger = get_logger(__name__)


class SplunkSyncCLI:
    """Command-line interface for Splunk synchronization."""

    def __init__(self):
        """Initialize CLI."""
        self.config_manager = ConfigManager()
        self.interrupted = False

        # Set up signal handlers
        signal.signal(signal.SIGINT, self._handle_interrupt)
        signal.signal(signal.SIGTERM, self._handle_interrupt)

    def _handle_interrupt(self, signum, frame):
        """Handle interrupt signals."""
        print("\nReceived interrupt signal. Shutting down gracefully...")
        self.interrupted = True

    def create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser."""
        parser = argparse.ArgumentParser(
            description="Synchronize Splunk knowledge objects between Git and Splunk servers",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Push local changes to Splunk
  splunk-sync push --host splunk.example.com --token mytoken
  # Pull remote changes to local
  splunk-sync pull --config /path/to/config.conf
  # Bidirectional sync with dry run
  splunk-sync sync --dry-run --debug
  # Test connection
  splunk-sync test-connection --host localhost --username admin --password changeme
  # Generate sample configuration
  splunk-sync generate-config --output splunk_sync.conf
Environment Variables:
  SPLUNK_HOST                - Splunk server hostname
  SPLUNK_PORT                - Splunk server port (default: 8089)
  SPLUNK_USERNAME            - Username for authentication
  SPLUNK_PASSWORD            - Password for authentication
  SPLUNK_TOKEN               - Token for authentication (preferred)
  SPLUNK_APP                 - Target app (default: search)
  SAVEDSEARCHES_ALLOWLIST    - Regex pattern for savedsearches filtering
  DRY_RUN                    - Enable dry run mode (true/false)
  DEBUG                      - Enable debug logging (true/false)
  LOG_LEVEL                  - Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  LOG_FILE                   - Path to log file
            """,
        )

        # Global options
        parser.add_argument(
            "--config", "-c", type=str, help="Path to configuration file"
        )
        parser.add_argument("--debug", action="store_true", help="Enable debug logging")
        parser.add_argument(
            "--log-level",
            choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            default="INFO",
            help="Set logging level",
        )
        parser.add_argument("--log-file", type=str, help="Path to log file")
        parser.add_argument(
            "--structured-logging",
            action="store_true",
            help="Enable structured JSON logging",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be done without making changes",
        )
        parser.add_argument("--version", action="version", version="%(prog)s 2.0.0")

        # Connection options
        connection_group = parser.add_argument_group("Connection Options")
        connection_group.add_argument("--host", type=str, help="Splunk server hostname")
        connection_group.add_argument(
            "--port", type=int, default=8089, help="Splunk server port (default: 8089)"
        )
        connection_group.add_argument(
            "--scheme",
            choices=["http", "https"],
            default="https",
            help="Connection scheme (default: https)",
        )
        connection_group.add_argument(
            "--username", type=str, help="Username for authentication"
        )
        connection_group.add_argument(
            "--password", type=str, help="Password for authentication"
        )
        connection_group.add_argument(
            "--token",
            type=str,
            help="Token for authentication (preferred over username/password)",
        )
        connection_group.add_argument(
            "--app",
            type=str,
            default="search",
            help="Target Splunk app (default: search)",
        )
        connection_group.add_argument(
            "--verify-ssl",
            action="store_true",
            default=True,
            help="Verify SSL certificates (default: True)",
        )
        connection_group.add_argument(
            "--no-verify-ssl",
            action="store_false",
            dest="verify_ssl",
            help="Disable SSL certificate verification",
        )

        # Sync options
        sync_group = parser.add_argument_group("Synchronization Options")
        sync_group.add_argument(
            "--apps-path",
            type=str,
            default="./apps",
            help="Path to apps directory (default: ./apps)",
        )
        sync_group.add_argument(
            "--ko-types",
            type=str,
            nargs="+",
            default=[
                "macros",
                "tags",
                "eventtypes",
                "savedsearches",
                "workflow_actions",
                "transforms",
                "props",
                "lookups",
            ],
            help="Knowledge object types to sync",
        )
        sync_group.add_argument(
            "--savedsearches-allowlist",
            type=str,
            default=".*",
            help="Regex pattern for savedsearches filtering (default: .*)",
        )
        sync_group.add_argument(
            "--disable-rbac", action="store_true", help="Disable RBAC management"
        )
        sync_group.add_argument(
            "--batch-size",
            type=int,
            default=100,
            help="Batch size for operations (default: 100)",
        )
        sync_group.add_argument(
            "--concurrent-requests",
            type=int,
            default=5,
            help="Number of concurrent requests (default: 5)",
        )

        # Subcommands
        subparsers = parser.add_subparsers(
            dest="command", help="Available commands", title="Commands"
        )

        # Push command
        push_parser = subparsers.add_parser(
            "push", help="Push local changes to Splunk server"
        )
        push_parser.set_defaults(mode=SyncMode.PUSH)

        # Pull command
        pull_parser = subparsers.add_parser(
            "pull", help="Pull remote changes from Splunk server"
        )
        pull_parser.set_defaults(mode=SyncMode.PULL)

        # Sync command
        sync_parser = subparsers.add_parser(
            "sync", help="Bidirectional synchronization"
        )
        sync_parser.set_defaults(mode=SyncMode.SYNC)

        # Test connection command
        test_parser = subparsers.add_parser(
            "test-connection", help="Test connection to Splunk server"
        )
        test_parser.set_defaults(command="test-connection")

        # Server info command
        info_parser = subparsers.add_parser(
            "server-info", help="Get Splunk server information"
        )
        info_parser.set_defaults(command="server-info")

        # Generate config command
        config_parser = subparsers.add_parser(
            "generate-config", help="Generate sample configuration file"
        )
        config_parser.add_argument(
            "--output",
            "-o",
            type=str,
            default="splunk_sync.conf",
            help="Output file path (default: splunk_sync.conf)",
        )
        config_parser.set_defaults(command="generate-config")

        # Validate command
        validate_parser = subparsers.add_parser(
            "validate", help="Validate configuration and local files"
        )
        validate_parser.set_defaults(command="validate")

        return parser

    def run(self, args: Optional[List[str]] = None) -> int:
        """Run the CLI application."""
        parser = self.create_parser()
        parsed_args = parser.parse_args(args)

        # Configure logging early
        logging_manager.configure_logging(
            level=parsed_args.log_level,
            log_file=parsed_args.log_file,
            structured=parsed_args.structured_logging,
            debug=parsed_args.debug,
        )

        # Set up exception logging
        logging_manager.setup_exception_logging()

        # Log system information
        logging_manager.log_system_info()

        try:
            # Handle commands that don't require full configuration
            if parsed_args.command == "generate-config":
                return self._generate_config(parsed_args)

            # Load configuration
            self.config_manager.config_path = parsed_args.config
            config = self._build_config(parsed_args)

            # Log configuration (sanitized)
            logging_manager.log_configuration(config.__dict__)

            # Handle specific commands
            if parsed_args.command == "test-connection":
                return self._test_connection(config)
            elif parsed_args.command == "server-info":
                return self._server_info(config)
            elif parsed_args.command == "validate":
                return self._validate(config)
            elif hasattr(parsed_args, "mode"):
                return self._sync(config, parsed_args.mode)
            else:
                parser.print_help()
                return 1

        except KeyboardInterrupt:
            logger.info("Operation cancelled by user")
            return 130
        except ConfigurationError as e:
            logger.error(f"Configuration error: {e}")
            return 2
        except SplunkSyncError as e:
            logger.error(f"Synchronization error: {e}")
            return 3
        except Exception as e:
            logger.exception(f"Unexpected error: {e}")
            return 1

    def _build_config(self, args) -> "SyncConfig":
        """Build configuration from arguments and config file."""
        from .config import (KnowledgeObjectConfig, ProxyConfig,
                             SplunkConnectionConfig)

        # Start with base config
        try:
            config = self.config_manager.load_config()
        except Exception as e:
            logger.warning(f"Failed to load config file: {e}, using defaults")
            config = SyncConfig(
                splunk=SplunkConnectionConfig(host="localhost"),
                proxy=ProxyConfig(),
                knowledge_objects=KnowledgeObjectConfig(),
            )

        # Override with command line arguments
        if args.host:
            config.splunk.host = args.host
        if args.port:
            config.splunk.port = args.port
        if args.scheme:
            config.splunk.scheme = args.scheme
        if args.username:
            config.splunk.username = args.username
        if args.password:
            config.splunk.password = args.password
        if args.token:
            config.splunk.token = args.token
        if args.app:
            config.splunk.app = args.app
            config.target_app = args.app
        if hasattr(args, "verify_ssl"):
            config.splunk.verify_ssl = args.verify_ssl

        # Sync options
        if args.apps_path:
            config.apps_path = args.apps_path
        if args.ko_types:
            config.knowledge_objects.types = args.ko_types
        if args.savedsearches_allowlist:
            config.knowledge_objects.savedsearches_allowlist = (
                args.savedsearches_allowlist
            )
        if args.disable_rbac:
            config.knowledge_objects.rbac_enabled = False
        if args.batch_size:
            config.batch_size = args.batch_size
        if args.concurrent_requests:
            config.concurrent_requests = args.concurrent_requests

        # Mode and other options
        if hasattr(args, "mode"):
            config.mode = args.mode
        if args.dry_run:
            config.dry_run = True
        if args.debug:
            config.debug = True
        if args.log_level:
            config.log_level = args.log_level
        if args.log_file:
            config.log_file = args.log_file

        return config

    def _sync(self, config, mode: SyncMode) -> int:
        """Perform synchronization."""
        logger.info(f"Starting synchronization in {mode.value} mode")

        with SplunkSynchronizer(config) as synchronizer:
            # Validate configuration
            issues = synchronizer.validate_configuration()
            if issues:
                logger.error("Configuration validation failed:")
                for issue in issues:
                    logger.error(f"  - {issue}")
                return 2

            # Perform sync
            result = synchronizer.sync()

            # Print results
            self._print_sync_results(result)

            return 0 if result.success else 1

    def _test_connection(self, config) -> int:
        """Test connection to Splunk server."""
        logger.info("Testing connection to Splunk server...")

        with SplunkSynchronizer(config) as synchronizer:
            if synchronizer.test_connection():
                logger.info("Connection test successful!")
                return 0
            else:
                logger.error("Connection test failed!")
                return 1

    def _server_info(self, config) -> int:
        """Get server information."""
        logger.info("Retrieving server information...")

        with SplunkSynchronizer(config) as synchronizer:
            try:
                info = synchronizer.get_server_info()
                self._print_server_info(info)
                return 0
            except Exception as e:
                logger.error(f"Failed to get server info: {e}")
                return 1

    def _validate(self, config) -> int:
        """Validate configuration and local files."""
        logger.info("Validating configuration...")

        # Validate configuration
        issues = self.config_manager.validate_config(config)
        if issues:
            logger.error("Configuration validation failed:")
            for issue in issues:
                logger.error(f"  - {issue}")
            return 2

        # Validate with synchronizer
        with SplunkSynchronizer(config) as synchronizer:
            sync_issues = synchronizer.validate_configuration()
            if sync_issues:
                logger.error("Synchronization validation failed:")
                for issue in sync_issues:
                    logger.error(f"  - {issue}")
                return 2

        logger.info("Configuration validation successful!")
        return 0

    def _generate_config(self, args) -> int:
        """Generate sample configuration file."""
        try:
            output_path = args.output
            self.config_manager.create_sample_config(output_path)
            print(f"Sample configuration created at: {output_path}")
            return 0
        except Exception as e:
            logger.error(f"Failed to generate config: {e}")
            return 1

    def _print_sync_results(self, result):
        """Print synchronization results."""
        stats = result.statistics

        print("\n" + "=" * 60)
        print("SYNCHRONIZATION RESULTS")
        print("=" * 60)
        print(f"Total objects processed: {stats.total_objects}")
        print(f"Created: {stats.created}")
        print(f"Updated: {stats.updated}")
        print(f"Deleted: {stats.deleted}")
        print(f"Skipped: {stats.skipped}")
        print(f"Errors: {stats.errors}")
        print(f"Duration: {stats.duration:.2f}s")
        print(
            f"Success rate: {stats.total_objects - stats.errors}/{stats.total_objects} "
            f"({((stats.total_objects - stats.errors) / max(stats.total_objects, 1) * 100):.1f}%)"
        )

        if result.warnings:
            print(f"\nWarnings ({len(result.warnings)}):")
            for warning in result.warnings:
                print(f"  - {warning}")

        if result.errors:
            print(f"\nErrors ({len(result.errors)}):")
            for error in result.errors:
                print(f"  - {error}")

        status = "SUCCESS" if result.success else "FAILED"
        print(f"\nStatus: {status}")
        print("=" * 60)

    def _print_server_info(self, info: Dict[str, Any]):
        """Print server information."""
        print("\n" + "=" * 60)
        print("SPLUNK SERVER INFORMATION")
        print("=" * 60)
        print(f"Version: {info.get('version', 'unknown')}")
        print(f"Build: {info.get('build', 'unknown')}")
        print(f"Server Name: {info.get('server_name', 'unknown')}")
        print(f"License State: {info.get('license_state', 'unknown')}")
        print(f"License Labels: {', '.join(info.get('license_labels', []))}")
        print(f"Max Users: {info.get('max_users', 'unknown')}")
        print(f"CPU Architecture: {info.get('cpu_arch', 'unknown')}")
        print(f"OS: {info.get('os_name', 'unknown')} {info.get('os_version', '')}")
        print("=" * 60)


def main():
    """Main entry point."""
    cli = SplunkSyncCLI()
    sys.exit(cli.run())


if __name__ == "__main__":
    main()
