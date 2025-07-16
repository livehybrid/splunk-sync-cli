#!/usr/bin/env python3
"""
Splunk Synchronization Tool

A modern, production-ready tool for synchronizing Splunk knowledge objects
between Git repositories and Splunk servers.

This replaces the original Git2Splunk.py with a completely refactored,
modular architecture that follows modern Python best practices.

Key Features:
- Modular architecture with proper separation of concerns
- Comprehensive error handling and logging
- Support for filtering with regex patterns (savedsearches allowlist)
- RBAC management with proper permission handling
- Dry-run mode for safe testing
- Structured logging with JSON output support
- Type hints throughout for better code quality
- Configuration management with validation
- Modern CLI with rich help and argument parsing

Usage:
    python splunk-sync.py push --host splunk.example.com --token mytoken
    python splunk-sync.py pull --config config.conf --dry-run
    python splunk-sync.py sync --debug --savedsearches-allowlist "Alert.*"
"""

import sys
from pathlib import Path

# Add the splunk_sync package to path
sys.path.insert(0, str(Path(__file__).parent))

from splunk_sync.cli import main

if __name__ == "__main__":
    main()