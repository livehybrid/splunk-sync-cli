"""
Main entry point for splunk_sync package.

This allows the package to be run as a module:
python -m splunk_sync
"""

from .cli import main

if __name__ == "__main__":
    main()
