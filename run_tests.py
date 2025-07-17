#!/usr/bin/env python3
"""
Test runner for Splunk Synchronization Tool.

This script provides a convenient way to run tests with different configurations
and options for development and CI/CD purposes.
"""

import sys
import argparse
import subprocess
from pathlib import Path


def run_command(cmd, description="Running command"):
    """Run a command and handle errors."""
    print(f"\n{'='*60}")
    print(f"{description}")
    print(f"Command: {' '.join(cmd)}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=False)
        print(f"✅ {description} completed successfully")
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed with exit code {e.returncode}")
        return False
    except FileNotFoundError:
        print(f"❌ Command not found: {cmd[0]}")
        return False


def main():
    """Main test runner function."""
    parser = argparse.ArgumentParser(
        description="Run tests for Splunk Synchronization Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_tests.py                    # Run all tests
  python run_tests.py --unit             # Run only unit tests
  python run_tests.py --integration      # Run only integration tests
  python run_tests.py --coverage         # Run with coverage report
  python run_tests.py --lint             # Run linting only
  python run_tests.py --format           # Format code only
  python run_tests.py --all              # Run all checks (tests, lint, format)
        """
    )
    
    # Test selection
    parser.add_argument(
        "--unit", action="store_true",
        help="Run unit tests only"
    )
    parser.add_argument(
        "--integration", action="store_true",
        help="Run integration tests only"
    )
    parser.add_argument(
        "--coverage", action="store_true",
        help="Run tests with coverage report"
    )
    parser.add_argument(
        "--no-cov", action="store_true",
        help="Run tests without coverage"
    )
    
    # Code quality
    parser.add_argument(
        "--lint", action="store_true",
        help="Run linting checks only"
    )
    parser.add_argument(
        "--format", action="store_true",
        help="Format code only"
    )
    parser.add_argument(
        "--type-check", action="store_true",
        help="Run type checking only"
    )
    
    # Combined options
    parser.add_argument(
        "--all", action="store_true",
        help="Run all checks (tests, lint, format, type check)"
    )
    parser.add_argument(
        "--quick", action="store_true",
        help="Run quick tests only (no coverage, no slow tests)"
    )
    
    # Test options
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--parallel", "-n", type=int, metavar="N",
        help="Run tests in parallel with N processes"
    )
    parser.add_argument(
        "--failfast", "-x", action="store_true",
        help="Stop on first failure"
    )
    parser.add_argument(
        "--pattern", "-k", type=str,
        help="Run tests matching pattern"
    )
    parser.add_argument(
        "--module", "-m", type=str,
        help="Run tests for specific module"
    )
    
    args = parser.parse_args()
    
    # Check if we're in the right directory
    if not Path("splunk_sync").exists():
        print("❌ Error: Run this script from the project root directory")
        return 1
    
    success = True
    
    if args.format or args.all:
        # Format code
        if not run_command(["black", "splunk_sync/", "tests/"], "Formatting code with black"):
            success = False
        
        if not run_command(["isort", "splunk_sync/", "tests/"], "Sorting imports with isort"):
            success = False
    
    if args.lint or args.all:
        # Run linting
        if not run_command(["flake8", "--max-line-length", "100", "splunk_sync/"], "Running flake8 linting"):
            success = False
    
    if args.type_check or args.all:
        # Run type checking
        if not run_command(["mypy", "splunk_sync/"], "Running mypy type checking"):
            success = False
    
    if not any([args.lint, args.format, args.type_check]) or args.all:
        # Build pytest command
        cmd = ["python", "-m", "pytest"]
        
        # Add test selection
        if args.unit:
            cmd.extend(["-m", "unit"])
        elif args.integration:
            cmd.extend(["-m", "integration"])
        elif args.quick:
            cmd.extend(["-m", "not slow"])
        
        # Add coverage options
        if args.coverage and not args.no_cov:
            cmd.extend([
                "--cov=splunk_sync",
                "--cov-report=html",
                "--cov-report=term-missing"
            ])
        elif args.no_cov:
            cmd.append("--no-cov")
        
        # Add parallel execution
        if args.parallel:
            cmd.extend(["-n", str(args.parallel)])
        
        # Add other options
        if args.verbose:
            cmd.append("-v")
        
        if args.failfast:
            cmd.append("-x")
        
        if args.pattern:
            cmd.extend(["-k", args.pattern])
        
        if args.module:
            cmd.append(f"tests/test_{args.module}.py")
        
        # Run tests
        if not run_command(cmd, "Running tests"):
            success = False
    
    # Summary
    print(f"\n{'='*60}")
    if success:
        print("✅ All checks passed!")
        return 0
    else:
        print("❌ Some checks failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
