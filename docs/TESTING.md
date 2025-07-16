# Testing Documentation

This document describes the testing strategy, test structure, and how to run tests for the Splunk Synchronization Tool.

## Test Structure

### Test Organization
```
tests/
├── __init__.py                 # Test package initialization
├── conftest.py                 # Pytest fixtures and configuration
├── test_config.py              # Configuration management tests
├── test_client.py              # Splunk client tests
├── test_knowledge_objects.py   # Knowledge object tests
├── test_rbac.py                # RBAC management tests
├── test_sync.py                # Synchronization logic tests
├── test_cli.py                 # CLI interface tests
├── test_logging.py             # Logging system tests
├── test_exceptions.py          # Exception handling tests
├── integration/                # Integration tests
│   ├── __init__.py
│   ├── test_end_to_end.py     # End-to-end workflow tests
│   └── test_splunk_integration.py
└── fixtures/                   # Test data and fixtures
    ├── sample_configs/
    ├── sample_apps/
    └── mock_responses/
```

### Test Categories

#### Unit Tests
- **Purpose**: Test individual components in isolation
- **Scope**: Single functions, methods, or classes
- **Mock Dependencies**: All external dependencies are mocked
- **Speed**: Fast execution (< 1 second per test)
- **Coverage**: High coverage of edge cases and error conditions

#### Integration Tests
- **Purpose**: Test component interactions
- **Scope**: Multiple components working together
- **Mock Dependencies**: Minimal mocking, real component integration
- **Speed**: Moderate execution (1-10 seconds per test)
- **Coverage**: Happy path and common error scenarios

#### End-to-End Tests
- **Purpose**: Test complete workflows
- **Scope**: Full application functionality
- **Mock Dependencies**: External services mocked (Splunk API)
- **Speed**: Slower execution (10+ seconds per test)
- **Coverage**: User scenarios and business logic

## Running Tests

### Prerequisites
```bash
# Install development dependencies
pip install -r requirements-dev.txt
```

### Basic Test Execution
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=splunk_sync

# Run specific test file
pytest tests/test_config.py

# Run specific test class
pytest tests/test_config.py::TestConfigManager

# Run specific test method
pytest tests/test_config.py::TestConfigManager::test_load_config
```

### Using the Test Runner
```bash
# Run all tests with coverage
python run_tests.py --coverage

# Run only unit tests
python run_tests.py --unit

# Run only integration tests
python run_tests.py --integration

# Run tests in parallel
python run_tests.py --parallel 4

# Run quick tests (no coverage, no slow tests)
python run_tests.py --quick

# Run all checks (tests, lint, format, type check)
python run_tests.py --all
```

### Test Markers

Tests are marked with pytest markers for categorization:

```python
import pytest

@pytest.mark.unit
def test_unit_functionality():
    """Unit test example."""
    pass

@pytest.mark.integration
def test_integration_functionality():
    """Integration test example."""
    pass

@pytest.mark.slow
def test_slow_functionality():
    """Slow test example."""
    pass

@pytest.mark.network
def test_network_functionality():
    """Test requiring network access."""
    pass
```

### Running Specific Test Categories
```bash
# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration

# Skip slow tests
pytest -m "not slow"

# Run network tests only
pytest -m network
```

## Test Fixtures

### Common Fixtures (conftest.py)

#### Configuration Fixtures
- `sample_config_data`: Dictionary with sample configuration
- `splunk_connection_config`: SplunkConnectionConfig instance
- `proxy_config`: ProxyConfig instance
- `knowledge_object_config`: KnowledgeObjectConfig instance
- `sync_config`: Complete SyncConfig instance

#### Data Fixtures
- `sample_knowledge_object`: Sample KnowledgeObject for macros
- `sample_savedsearch`: Sample savedsearch KnowledgeObject
- `sample_eventtype`: Sample eventtype KnowledgeObject
- `sample_acl`: Sample ACL object

#### Mock Fixtures
- `mock_splunk_service`: Mock Splunk service
- `mock_splunk_conf`: Mock Splunk configuration object
- `mock_config_file`: Temporary configuration file
- `mock_apps_directory`: Mock apps directory structure
- `mock_environment_variables`: Mock environment variables

#### File System Fixtures
- `temp_dir`: Temporary directory for test files
- `mock_apps_directory`: Complete mock apps structure

### Using Fixtures

```python
def test_config_loading(mock_config_file):
    """Test loading configuration from file."""
    manager = ConfigManager(str(mock_config_file))
    config = manager.load_config()
    assert config.splunk.host == "localhost"

def test_knowledge_object_validation(sample_knowledge_object):
    """Test knowledge object validation."""
    config = KnowledgeObjectConfig()
    manager = KnowledgeObjectManager(config)
    issues = manager.validate_object(sample_knowledge_object)
    assert issues == []
```

## Test Writing Guidelines

### Test Naming
- Use descriptive test names: `test_<functionality>_<scenario>`
- Include expected outcome: `test_load_config_success`, `test_load_config_file_not_found`
- Group related tests in classes: `TestConfigManager`, `TestSplunkClient`

### Test Structure
```python
def test_function_name():
    """Test description explaining what is being tested."""
    # Arrange - Set up test data and mocks
    config = SplunkConnectionConfig(host="localhost", token="test-token")
    
    # Act - Execute the functionality being tested
    result = some_function(config)
    
    # Assert - Verify the expected outcome
    assert result.success is True
    assert result.message == "Expected message"
```

### Mocking Best Practices

#### Use Patch Decorators
```python
@patch('splunk_sync.client.connect')
def test_client_connection(mock_connect):
    """Test client connection with mocked Splunk SDK."""
    mock_service = Mock()
    mock_connect.return_value = mock_service
    
    client = SplunkClient(config)
    client.connect()
    
    mock_connect.assert_called_once()
```

#### Use Context Managers
```python
def test_client_connection():
    """Test client connection with context manager."""
    with patch('splunk_sync.client.connect') as mock_connect:
        mock_service = Mock()
        mock_connect.return_value = mock_service
        
        client = SplunkClient(config)
        client.connect()
        
        mock_connect.assert_called_once()
```

#### Mock External Dependencies
```python
def test_file_operations(temp_dir):
    """Test file operations with temporary directory."""
    test_file = temp_dir / "test.conf"
    
    with patch('splunk_sync.knowledge_objects.configparser.RawConfigParser') as mock_parser:
        mock_config = Mock()
        mock_parser.return_value = mock_config
        
        manager = KnowledgeObjectManager(config)
        manager.save_to_file(objects, test_file, "macros")
        
        mock_config.write.assert_called_once()
```

### Exception Testing
```python
def test_function_with_exception():
    """Test function behavior when exception occurs."""
    with pytest.raises(SpecificException, match="Expected error message"):
        function_that_should_raise_exception()

def test_function_with_logged_exception(caplog):
    """Test function that logs exceptions."""
    with caplog.at_level(logging.ERROR):
        function_that_logs_error()
    
    assert "Expected error message" in caplog.text
```

### Parameterized Tests
```python
@pytest.mark.parametrize("input_value,expected_output", [
    ("true", True),
    ("false", False),
    ("1", 1),
    ("3.14", 3.14),
    ("hello", "hello")
])
def test_value_conversion(input_value, expected_output):
    """Test value conversion with different input types."""
    manager = ConfigManager()
    result = manager._convert_value(input_value)
    assert result == expected_output
```

## Test Data Management

### Sample Configuration Files
```python
# In conftest.py
@pytest.fixture
def sample_config_content():
    return """
[splunk]
host = localhost
port = 8089
token = test-token

[knowledge_objects]
types = macros,savedsearches
savedsearches_allowlist = .*
"""
```

### Mock Responses
```python
# Mock Splunk API responses
@pytest.fixture
def mock_knowledge_objects_response():
    return [
        {
            "name": "test_macro",
            "content": {"definition": "index=main"},
            "access": {
                "owner": "admin",
                "app": "search",
                "sharing": "app"
            }
        }
    ]
```

### Test Utilities
```python
# In conftest.py
def create_mock_stanza(name, content, access=None):
    """Create a mock Splunk stanza object."""
    stanza = Mock()
    stanza.name = name
    stanza.content = content
    # ... setup mock attributes
    return stanza
```

## Coverage Requirements

### Coverage Targets
- **Overall Coverage**: 80% minimum
- **Unit Tests**: 90% minimum
- **Integration Tests**: 70% minimum
- **Critical Paths**: 95% minimum (authentication, sync operations)

### Coverage Reporting
```bash
# Generate HTML coverage report
pytest --cov=splunk_sync --cov-report=html

# Generate XML coverage report (for CI/CD)
pytest --cov=splunk_sync --cov-report=xml

# View coverage in terminal
pytest --cov=splunk_sync --cov-report=term-missing
```

### Coverage Configuration
```ini
# In pytest.ini
[tool:pytest]
addopts = 
    --cov=splunk_sync
    --cov-report=html
    --cov-report=term-missing
    --cov-fail-under=80
```

## Continuous Integration

### GitHub Actions Example
```yaml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.7, 3.8, 3.9, '3.10']
    
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v2
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        pip install -r requirements-dev.txt
    
    - name: Run tests
      run: |
        python run_tests.py --all
    
    - name: Upload coverage
      uses: codecov/codecov-action@v1
```

### Pre-commit Hooks
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/psf/black
    rev: 22.3.0
    hooks:
      - id: black
        language_version: python3
  
  - repo: https://github.com/pycqa/isort
    rev: 5.10.1
    hooks:
      - id: isort
  
  - repo: https://github.com/pycqa/flake8
    rev: 4.0.1
    hooks:
      - id: flake8
  
  - repo: local
    hooks:
      - id: pytest
        name: pytest
        entry: python run_tests.py --quick
        language: system
        pass_filenames: false
```

## Performance Testing

### Benchmarking
```python
import time
import pytest

@pytest.mark.slow
def test_sync_performance():
    """Test synchronization performance with large datasets."""
    start_time = time.time()
    
    # Perform sync operation
    result = synchronizer.sync()
    
    end_time = time.time()
    duration = end_time - start_time
    
    assert result.success
    assert duration < 60  # Should complete within 60 seconds
```

### Memory Usage Testing
```python
import psutil
import os

def test_memory_usage():
    """Test memory usage during sync operations."""
    process = psutil.Process(os.getpid())
    initial_memory = process.memory_info().rss
    
    # Perform memory-intensive operation
    synchronizer.sync()
    
    final_memory = process.memory_info().rss
    memory_increase = final_memory - initial_memory
    
    # Should not increase memory by more than 100MB
    assert memory_increase < 100 * 1024 * 1024
```

## Debugging Tests

### Running Single Tests
```bash
# Run single test with verbose output
pytest -v tests/test_config.py::TestConfigManager::test_load_config

# Run with pdb debugger
pytest --pdb tests/test_config.py::TestConfigManager::test_load_config

# Run with capture disabled (see print statements)
pytest -s tests/test_config.py::TestConfigManager::test_load_config
```

### Logging in Tests
```python
import logging

def test_with_logging(caplog):
    """Test that captures log output."""
    with caplog.at_level(logging.INFO):
        function_that_logs()
    
    assert "Expected log message" in caplog.text
    assert caplog.records[0].levelname == "INFO"
```

### Using pytest-xdist for Parallel Testing
```bash
# Run tests in parallel with 4 processes
pytest -n 4

# Run tests in parallel with auto-detection
pytest -n auto
```

## Best Practices Summary

1. **Write tests first** (TDD approach when possible)
2. **Test behavior, not implementation** 
3. **Use descriptive test names** that explain the scenario
4. **Mock external dependencies** to isolate units under test
5. **Test edge cases and error conditions**
6. **Keep tests simple and focused**
7. **Use fixtures** to reduce code duplication
8. **Maintain high test coverage** but focus on quality over quantity
9. **Run tests frequently** during development
10. **Use CI/CD** to run tests automatically on all changes

## Troubleshooting

### Common Issues

#### Import Errors
```bash
# Make sure package is installed in development mode
pip install -e .

# Or add to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:/path/to/project"
```

#### Mock Issues
```python
# Use patch.object for cleaner mocking
with patch.object(SplunkClient, 'connect') as mock_connect:
    # Test code
    pass
```

#### Fixture Scope Issues
```python
# Use appropriate fixture scope
@pytest.fixture(scope="session")  # Once per test session
@pytest.fixture(scope="module")   # Once per test module
@pytest.fixture(scope="function") # Once per test function (default)
```

### Getting Help
- Check pytest documentation: https://docs.pytest.org/
- Review existing tests for patterns
- Use `pytest --help` for command options
- Enable verbose mode with `-v` for detailed output