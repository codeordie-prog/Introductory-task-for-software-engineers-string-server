"""
Test suite for exception handling in the configuration module.

This module contains tests that verify the configuration module's behavior when encountering
various error conditions and exceptions. It tests the robustness of the configuration
loading and validation by simulating different failure scenarios.

The tests cover:
- JSON decode errors
- Missing configuration files
- Invalid configuration types
- Missing SSL certificates
- Invalid SSL paths
- Invalid configuration values

Each test is designed to be isolated and includes proper cleanup of test resources.
The tests use pytest fixtures for resource management and unittest.mock for
simulating file operations.

Example:
    To run all tests:
        pytest testsuite/test_exception_handling_config.py -v

    To run a specific test:
        pytest testsuite/test_exception_handling_config.py::test_json_decode_error -v
"""

from typing import Dict, Any
import pytest
import json
from unittest.mock import patch, mock_open
from config import load_server_configurations, DEFAULT_CONFIGURATIONS


@pytest.fixture
def mock_logger():
    """Fixture to mock the logger to prevent actual logging during tests."""
    with patch('config.Logger') as mock:
        yield mock


def test_json_decode_error(mock_logger: None) -> None:
    """
    Test handling of malformed JSON in configuration file.

    Verifies that the function falls back to default configurations when
    encountering a JSONDecodeError.

    Args:
        mock_logger: Mocked logger instance
    """
    with patch('builtins.open', mock_open(read_data='invalid json')):
        config: Dict[str, Any] = load_server_configurations()
        assert config == DEFAULT_CONFIGURATIONS


def test_missing_config_file(mock_logger: None) -> None:
    """
    Test handling of missing configuration file.

    Verifies that the function uses default configurations when
    the configuration file doesn't exist.

    Args:
        mock_logger: Mocked logger instance
    """
    with patch('os.path.exists', return_value=False):
        config: Dict[str, Any] = load_server_configurations()
        assert config == DEFAULT_CONFIGURATIONS


def test_invalid_config_type(mock_logger: None) -> None:
    """
    Test handling of invalid configuration value types.

    Verifies that the function falls back to default value when
    encountering an invalid type for a configuration key.

    Args:
        mock_logger: Mocked logger instance
    """
    invalid_config: Dict[str, Any] = {
        "port": "invalid_port",  # Should be int
        "workers": "invalid_workers"  # Should be int
    }
    with patch('os.path.exists', return_value=True), \
         patch('builtins.open', mock_open(read_data=json.dumps(invalid_config))):
        config: Dict[str, Any] = load_server_configurations()
        assert isinstance(config["port"], int)
        assert isinstance(config["workers"], int)
        assert config["port"] == DEFAULT_CONFIGURATIONS["port"]
        assert config["workers"] == DEFAULT_CONFIGURATIONS["workers"]


def test_missing_ssl_certificates(mock_logger: None) -> None:
    """
    Test handling of missing SSL certificates.

    Verifies that SSL is disabled when certificate files don't exist.

    Args:
        mock_logger: Mocked logger instance
    """
    config_with_ssl: Dict[str, Any] = {
        "ssl_enabled": True,
        "ssl_certificate": "nonexistent_cert.pem",
        "ssl_key": "nonexistent_key.pem"
    }
    with patch('os.path.exists', side_effect=lambda x: x not in ["nonexistent_cert.pem", "nonexistent_key.pem"]), \
         patch('builtins.open', mock_open(read_data=json.dumps(config_with_ssl))):
        config: Dict[str, Any] = load_server_configurations()
        assert not config["ssl_enabled"]
        assert config["ssl_certificate"] == DEFAULT_CONFIGURATIONS["ssl_certificate"]
        assert config["ssl_key"] == DEFAULT_CONFIGURATIONS["ssl_key"]


def test_invalid_ssl_paths(mock_logger: None) -> None:
    """
    Test handling of invalid SSL paths.

    Verifies that the function properly handles invalid SSL certificate paths
    and falls back to default values.

    Args:
        mock_logger: Mocked logger instance
    """
    config_with_invalid_ssl: Dict[str, Any] = {
        "ssl_enabled": True,
        "ssl_certificate": "",  # Empty path
        "ssl_key": None  # None path
    }
    with patch('os.path.exists', return_value=False), \
         patch('builtins.open', mock_open(read_data=json.dumps(config_with_invalid_ssl))):
        config: Dict[str, Any] = load_server_configurations()
        assert not config["ssl_enabled"]
        assert config["ssl_certificate"] == DEFAULT_CONFIGURATIONS["ssl_certificate"]
        assert config["ssl_key"] == DEFAULT_CONFIGURATIONS["ssl_key"]


def test_invalid_config_values(mock_logger: None) -> None:
    """
    Test handling of invalid configuration values.

    Verifies that the function properly handles invalid configuration values
    and falls back to default values.

    Args:
        mock_logger: Mocked logger instance
    """
    invalid_config: Dict[str, Any] = {
        "logging_level": 123,  # Should be string
        "reread_on_query": "true",  # Should be boolean
        "test_mode": "false"  # Should be boolean
    }
    with patch('os.path.exists', return_value=True), \
         patch('builtins.open', mock_open(read_data=json.dumps(invalid_config))):
        config: Dict[str, Any] = load_server_configurations()
        assert config["logging_level"] == DEFAULT_CONFIGURATIONS["logging_level"]
        assert config["reread_on_query"] == DEFAULT_CONFIGURATIONS["reread_on_query"]
        assert config["test_mode"] == DEFAULT_CONFIGURATIONS["test_mode"]
