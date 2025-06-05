"""Test suite for server configuration management.

This module contains tests for loading and validating server configurations,
including:
- Loading configurations from file
- Handling missing configuration files
- Default configuration fallback behavior
"""

from typing import Dict, Any
import os
import json
import tempfile
import pytest
from config import load_server_configurations, DEFAULT_CONFIGURATIONS


def test_load_server_configurations_from_file() -> None:
    """Test loading server configurations from a custom configuration file.
    
    This test verifies that:
    1. Custom configurations are properly loaded from file
    2. Default values are preserved for unspecified settings
    3. Configuration values are correctly typed
    """
    # Create a temporary config file with overrides
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path: str = os.path.join(tmpdir, "server_configurations.json")
        custom_config: Dict[str, Any] = {
            "port": 5555,
            "host": "127.0.0.1",
            "ssl_enabled": True
        }
        
        with open(config_path, "w") as f:
            json.dump(custom_config, f)

        # Load configurations using the test file path
        config: Dict[str, Any] = load_server_configurations(
            config_file_path=config_path
        )

        # Verify custom configurations are loaded
        assert config["port"] == 5555
        assert config["host"] == "127.0.0.1"
        assert config["ssl_enabled"] is True
        
        # Verify default values didn't change
        assert config["linuxpath"] == DEFAULT_CONFIGURATIONS["linuxpath"]


def test_load_server_configurations_missing_file(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test behavior when configuration file is missing.
    
    This test verifies that:
    1. The system gracefully handles missing configuration files
    2. Default configurations are returned when file is not found
    
    Args:
        monkeypatch: Pytest fixture for modifying Python objects
    """
    # Patch os.path.exists to simulate missing file
    monkeypatch.setattr(os.path, "exists", lambda path: False)

    # Attempt to load configurations from non-existent file
    config: Dict[str, Any] = load_server_configurations("nonexistent/path.json")

    # Verify default configurations are returned
    assert config == DEFAULT_CONFIGURATIONS


def test_load_server_configurations_invalid_json() -> None:
    """Test behavior when configuration file contains invalid JSON.
    
    This test verifies that:
    1. The system properly handles malformed JSON
    2. Default configurations are returned when JSON is invalid
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path: str = os.path.join(tmpdir, "invalid_config.json")
        with open(config_path, "w") as f:
            f.write("{invalid json content}")

        # Load configurations should fall back to defaults
        config: Dict[str, Any] = load_server_configurations(config_file_path=config_path)
        assert config == DEFAULT_CONFIGURATIONS


def test_load_server_configurations_invalid_types() -> None:
    """Test behavior when configuration file contains invalid value types.
    
    This test verifies that:
    1. The system properly handles invalid value types.
    2. Default configurations are preserved for invalid values.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path: str = os.path.join(tmpdir, "invalid_types.json")
        invalid_config: Dict[str, Any] = {
            "port": "not_a_number",  # Should be int
            "workers": "4",          # Should be int
            "ssl_enabled": "true"    # Should be bool
        }
        
        with open(config_path, "w") as f:
            json.dump(invalid_config, f)

        # Load configurations
        config: Dict[str, Any] = load_server_configurations(config_file_path=config_path)
        
        # Verify invalid values are ignored and defaults are used
        assert isinstance(config["port"], int)
        assert isinstance(config["workers"], int)
        assert isinstance(config["ssl_enabled"], bool)


def test_load_server_configurations_empty_file() -> None:
    """Test behavior when configuration file is empty.
    
    This test verifies that:
    1. The system properly handles empty configuration files
    2. Default configurations are returned when file is empty
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path: str = os.path.join(tmpdir, "empty_config.json")
        with open(config_path, "w") as f:
            f.write("{}")

        # Load configurations
        config: Dict[str, Any] = load_server_configurations(config_file_path=config_path)
        
        # Verify all values are from defaults
        assert config == DEFAULT_CONFIGURATIONS


def test_load_server_configurations_extra_fields() -> None:
    """Test behavior when configuration file contains extra fields.
    
    This test verifies that:
    1. The system properly handles additional configuration fields
    2. Extra fields are ignored and not included in final config
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path: str = os.path.join(tmpdir, "extra_fields.json")
        extra_config: Dict[str, Any] = {
            "port": 5555,
            "extra_field1": "value1",
            "extra_field2": 123,
            "unknown_setting": True
        }
        
        with open(config_path, "w") as f:
            json.dump(extra_config, f)

        # Load configurations
        config: Dict[str, Any] = load_server_configurations(config_file_path=config_path)
        
        # Verify extra fields are not included
        assert "extra_field1" not in config
        assert "extra_field2" not in config
        assert "unknown_setting" not in config
        assert config["port"] == 5555


def test_load_server_configurations_invalid_ssl_paths() -> None:
    """Test behavior when SSL certificate and key paths are invalid.
    
    This test verifies that:
    1. The system properly handles invalid SSL file paths
    2. SSL configuration is properly loaded even with invalid paths
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path: str = os.path.join(tmpdir, "invalid_ssl.json")
        ssl_config: Dict[str, Any] = {
            "ssl_enabled": True,
            "ssl_certificate": "/nonexistent/cert.pem",
            "ssl_key": "/nonexistent/key.pem"
        }
        
        with open(config_path, "w") as f:
            json.dump(ssl_config, f)

        # Load configurations
        config: Dict[str, Any] = load_server_configurations(config_file_path=config_path)
        
        # Verify SSL settings are loaded correctly
        assert config["ssl_enabled"] is False
        assert config["ssl_certificate"] == "config/cert.pem"
        assert config["ssl_key"] == "config/key.pem"
