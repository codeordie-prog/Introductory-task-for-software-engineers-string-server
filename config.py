"""Configuration module for server settings and defaults.

This module handles loading and managing server configurations, including
default configuration values and file-based configuration loading.
"""

from __future__ import annotations

import json
import os
from typing import Dict, Any, TypedDict
from json.decoder import JSONDecodeError

from logger_setup import Logger


class ServerConfig(TypedDict):
    """Type definition for server configuration dictionary."""
    linuxpath: str
    host: str
    port: int
    logging_level: str
    workers: int
    reread_on_query: bool
    ssl_enabled: bool
    ssl_certificate: str
    ssl_key: str
    ssl_client_auth: bool
    ssl_ca_certificate: str
    ssl_verify_mode: str
    ssl_ciphers: str
    test_mode: bool


# Default configurations in case the configuration file is not provided.
DEFAULT_CONFIGURATIONS: ServerConfig = {
    "linuxpath": "Strings/200k.txt",
    "host": "127.0.0.1",
    "port": 5555,
    "logging_level": "DEBUG",
    "workers": 4,
    "reread_on_query": False,
    "ssl_enabled": False,
    "ssl_certificate": "config/cert.pem",
    "ssl_key": "config/key.pem",
    "ssl_client_auth":True,
    "ssl_ca_certificate":"config/ca.pem",
    "ssl_verify_mode":"CERT_REQUIRED",
    "ssl_ciphers":"ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS",
    "test_mode": False
}


def load_server_configurations(
    config_file_path: str = "config/server_configurations.json"
) -> ServerConfig:
    """Load server configurations from specified configuration file or use default configurations.

    Args:
        config_file_path: Path to the configuration file.

    Returns:
        Server configuration dictionary containing:
            - linuxpath: Path to the strings file
            - host: Server host specification
            - port: Server port specification
            - logging_level: Logging level, defaults to "DEBUG" level
            - workers: Number of multiprocessing workers
            - ssl_enabled: Whether SSL authentication is enabled
            - ssl_certificate: Path to SSL certificate
            - ssl_key: Path to SSL key
            - reread_on_query: Whether to reload strings file on query
            - test_mode: Whether server is running in test mode
    """
    # Set up the logger.
    logger: Logger = Logger()
    
    # Get the root directory.
    root_dir: str = os.path.dirname(os.path.abspath(__file__))
    # Setup the absolute path for the configuration file.
    configuration_file_path: str = os.path.join(root_dir, config_file_path)

    # Load configuration file if it is provided, else use default configurations.
    server_configurations: Dict[str, Any] = {}
    if os.path.exists(configuration_file_path):
        try:
            with open(configuration_file_path, "r") as f:
                server_configurations = json.load(f)
        except JSONDecodeError:
            logger.warning(f"Malformed JSON in configuration file : {configuration_file_path}. Falling back to defaults.")
    else:
        # Alert warning about the missing configuration file.  
        logger.warning(
            f"Warning: Configuration file was not found at {configuration_file_path}, "
            "currently using DEFAULT CONFIGS"
        )

    # Type-check all entries.
    config: ServerConfig = DEFAULT_CONFIGURATIONS.copy()

    # Only apply known keys
    for key in DEFAULT_CONFIGURATIONS:
        if key in server_configurations:
            config[key] = server_configurations[key]

    # Validate types
    for key, default_value in DEFAULT_CONFIGURATIONS.items():
        if not isinstance(config[key], type(default_value)):
            logger.warning(
                f"Ignoring invalid type for key '{key}' : {config[key]} (expected {type(default_value).__name__})"
            )
            config[key] = default_value

    # validate SSL key and certificate paths
    for key, _ in config.items():
        if not os.path.exists(config["ssl_certificate"]) or not os.path.exists(config["ssl_key"]):
            # set SSL authentication to False.
            config["ssl_enabled"] = False
            config["ssl_certificate"] = DEFAULT_CONFIGURATIONS['ssl_certificate']
            config["ssl_key"] = DEFAULT_CONFIGURATIONS["ssl_key"]

    return config


