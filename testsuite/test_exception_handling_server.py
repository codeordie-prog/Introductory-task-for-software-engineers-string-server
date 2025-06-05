"""
Test suite for exception handling in the server implementation.

This module contains tests that verify the server's behavior when encountering various
error conditions and exceptions. It tests the robustness of the server implementation
by simulating different failure scenarios.

The tests cover:
- File system errors (FileNotFoundError, PermissionError, OSError)
- Network operations (socket.timeout, ConnectionError)
- SSL/TLS operations (SSLError)
- Shared memory operations (MemoryError, RuntimeError)
- Client communication (ValueError, OSError)
- Background monitoring (FileNotFoundError)

Each test is designed to be isolated and includes proper cleanup of test resources.
The tests use pytest fixtures for resource management and unittest.mock for
simulating system calls and file operations.

Example:
    To run all tests:
        pytest testsuite/test_exception_handling_server.py -v

    To run a specific test:
        pytest testsuite/test_exception_handling_server.py::test_file_not_found_exception_get_hashed_values -v
"""

from typing import Dict, Any, Optional, Tuple
import pytest
import socket
import ssl
from unittest.mock import patch, MagicMock
from server import Server, BackgroundFileMonitor
from logger_setup import Logger


# Test configuration
test_config: Dict[str, Any] = {
    'host': 'localhost',
    'port': 9999,
    'ssl_enabled': True,
    'ssl_certificate': 'test_cert.pem',
    'ssl_key': 'test_key.pem',
    'ssl_ca_certificate': 'test_ca.pem',
    'ssl_client_auth': True,
    'ssl_verify_mode': 'CERT_REQUIRED',
    'reread_on_query': True
}


@pytest.fixture
def server() -> Server:
    """
    Fixture to create server instance.

    Returns:
        Server: A new server instance for testing
    """
    return Server()


@pytest.fixture
def mock_connection() -> MagicMock:
    """
    Fixture to create a mock connection.

    Returns:
        MagicMock: A mock connection object for testing
    """
    return MagicMock()


def test_file_not_found_exception_get_hashed_values(server: Server) -> None:
    """
    Test FileNotFoundError handling in get_hashed_values.

    Verifies that the server returns None when attempting to access a non-existent file.

    Args:
        server: Server instance to test
    """
    results: Optional[Dict[str, Any]] = server.get_hashed_values(file_path="nonexistent_file.txt")
    assert results is None


def test_permission_error_get_hashed_values(server: Server) -> None:
    """
    Test PermissionError handling in get_hashed_values.

    Verifies that the server returns None when encountering permission errors.

    Args:
        server: Server instance to test
    """
    with patch('os.path.exists', return_value=True), \
         patch('server.remove_duplicates', side_effect=PermissionError):
        results: Optional[Dict[str, Any]] = server.get_hashed_values(file_path="test_file.txt")
        assert results is None


def test_os_error_get_hashed_values(server: Server) -> None:
    """
    Test OSError handling in get_hashed_values.

    Verifies that the server returns None when encountering OS errors.

    Args:
        server: Server instance to test
    """
    with patch('os.path.exists', return_value=True), \
         patch('server.remove_duplicates', side_effect=OSError):
        results: Optional[Dict[str, Any]] = server.get_hashed_values(file_path="test_file.txt")
        assert results is None


def test_value_error_get_hashed_values(server: Server) -> None:
    """
    Test ValueError handling in get_hashed_values.

    Verifies that the server returns None when encountering value errors.

    Args:
        server: Server instance to test
    """
    with patch('os.path.exists', return_value=True), \
         patch('server.remove_duplicates', return_value=set()), \
         patch('server.hash_file', side_effect=ValueError):
        results: Optional[Dict[str, Any]] = server.get_hashed_values(file_path="test_file.txt")
        assert results is None


def test_socket_timeout_handle_client(server: Server, mock_connection: MagicMock) -> None:
    """
    Test socket timeout handling in handle_client.

    Verifies that the server properly handles socket timeouts.

    Args:
        server: Server instance to test
        mock_connection: Mock connection object
    """
    mock_connection.recv.side_effect = socket.timeout
    with pytest.raises(socket.timeout):
        server.handle_client(mock_connection, ('localhost', 9999))


def test_connection_error_handle_client(server: Server, mock_connection: MagicMock) -> None:
    """
    Test ConnectionError handling in handle_client.

    Verifies that the server properly handles connection errors.

    Args:
        server: Server instance to test
        mock_connection: Mock connection object
    """
    mock_connection.sendall.side_effect = socket.error
    with pytest.raises(ConnectionError):
        server.handle_client(mock_connection, ('localhost', 9999))


def test_ssl_error_handle_client(server: Server, mock_connection: MagicMock) -> None:
    """
    Test SSL error handling in handle_client.

    Verifies that the server properly handles SSL errors and closes the connection.

    Args:
        server: Server instance to test
        mock_connection: Mock connection object
    """
    mock_connection.unwrap.side_effect = ssl.SSLError
    try:
        server.handle_client(mock_connection, ('localhost', 9999), ssl_enabled=True)
    except ssl.SSLError:
        pass
    mock_connection.close.assert_called_once()


def test_value_error_handle_client(server: Server, mock_connection: MagicMock) -> None:
    """
    Test ValueError handling in handle_client.

    Verifies that the server properly handles invalid UTF-8 data.

    Args:
        server: Server instance to test
        mock_connection: Mock connection object
    """
    mock_connection.recv.return_value = b'\xff\xfe'  # Invalid UTF-8
    with pytest.raises(ValueError):
        server.handle_client(mock_connection, ('localhost', 9999))


def test_os_error_handle_client(server: Server, mock_connection: MagicMock) -> None:
    """
    Test OSError handling in handle_client.

    Verifies that the server properly handles OS errors during client communication.

    Args:
        server: Server instance to test
        mock_connection: Mock connection object
    """
    mock_connection.recv.side_effect = OSError
    with pytest.raises(OSError):
        server.handle_client(mock_connection, ('localhost', 9999))


def test_file_not_found_reload_shared_memory(server: Server) -> None:
    """
    Test FileNotFoundError handling in reload_shared_memory.

    Verifies that the server properly handles missing shared memory files.

    Args:
        server: Server instance to test
    """
    with patch('multiprocessing.shared_memory.SharedMemory', side_effect=FileNotFoundError):
        with pytest.raises(OSError):
            server.reload_shared_memory()


def test_memory_error_reload_shared_memory(server: Server) -> None:
    """
    Test MemoryError handling in reload_shared_memory.

    Verifies that the server properly handles memory allocation errors.

    Args:
        server: Server instance to test
    """
    with patch('multiprocessing.shared_memory.SharedMemory', side_effect=MemoryError):
        with pytest.raises(MemoryError):
            server.reload_shared_memory()


def test_runtime_error_reload_shared_memory(server: Server) -> None:
    """
    Test RuntimeError handling in reload_shared_memory.

    Verifies that the server properly handles runtime errors during shared memory operations.

    Args:
        server: Server instance to test
    """
    with patch('multiprocessing.shared_memory.SharedMemory', side_effect=RuntimeError):
        with pytest.raises(RuntimeError):
            server.reload_shared_memory()


def test_file_not_found_background_monitor(server: Server) -> None:
    """
    Test FileNotFoundError handling in BackgroundFileMonitor.

    Verifies that the background monitor properly handles missing files.

    Args:
        server: Server instance to test
    """
    monitor: BackgroundFileMonitor = BackgroundFileMonitor(server, "nonexistent_file.txt")
    with pytest.raises(FileNotFoundError):
        monitor.run_monitor()


def test_ssl_certificate_verification_failure(server: Server, mock_connection: MagicMock) -> None:
    """
    Test SSL certificate verification failure handling.

    Verifies that the server properly handles SSL certificate verification failures
    and closes the connection.

    Args:
        server: Server instance to test
        mock_connection: Mock connection object
    """
    mock_connection.getpeercert.side_effect = ssl.SSLError
    try:
        server.handle_client(mock_connection, ('localhost', 9999), ssl_enabled=True)
    except ssl.SSLError:
        pass
    mock_connection.close.assert_called_once()
