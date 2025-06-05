"""Test suite for the daemon functionality of the server.

This module contains tests for the server daemon operations including:
- PID file handling
- Server daemon start/stop operations
- Server status checking
- Server restart functionality

Note: These tests are skipped on Windows systems as daemon functionality
is only supported on Linux/WSL environments.
"""

from typing import Optional, Any
import pytest
import platform
import tempfile
from pathlib import Path
from daemon import get_pid
from unittest.mock import patch, MagicMock


pytestmark = pytest.mark.skipif(
    platform.system() == "Windows",
    reason="Daemon tests only run on Linux/WSL"
)


def test_get_pid_from_valid_file() -> None:
    """Test reading PID from a valid PID file.
    
    Verifies that the get_pid function correctly reads and parses
    the process ID from a PID file.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        pidfile: Path = Path(tmpdir) / "server.pid"
        pidfile.write_text("424242")

        pid: Optional[int] = get_pid(str(pidfile))
        assert pid == 424242


@patch("daemon.daemonize_server")
@patch("daemon.Server.start")
def test_start_server_daemon(
    mock_start: MagicMock,
    mock_daemonize: MagicMock
) -> None:
    """Test starting the server daemon process.
    
    Args:
        mock_start: Mocked Server.start method
        mock_daemonize: Mocked daemonize_server function
    """
    from daemon import start_server_daemon
    
    pidfile: str = "/tmp/test.pid"
    stdout: str = "/tmp/stdout.log"
    stderr: str = "/tmp/stderr.log"

    start_server_daemon(pidfile, stdout, stderr)

    mock_daemonize.assert_called_once_with(pidfile, stdout, stderr)
    mock_start.assert_called_once()


@patch("daemon.get_pid", return_value=9999)
@patch("os.kill")
@patch("daemon.is_server_daemon_running", side_effect=[True, False])
def test_stop_server_daemon(
    mock_running: MagicMock,
    mock_kill: MagicMock,
    mock_get_pid: MagicMock
) -> None:
    """Test stopping the server daemon process.
    
    Args:
        mock_running: Mocked is_server_daemon_running function
        mock_kill: Mocked os.kill function
        mock_get_pid: Mocked get_pid function
    """
    from daemon import stop_server_daemon

    stop_server_daemon("/tmp/fake.pid")

    mock_kill.assert_called_with(9999, 15)
    assert mock_running.call_count == 2


@patch("daemon.get_pid", return_value=9999)
@patch("daemon.is_server_daemon_running", return_value=True)
def test_status_running(
    mock_running: MagicMock,
    mock_pid: MagicMock
) -> None:
    """Test server status when daemon is running.
    
    Args:
        mock_running: Mocked is_server_daemon_running function
        mock_pid: Mocked get_pid function
    """
    from daemon import status_of_server_daemon
    
    status: str = status_of_server_daemon("/tmp/fake.pid")
    assert "Daemon is running" in status


@patch("daemon.get_pid", return_value=None)
def test_status_not_running(mock_pid: MagicMock) -> None:
    """Test server status when daemon is not running.
    
    Args:
        mock_pid: Mocked get_pid function
    """
    from daemon import status_of_server_daemon
    
    status: str = status_of_server_daemon("/tmp/fake.pid")
    assert "not running" in status


@patch("daemon.start_server_daemon")
@patch("daemon.stop_server_daemon")
def test_restart_server_daemon(
    mock_stop: MagicMock,
    mock_start: MagicMock
) -> None:
    """Test restarting the server daemon process.
    
    Args:
        mock_stop: Mocked stop_server_daemon function
        mock_start: Mocked start_server_daemon function
    """
    from daemon import restart_server_daemon
    
    restart_server_daemon("file.pid", "stdout.log", "stderr.log")
    mock_stop.assert_called_once_with("file.pid")
    mock_start.assert_called_once_with("file.pid", "stdout.log", "stderr.log")


def test_get_pid_invalid_content() -> None:
    """Test reading PID from a file with invalid content.
    
    Verifies that the get_pid function handles invalid PID file content
    gracefully and returns None.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        pidfile: Path = Path(tmpdir) / "invalid.pid"
        # Write invalid content (non-numeric)
        pidfile.write_text("not_a_pid")
        
        pid: Optional[int] = get_pid(str(pidfile))
        assert pid is None


@patch("daemon.get_pid", return_value=9999)
@patch("os.kill", side_effect=PermissionError)
@patch("daemon.is_server_daemon_running", return_value=True)
def test_stop_server_daemon_permission_denied(
    mock_running: MagicMock,
    mock_kill: MagicMock,
    mock_get_pid: MagicMock
) -> None:
    """Test stopping server daemon with insufficient permissions.
    
    Args:
        mock_running: Mocked is_server_daemon_running function
        mock_kill: Mocked os.kill function
        mock_get_pid: Mocked get_pid function
    """
    from daemon import stop_server_daemon
    
    with pytest.raises(SystemExit):
        stop_server_daemon("/tmp/fake.pid")



def test_get_pid_corrupted_file() -> None:
    """Test reading PID from a corrupted file.
    
    Verifies that the get_pid function handles corrupted PID files
    gracefully and returns None.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        pidfile: Path = Path(tmpdir) / "corrupted.pid"
        # Write binary data to simulate corruption
        pidfile.write_bytes(b'\x00\x01\x02\x03\x04\x05')
        
        pid: Optional[int] = get_pid(str(pidfile))
        assert pid is None


@patch("daemon.start_server_daemon")
@patch("daemon.stop_server_daemon")
def test_restart_server_daemon(mock_stop: MagicMock, mock_start: MagicMock) -> None:
    """Test restarting the server daemon process."""
    from daemon import restart_server_daemon

    pidfile = "/tmp/test.pid"
    stdout = "/tmp/stdout.log"
    stderr = "/tmp/stderr.log"

    # Act
    restart_server_daemon(pidfile, stdout, stderr)

    # Assert
    mock_stop.assert_called_once_with(pidfile)
    mock_start.assert_called_once_with(pidfile, stdout, stderr)

@patch("daemon.get_pid", return_value=None)
@patch("daemon.is_server_daemon_running", return_value=False)
def test_status_nonexistent_pid_file(
    mock_running: MagicMock,
    mock_get_pid: MagicMock
) -> None:
    """Test server status with non-existent PID file.
    
    Args:
        mock_running: Mocked is_server_daemon_running function
        mock_get_pid: Mocked get_pid function
    """
    from daemon import status_of_server_daemon
    
    status: str = status_of_server_daemon("/nonexistent/file.pid")
    assert "Daemon is not running" in status