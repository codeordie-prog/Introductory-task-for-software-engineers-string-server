"""
Test suite for exception handling in the daemon implementation.

This module contains tests that verify the daemon's behavior when encountering various
error conditions and exceptions. It tests the robustness of the daemon implementation
by simulating different failure scenarios.

The tests cover:
- Process forking failures
- File system errors
- PID file handling
- Process management errors
- Server start/stop/restart operations
- Status checking
- Permission errors

Each test is designed to be isolated and includes proper cleanup of test resources.
The tests use pytest fixtures for resource management and unittest.mock for
simulating system calls and file operations.

Example:
    To run all tests:
        pytest testsuite/test_exception_handling_daemon.py -v

    To run a specific test:
        pytest testsuite/test_exception_handling_daemon.py::test_first_fork_failure -v
"""

from typing import Tuple, Generator, Any,Optional
import pytest
import os
from unittest.mock import patch, MagicMock

from daemon import (
    daemonize_server,
    get_pid,
    start_server_daemon,
    stop_server_daemon,
    status_of_server_daemon,
    restart_server_daemon,
    is_server_daemon_running
)


@pytest.fixture
def test_files() -> Generator[Tuple[str, str, str], None, None]:
    """
    Fixture to create and cleanup test files.

    Creates temporary files for testing daemon operations:
    - PID file
    - stdout log file
    - stderr log file

    Yields:
        Tuple[str, str, str]: Paths to pidfile, stdout_file, and stderr_file

    Example:
        def test_something(test_files):
            pidfile, stdout_file, stderr_file = test_files
            # Use the files in test
    """
    pidfile: str = "test.pid"
    stdout_file: str = "test_stdout.log"
    stderr_file: str = "test_stderr.log"
    yield pidfile, stdout_file, stderr_file
    # Cleanup
    for file in [pidfile, stdout_file, stderr_file]:
        if os.path.exists(file):
            os.remove(file)


def test_first_fork_failure(test_files: Tuple[str, str, str]) -> None:
    """
    Test OSError handling in first fork.

    Verifies that the daemon properly handles OSError during the first fork
    operation and exits with the correct status code.

    Args:
        test_files: Tuple containing paths to test files
    """
    pidfile, stdout_file, stderr_file = test_files
    with patch('os.fork', side_effect=OSError("Fork failed")):
        with pytest.raises(SystemExit) as exc_info:
            daemonize_server(pidfile, stdout_file, stderr_file)
        assert exc_info.value.code == 1


def test_second_fork_failure(test_files: Tuple[str, str, str]) -> None:
    """
    Test OSError handling in second fork.

    Verifies that the daemon properly handles OSError during the second fork
    operation and exits with the correct status code.

    Args:
        test_files: Tuple containing paths to test files
    """
    pidfile, stdout_file, stderr_file = test_files
    
    # Mock fork to return 0 for first call (child process), then raise OSError on second call
    # This simulates being in the child process where the second fork fails
    with patch('os.fork', side_effect=[0, OSError("Second fork failed")]), \
         patch('os.setsid'), \
         patch('os.umask'):
        with pytest.raises(SystemExit) as exc_info:
            daemonize_server(pidfile, stdout_file, stderr_file)
        assert exc_info.value.code == 1


def test_get_pid_invalid_file(test_files: Tuple[str, str, str]) -> None:
    """
    Test handling of invalid PID file content.

    Verifies that get_pid returns None when the PID file contains invalid data.

    Args:
        test_files: Tuple containing paths to test files
    """
    pidfile, _, _ = test_files
    with open(pidfile, 'w') as f:
        f.write("invalid_pid")
    result: Optional[int] = get_pid(pidfile)
    assert result is None


def test_get_pid_file_not_found(test_files: Tuple[str, str, str]) -> None:
    """
    Test handling of non-existent PID file.

    Verifies that get_pid returns None when the PID file doesn't exist.

    Args:
        test_files: Tuple containing paths to test files
    """
    pidfile, _, _ = test_files
    result: Optional[int] = get_pid("nonexistent.pid")
    assert result is None


def test_start_daemon_already_running(test_files: Tuple[str, str, str]) -> None:
    """
    Test handling of already running daemon.

    Verifies that attempting to start a daemon that's already running
    results in the correct error code.

    Args:
        test_files: Tuple containing paths to test files
    """
    pidfile, stdout_file, stderr_file = test_files
    with patch('daemon.get_pid', return_value=1234), \
         patch('daemon.is_server_daemon_running', return_value=True):
        with pytest.raises(SystemExit) as exc_info:
            start_server_daemon(pidfile, stdout_file, stderr_file)
        assert exc_info.value.code == 1


def test_stop_daemon_no_pid_file(test_files: Tuple[str, str, str]) -> None:
    """
    Test handling of stop command with no PID file.

    Verifies that attempting to stop a daemon without a PID file
    results in the correct error message.

    Args:
        test_files: Tuple containing paths to test files
    """
    pidfile, _, _ = test_files
    with patch('daemon.get_pid', return_value=None):
        with patch('sys.stderr.write') as mock_stderr:
            stop_server_daemon(pidfile)
            mock_stderr.assert_called_once()


def test_restart_daemon_error(test_files: Tuple[str, str, str]) -> None:
    """
    Test handling of error during restart.

    Verifies that errors during daemon restart are properly propagated.

    Args:
        test_files: Tuple containing paths to test files
    """
    pidfile, stdout_file, stderr_file = test_files
    with patch('daemon.stop_server_daemon', side_effect=Exception("Stop failed")):
        with pytest.raises(Exception) as exc_info:
            restart_server_daemon(pidfile, stdout_file, stderr_file)
        assert str(exc_info.value) == "Stop failed"


def test_server_start_error(test_files: Tuple[str, str, str]) -> None:
    """
    Test handling of server start error.

    Verifies that server initialization errors are properly handled
    and result in the correct exit code.

    Args:
        test_files: Tuple containing paths to test files
    """
    pidfile, stdout_file, stderr_file = test_files
    with patch('daemon.get_pid', return_value=None), \
         patch('daemon.daemonize_server'), \
         patch('daemon.Server', side_effect=Exception("Server start failed")):
        with pytest.raises(SystemExit) as exc_info:
            start_server_daemon(pidfile, stdout_file, stderr_file)
        assert exc_info.value.code == 1


def test_status_daemon_invalid_pid(test_files: Tuple[str, str, str]) -> None:
    """
    Test handling of invalid PID in status check.

    Verifies that checking status with an invalid PID returns
    the correct status message.

    Args:
        test_files: Tuple containing paths to test files
    """
    pidfile, _, _ = test_files
    with patch('daemon.get_pid', return_value=999999), \
         patch('daemon.is_server_daemon_running', return_value=False):
        status: str = status_of_server_daemon(pidfile)
        assert status == "Daemon is not running."