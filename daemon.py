import os
import sys
import atexit
import signal
import argparse
import time
from pathlib import Path
from typing import Optional, NoReturn, Union, Any
from logger_setup import Logger

# import the server.
from server import Server

def daemonize_server(pidfile: str, stdout_file: str, stderr_file: str) -> None:
    """
    Detaches the main server process from the terminal task using a double forking method.

    Args:
        pidfile(str): Path to file where the daemon's process id will be stored.
        stdout_file(str): Path to file where stdout will be redirected.
        stderr_file(str): Path to file where stderr will be redirected.
    """
    # First fork.
    try:
        pid: int = os.fork()
        if pid > 0:
            # Exit parent.
            sys.exit(0)

    except OSError as e:
        sys.stderr.write(f"First fork failed: {e}.\n")
        sys.exit(1)

    # Set the session leader.
    os.setsid()
    os.umask(0)

    # Second fork.
    try:
        pid: int = os.fork()
        if pid > 0:
            # Exit child.
            sys.exit(0)

    except OSError as e:
        sys.stderr.write(f"Second fork failed : {e}\n")
        sys.exit(1)

    # Clean the buffer.
    sys.stdout.flush()
    sys.stderr.flush()

    # Redirect the new file descriptors.
    stdout_path: Path = Path(stdout_file).expanduser().absolute()
    stderr_path: Path = Path(stderr_file).expanduser().absolute()

    # After getting absolute paths - create the directories.
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)

    # Open new files in append mode.
    so: Any = open(stdout_path, "a+") 
    se: Any = open(stderr_path, "a+")

    # Use dup2 to redirect file descriptors.
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())

    # Write a new Process id file.
    pid_path: Path = Path(pidfile).expanduser().absolute()
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    with open(pid_path, "w+") as f:
        f.write(str(os.getpid())) # Get the process id and write it in the file.

    # Cleanup at exit.
    atexit.register(lambda: os.remove(pid_path) if os.path.exists(pid_path) else None)

def get_pid(pidfile: str) -> Optional[int]:
    """Read the PID from PID file provided.

    Args:
        pidfile(str) : Path to the pid file.

    Returns:
        Optional[int] : PID if found else None.
    """
    try:
        # Open the pidfile path.
        with open(pidfile, "r") as f:
            pid: int = int(f.read().strip())
        return pid
    
    except (ValueError, IOError):
        return None

def start_server_daemon(pidfile: str, stdout_file: str, stderr_file: str) -> None:
    """
    Starts the server daemon.

    Args:
        pidfile(str): Path to the PID file.
        stdout_file(str): Path to the stdout file descriptor.
        stderr_file(str): Path to the stderr file descriptor.
    """
    # Check if daemon is running.
    pid: Optional[int] = get_pid(pidfile)
    if pid and is_server_daemon_running(pid):
        sys.stderr.write(f"Daemon is still running with PID : {pid}")
        sys.exit(1)

    # Setup the logger.
    logger: Logger = Logger()

    # Start the daemon.
    logger.info("Starting server daemon...")
    logger.info(f"PID file : {pidfile}")
    logger.info(f"Logger files : {stdout_file} and {stderr_file}")

    # Call the daemonize_server function.
    daemonize_server(pidfile, stdout_file, stderr_file)

    # Run the server.
    try:
       
        server: Server = Server() # Start the server.
        server.start()
        
    except Exception as e:
        sys.stderr.write(f"Error in Daemon : {e}\n")
        sys.exit(1)

def stop_server_daemon(pidfile: str) -> None:
    """
    Stop the Daemon process.

    Args:
        pidfile (str): Path to the PID file.
    """
    pid: Optional[int] = get_pid(pidfile)
    logger: Logger = Logger()

    if not pid:
        sys.stderr.write(f"PID file {pidfile} does NOT exist. Daemon is not running.\n")
        return
    
    try:
        while is_server_daemon_running(pid):
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.1)
            logger.info(f"Daemon stopped (PID: {pid})")

    except OSError as e:
        if 'No such process' in str(e):
            if os.path.exists(pidfile):
                os.remove(pidfile)
                
        else:
            sys.stderr.write(str(e) + "\n")
            sys.exit()

def status_of_server_daemon(pidfile: str) -> str:
    """
    Check the status of the Daemon process.
    Args:
        pidfile(str): Path to the PID file of the Daemon.
    
    Returns:
        str: A message indicating whether the daemon is running.
    """
    pid: Optional[int] = get_pid(pidfile)
    if pid and is_server_daemon_running(pid):
        return f"Daemon is running with PID : {pid}"
    
    return "Daemon is not running."

def restart_server_daemon(pidfile: str, stdout_file: str, stderr_file: str) -> None:
    """
    Restarts the Daemon process.

    Args:
        pidfile(str): Path to the PID file.
        stdout_file(str): Path to the stdout file descriptor.
        stderr_file(str): Path to the stderr file descriptor.
    """
    stop_server_daemon(pidfile)
    start_server_daemon(pidfile, stdout_file, stderr_file)

def is_server_daemon_running(pid: int) -> bool:
    """Checks if the server daemon is running.
    
    Args:
        pid(int): The PID of the daemon.

    Returns:
        bool: True if the server daemon is running else False.
    """
    try:
        os.kill(pid, 0)  
        return True
    except OSError:
        return False

def main() -> None:
    # Get home directory.
    home_dir: str = os.path.expanduser("~")

    # Set the argument parser.
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description="Daemon Controller")
    # Add action arguments.
    parser.add_argument('action', choices=['start','stop','restart','status'],
                        help='The action to perform on the daemon')
    
    # Add pid file argument.
    parser.add_argument('--pidfile', default=f'{home_dir}/PID/server.pid',
                        help='Path to find PID file')
    
    # stdout.
    parser.add_argument('--stdout', default=f'{home_dir}/logs/stdout.log',
                        help='Path to stdout log file')
    # stderr.
    parser.add_argument('--stderr', default=f'{home_dir}/logs/stderr.log',
                        help='Path to stderr log file')
    
    args: argparse.Namespace = parser.parse_args()

    if args.action == 'start':
        start_server_daemon(args.pidfile, args.stdout, args.stderr)

    elif args.action == 'stop':
        stop_server_daemon(args.pidfile)

    elif args.action == 'restart':
        restart_server_daemon(args.pidfile, args.stdout, args.stderr)

    elif args.action == 'status':
        status: str = status_of_server_daemon(args.pidfile)
        print(status)

if __name__ == "__main__":
    main()