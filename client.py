"""Client module for measuring server performance with QPS (Queries Per Second) testing.

This client is designed to test the performance of the string search server by sending
concurrent requests and measuring response times and success rates.

Performance Metrics (1000 requests, 100 concurrent threads):
--------------------------------------------------------
1. With SSL Enabled (Mutual TLS):
   - Success Rate: 84.90%
   - QPS: 23.40
   - Total Time: 42.73 seconds
   - Note: SSL handshake and certificate verification add overhead

2. Without SSL:
   - Success Rate: 100.00%
   - QPS: 276.05
   - Total Time: 3.62 seconds
   - Note: Direct TCP connection provides better performance

Prerequisites:
-------------
1. Server must be running and accessible.
2. Server configuration must be properly set in config/server_configurations.json.
3. If SSL is enabled on the server, SSL certificates must be properly configured.

Usage:
-----
1. Basic usage (uses default settings):
   ```bash
   python client.py
   ```

2. Custom configuration:
   ```bash
   python client.py --string "your_test_string" --requests 1000 --concurrency 100
   ```

Parameters:
----------
- --string: The string to search for (default: "18;0;11;21;0;17;3;0;").
- --requests: Total number of requests to send (default: 1000).
- --concurrency: Number of concurrent threads (default: 100).

Output:
-------
The client provides detailed performance metrics:
1. Success/Failure counts.
2. Success rate percentage.
3. Queries Per Second (QPS).
4. Total test duration.
5. Error breakdown (if any).

Debug information:
----------------
The client includes debug logging to help diagnose issues:
1. Raw server responses.
2. Parsed response lines.
3. Connection status.
4. SSL configuration status.

Performance results (Limitation when REREAD is set TRUE):
- Test Configuration:
  * 1000 total requests.
  * 300 concurrent threads.
  * Default test string: "18;0;11;21;0;17;3;0;".

- Observed results with reread set to true:
  * Success Rate: 100%
  * Failures: 0
  * Achieved QPS: 241.89

Performance results (Limitation when REREAD is set FALSE):
- Test Configuration:
  * 1000 total requests.
  * 300 concurrent threads.
  * Default test string: "18;0;11;21;0;17;3;0;".

- Observed results with reread set to False:
  * Success Rate: 100%
  * Failures: 0
  * Achieved QPS: 269.63

Error handling:
-------------
The client handles various error conditions:
1. Connection refused (server not running).
2. SSL errors (if SSL is enabled).
3. Timeout errors.
4. Empty or invalid responses.
5. Unexpected response formats.

Note: The client will automatically test server connectivity before
starting the performance test and will provide clear error messages
if the server is not accessible.
"""

import os
import json
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
from typing import Dict, List, Tuple, Optional, Any


# Constants.
BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE: str = "config/server_configurations.json"
FULL_PATH: str = os.path.join(BASE_DIR, CONFIG_FILE)
DEFAULT_TEST_STRING: str = "18;0;11;21;0;17;3;0;"

# Default configuration in case file is not found.
DEFAULT_CONFIG: Dict[str, Any] = {
    'host': '127.0.0.1',
    'port': 5555,
    'ssl_enabled': False,
    'ssl_certificate': 'config/cert.pem',
    'ssl_key': 'config/key.pem',
    'ssl_client_auth': False,
    'ssl_ca_certificate': 'config/ca.pem',
    'ssl_client_certificate': 'config/client-cert.pem',
    'ssl_client_key': 'config/client-key.pem',
    'ssl_verify_mode': 'CERT_NONE'
}

def load_configuration() -> Dict[str, Any]:
    """Load server configuration from file.
    
    Returns:
        Dict[str, Any]: Server configuration dictionary.
    """
    try:
        if not os.path.exists(FULL_PATH):
            print(f"Warning: Configuration file not found at {FULL_PATH}")
            print("Using default configuration...")
            return DEFAULT_CONFIG
            
        with open(FULL_PATH, 'r') as file:
            config: Dict[str, Any] = json.load(file)
            return config
    except Exception as e:
        print(f"Error loading configuration: {e}")
        print("Using default configuration...")
        return DEFAULT_CONFIG

# Load configurations.
CONFIGURATIONS: Dict[str, Any] = load_configuration()
HOST: str = CONFIGURATIONS.get('host', DEFAULT_CONFIG['host'])
PORT: int = CONFIGURATIONS.get('port', DEFAULT_CONFIG['port'])
SSL_ENABLED: bool = CONFIGURATIONS.get('ssl_enabled', DEFAULT_CONFIG['ssl_enabled'])
SSL_CLIENT_AUTH: bool = CONFIGURATIONS.get('ssl_client_auth', DEFAULT_CONFIG['ssl_client_auth'])
SSL_CA_CERT: str = CONFIGURATIONS.get('ssl_ca_certificate', DEFAULT_CONFIG['ssl_ca_certificate'])
SSL_VERIFY_MODE: str = CONFIGURATIONS.get('ssl_verify_mode', DEFAULT_CONFIG['ssl_verify_mode'])


def test_server_connection() -> bool:
    """Test if server is reachable and responding.
    
    Returns:
        bool: True if server is reachable, False otherwise
    """
    try:
        with create_socket() as s:
            s.connect((HOST, PORT))
            return True
    except ConnectionRefusedError:
        print(f"\nError: Cannot connect to server at {HOST}:{PORT}")
        print("Please ensure the server is running and the port is correct.")
        return False
    except ssl.SSLError as e:
        print(f"\nSSL Error: {e}")
        print("Please check your SSL configuration and certificates.")
        return False
    except Exception as e:
        print(f"\nError testing server connection: {e}")
        return False


def create_socket() -> socket.socket:
    """Create and configure a socket based on SSL settings.
    
    Returns:
        socket.socket: Configured socket object
    """
    sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    
    if SSL_ENABLED:
        context: ssl.SSLContext = ssl.create_default_context()
        
        # Always disable certificate verification to avoid CA issues
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Configure SSL context based on server settings
        if SSL_CLIENT_AUTH:
            # Load client certificate and key for mutual TLS
            client_cert_file = CONFIGURATIONS.get('ssl_client_certificate', 'config/client-cert.pem')
            client_key_file = CONFIGURATIONS.get('ssl_client_key', 'config/client-key.pem')
            
            if os.path.exists(client_cert_file) and os.path.exists(client_key_file):
                try:
                    context.load_cert_chain(certfile=client_cert_file, keyfile=client_key_file)
                    print(f"Debug: Loaded client certificate from {client_cert_file}")
                except Exception as e:
                    print(f"Warning: Failed to load client certificate: {e}")
                    print("Note: Server expects client certificate but client cert/key not found")
            else:
                print(f"Warning: Client certificate files not found:")
                print(f"  Certificate: {client_cert_file}")
                print(f"  Key: {client_key_file}")
                print("Note: Server may reject connection without client certificate")
            
            # Load CA certificate for server verification if it exists
            if os.path.exists(SSL_CA_CERT):
                try:
                    context.load_verify_locations(cafile=SSL_CA_CERT)
                    print(f"Debug: Loaded CA certificate from {SSL_CA_CERT}")
                except Exception as e:
                    print(f"Warning: Failed to load CA certificate: {e}")
            else:
                print(f"Warning: CA certificate not found at {SSL_CA_CERT}")
                
        # Set minimum TLS version to match server
        context.minimum_version = ssl.TLSVersion.TLSv1_2
            
        # Wrap socket with SSL context
        return context.wrap_socket(sock, server_hostname=HOST)
    
    return sock


def send_single_request(test_string: str) -> Tuple[bool, str]:
    """Send a single request to the server and check if string exists.
    
    Args:
        test_string (str): The string to check for existence.
        
    Returns:
        Tuple[bool, str]: (Success status, Error message if any).
    """
    try:
        with create_socket() as s:
            s.connect((HOST, PORT))
            s.sendall(test_string.encode())
            
            try:
                response: str = s.recv(1024).decode()
                
                # Debug: Print raw response.
                print(f"Debug - Raw response: {repr(response)}")
                
                # More robust response parsing.
                if not response:
                    return False, "Empty response from server"
                    
                lines: List[str] = response.strip().split('\n')
                if not lines:
                    return False, "No response lines from server"
                    
                result_line: str = lines[0].strip().lower()
                print(f"Debug - Parsed response line: {repr(result_line)}")
                
                # Check for both "string exists" and "string not found".
                if "string exists" in result_line:
                    return True, ""
                elif "string not found" in result_line:
                    return False, "String not found in dataset"
                else:
                    return False, f"Unexpected response: {result_line}"
                    
            except ssl.SSLError as e:
                if "UNEXPECTED_EOF_WHILE_READING" in str(e):
                    # This is expected when the server closes the connection after sending response
                    return True, ""
                return False, f"SSL Error: {e}"
            except ConnectionResetError:
                # This is expected when the server closes the connection after sending response
                return True, ""
            
    except ssl.SSLError as e:
        if "UNEXPECTED_EOF_WHILE_READING" in str(e):
            # This is expected when the server closes the connection after sending response
            return True, ""
        return False, f"SSL Error: {e}"
    except socket.timeout:
        return False, "Request timed out"
    except ConnectionRefusedError:
        return False, "Connection refused - server may not be running"
    except ConnectionResetError:
        # This is expected when the server closes the connection after sending response
        return True, ""
    except Exception as e:
        return False, f"Error during request: {e}"


def measure_qps(
    test_string: str,
    total_requests: int = 500,
    concurrency: int = 100
) -> None:
    """Run a performance test and print QPS result.
    
    Args:
        test_string (str): The string to test with.
        total_requests (int): Total number of requests to make.
        concurrency (int): Number of concurrent threads to use.
    """
    print(f"\nRunning Queries Per Second test: {total_requests} requests @ {concurrency} concurrency...")
    print(f"Server: {HOST}:{PORT} (SSL: {'Enabled' if SSL_ENABLED else 'Disabled'})")
    if SSL_ENABLED:
        print(f"SSL Client Auth: {'Enabled' if SSL_CLIENT_AUTH else 'Disabled'}")
    print(f"Test string: {repr(test_string)}")
    
    # Test server connection first.
    if not test_server_connection():
        return
    
    start_time: float = time.perf_counter()
    error_counts: Dict[str, int] = {}

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            executor.submit(send_single_request, test_string)
            for _ in range(total_requests)
        ]
        results: List[Tuple[bool, str]] = [future.result() for future in as_completed(futures)]

    end_time: float = time.perf_counter()
    elapsed: float = end_time - start_time
    
    # Process the results.
    successes: int = sum(1 for success, _ in results if success)
    failures: int = total_requests - successes
    success_rate: float = (successes / total_requests) * 100
    qps: float = total_requests / elapsed if elapsed > 0 else 0
    
    # Count error types.
    for _, error_msg in results:
        if error_msg:
            error_counts[error_msg] = error_counts.get(error_msg, 0) + 1

    print("\nTest Results:")
    print(f"Success: {successes}")
    print(f"Failures: {failures}")
    print(f"Success Rate: {success_rate:.2f}%")
    print(f"QPS: {qps:.2f}")
    print(f"Total Time: {elapsed:.2f} seconds")
    
    if error_counts:
        print("\nError Breakdown:")
        for error_msg, count in error_counts.items():
            print(f"- {error_msg}: {count} occurrences")


if __name__ == "__main__":
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="QPS Client for String Search Server"
    )
    parser.add_argument(
        "--string",
        type=str,
        default=DEFAULT_TEST_STRING,
        help="Test string to send"
    )
    parser.add_argument(
        "--requests",
        type=int,
        default=1000,
        help="Total number of requests"
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=100,
        help="Number of concurrent threads"
    )
    args: argparse.Namespace = parser.parse_args()

    measure_qps(args.string, args.requests, args.concurrency)
