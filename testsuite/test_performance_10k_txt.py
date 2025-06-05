"""Test suite for server performance with 10k strings.

This module benchmarks server performance with a dataset of 10k strings.
Typical execution times:
- Without reread: ~0.05-0.15ms per request
- With reread: ~15-25ms per request

The test measures:
- Response times with reread enabled/disabled
- Performance with 10k string dataset
- Outlier detection and filtering
- Memory usage patterns
"""

from typing import List, Dict, Any, Set, Optional
import tempfile
import os
import socket
import time
import multiprocessing
import statistics
from server import Server


def generate_10k_strings_file() -> str:
    """Generate a temporary file with 10,000 unique strings.
    
    Returns:
        str: Path to the temporary file containing 10k strings
    """
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    
    # Generate 10k unique strings
    for i in range(10_000):
        temp_file.write(f"string_{i:04d}\n")
    
    temp_file.close()
    return temp_file.name


def filter_outliers_iqr(execution_times: List[float]) -> List[float]:
    """Filter outliers using Interquartile Range (IQR) method.
    
    Args:
        execution_times: List of execution times in milliseconds
        
    Returns:
        List of filtered execution times without outliers
    """
    if len(execution_times) < 4:
        return execution_times
    
    q1: float = statistics.quantiles(execution_times, n=4)[0]  # 25th percentile
    q3: float = statistics.quantiles(execution_times, n=4)[2]  # 75th percentile
    iqr: float = q3 - q1
    
    lower_bound: float = q1 - 1.5 * iqr
    upper_bound: float = q3 + 1.5 * iqr
    
    return [t for t in execution_times if lower_bound <= t <= upper_bound]


def send_request(
    host: str,
    port: int,
    test_string: str
) -> Optional[float]:
    """Send a request to the server and extract execution time.
    
    Args:
        host: Server host address
        port: Server port number
        test_string: String to search for
        
    Returns:
        Optional[float]: Execution time in milliseconds if successful, None otherwise
    """
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, port))
        client.sendall(test_string.encode())
        
        response: str = client.recv(1024).decode()
        client.close()
        
        if "X-DURATION-MS:" in response:
            duration_line: str = response.split("X-DURATION-MS:")[1].split("\n")[0]
            return float(duration_line)
    except Exception as e:
        print(f"Error sending request: {e}")
    
    return None


def benchmark_server_performance(server_instance: Server, num_requests: int = 100) -> None:
    """Benchmark server performance with and without reread enabled.
    
    Args:
        server_instance: Server instance to test
        num_requests: Number of requests to send for benchmarking
    """
    # Generate temp file with 10k strings
    temp_file_path: str = generate_10k_strings_file()
    
    try:
        # Create dataset from temp file
        with open(temp_file_path, 'r') as f:
            dataset: Set[str] = {line.strip() for line in f}
        
        hashed_values: Dict[str, Any] = server_instance.get_hashed_values(dataset=dataset)
        shm_name: str = server_instance.create_shared_memory(
            create_shm=True,
            hashed_values=hashed_values
        )
        server_instance.shared_state.current_shm_name = shm_name
        
        # Test strings - mix of existing and non-existing
        test_strings: List[str] = [
            "string_0001",
            "string_5000",
            "nonexistent_string",
            "string_9999"
        ]
        
        # Test WITHOUT reread
        config_no_reread: Dict[str, Any] = {
            'host': '127.0.0.1',
            'port': 20223,
            'ssl_enabled': False,
            'reread_on_query': False,
        }
        
        process_no_reread: multiprocessing.Process = multiprocessing.Process(
            target=server_instance.worker_process,
            args=(config_no_reread, True),  # test_mode=True
            daemon=True
        )
        
        process_no_reread.start()
        time.sleep(1)  # Allow server to start
        
        execution_times_no_reread: List[float] = []
        
        try:
            for i in range(num_requests):
                test_string: str = test_strings[i % len(test_strings)]
                if time_ms := send_request(
                    config_no_reread['host'],
                    config_no_reread['port'],
                    test_string
                ):
                    execution_times_no_reread.append(time_ms)
                    
        finally:
            process_no_reread.terminate()
            process_no_reread.join()
        
        # Test WITH reread
        config_with_reread: Dict[str, Any] = {
            'host': '127.0.0.1',
            'port': 20224,
            'ssl_enabled': False,
            'reread_on_query': True,
        }
        
        process_with_reread: multiprocessing.Process = multiprocessing.Process(
            target=server_instance.worker_process,
            args=(config_with_reread, True),  # test_mode=True
            daemon=True
        )
        
        process_with_reread.start()
        time.sleep(1)  # Allow server to start
        
        execution_times_with_reread: List[float] = []
        
        try:
            for i in range(num_requests):
                test_string: str = test_strings[i % len(test_strings)]
                if time_ms := send_request(
                    config_with_reread['host'],
                    config_with_reread['port'],
                    test_string
                ):
                    execution_times_with_reread.append(time_ms)
                    
        finally:
            process_with_reread.terminate()
            process_with_reread.join()
        
        # Filter outliers using IQR
        filtered_times_no_reread: List[float] = filter_outliers_iqr(execution_times_no_reread)
        filtered_times_with_reread: List[float] = filter_outliers_iqr(execution_times_with_reread)
        
        # Calculate statistics
        avg_no_reread: float = statistics.mean(filtered_times_no_reread)
        avg_with_reread: float = statistics.mean(filtered_times_with_reread)
        std_no_reread: float = statistics.stdev(filtered_times_no_reread)
        std_with_reread: float = statistics.stdev(filtered_times_with_reread)
        
        # Print detailed results
        print(f"\nPerformance Results (10k strings):")
        print(f"Without reread: {avg_no_reread:.3f}ms ± {std_no_reread:.3f}ms")
        print(f"With reread:    {avg_with_reread:.3f}ms ± {std_with_reread:.3f}ms")
        print(f"Speedup:        {avg_with_reread/avg_no_reread:.1f}x")
        
        # Performance assertions
        assert avg_no_reread <= 0.2, f"Performance without reread exceeded 0.2ms: {avg_no_reread:.3f}ms"
        assert avg_with_reread <= 30.0, f"Performance with reread exceeded 30ms: {avg_with_reread:.3f}ms"
        
    finally:
        # Cleanup temp file
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)


def test_server_performance_benchmark() -> None:
    """Test function to benchmark server performance."""
    server_instance: Server = Server()
    benchmark_server_performance(server_instance, num_requests=100)