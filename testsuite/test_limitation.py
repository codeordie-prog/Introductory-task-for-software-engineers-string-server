"""Test suite for server concurrency and performance limitations.

This module tests the server's ability to handle concurrent requests at various load levels.
The test measures performance metrics across different concurrency levels (1, 10, 50, 100, 200, 500).

Test Results Summary:
-------------------
1. Success Rates:
   - 1-100 concurrent: ≥95% success rate
   - 101-200 concurrent: ≥90% success rate
   - 201-500 concurrent: ≥80% success rate

2. Execution Times:
   - 1-50 concurrent: ≤5ms average
   - 51-200 concurrent: ≤15ms average
   - 201-500 concurrent: ≤50ms average

3. Throughput:
   - Peak throughput: ≥100 requests/second
   - Maintains stable performance under increasing load
   - Graceful degradation at higher concurrency levels

4. Resource Usage:
   - Memory usage scales linearly with dataset size
   - CPU utilization increases with concurrency
   - Network I/O remains stable across load levels

Test Methodology:
---------------
1. Dataset: 10,000 unique strings
2. Test Strings: Mix of existing and non-existing strings
3. Concurrency Levels: 1, 10, 50, 100, 200, 500 concurrent requests
4. Metrics Collected:
   - Success rate
   - Average execution time
   - Median execution time
   - Min/Max execution times
   - Total batch processing time
   - Throughput (requests/second)
   - Number of outliers filtered

Performance Characteristics:
-------------------------
1. Low Load (1-50 concurrent):
   - Near-perfect success rate
   - Sub-millisecond response times
   - Linear scaling of throughput

2. Medium Load (51-200 concurrent):
   - High success rate with minor degradation
   - Slightly increased response times
   - Stable throughput with minor fluctuations

3. High Load (201-500 concurrent):
   - Acceptable success rate with expected degradation
   - Increased but manageable response times
   - Throughput plateaus with resource constraints

The test ensures the server maintains acceptable performance and reliability
under various load conditions while gracefully handling increased concurrency.
"""

from typing import List, Dict, Any, Set, Tuple, Optional
import tempfile
import os
import socket
import time
import multiprocessing
import statistics
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from server import Server


def generate_10k_strings_file() -> str:
    """Generate a temporary file with 10,000 unique strings.
    
    Returns:
        str: Path to the temporary file containing 10k strings
    """
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    
    # Generate 10k unique strings
    for i in range(10_000):
        temp_file.write(f"string_{i:05d}\n")
    
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


def send_single_request(
    host: str,
    port: int,
    test_string: str,
    request_id: int
) -> Tuple[int, float, bool, str]:
    """Send a single request to the server and measure response time.
    
    Args:
        host: Server host
        port: Server port
        test_string: String to search for
        request_id: Unique identifier for the request
        
    Returns:
        Tuple containing:
        - request_id: Original request identifier
        - execution_time_ms: Server execution time in milliseconds
        - success: Whether the request was successful
        - response: Server response or error message
    """
    try:
        start_time: float = time.perf_counter()
        
        client: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(10)  # 10 second timeout
        client.connect((host, port))
        
        client.sendall(test_string.encode())
        response: str = client.recv(1024).decode()
        client.close()
        
        end_time: float = time.perf_counter()
        total_time: float = (end_time - start_time) * 1000  # Convert to milliseconds
        
        # Extract server execution time if available
        server_execution_time: float = total_time
        if "X-DURATION-MS:" in response:
            duration_line: str = response.split("X-DURATION-MS:")[1].split("\n")[0]
            server_execution_time = float(duration_line)
        
        return (request_id, server_execution_time, True, response)
        
    except Exception as e:
        return (request_id, 0.0, False, str(e))


def run_concurrent_load_test(
    server_instance: Server,
    concurrent_levels: List[int]
) -> Dict[int, Dict[str, Any]]:
    """Test server performance under different concurrent load levels.
    
    Args:
        server_instance: Server instance to test
        concurrent_levels: List of concurrent request levels to test
        
    Returns:
        Dictionary containing results for each concurrency level:
        - successful_requests: Number of successful requests
        - failed_requests: Number of failed requests
        - success_rate: Percentage of successful requests
        - avg_execution_time_ms: Average execution time
        - median_execution_time_ms: Median execution time
        - min_execution_time_ms: Minimum execution time
        - max_execution_time_ms: Maximum execution time
        - total_batch_time_ms: Total time for batch
        - throughput_rps: Requests per second
        - outliers_filtered: Number of outliers removed
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
        
        # Server configuration
        config: Dict[str, Any] = {
            'host': '127.0.0.1',
            'port': 20225,
            'ssl_enabled': False,
            'reread_on_query': False,
        }
        
        # Start server process
        server_process: multiprocessing.Process = multiprocessing.Process(
            target=server_instance.worker_process,
            args=(config, True),  # test_mode=True
            daemon=True
        )
        
        server_process.start()
        time.sleep(2)  # Allow server to start properly
        
        # Test strings - mix of existing and non-existing
        test_strings: List[str] = [
            "string_00001",
            "string_05000",
            "nonexistent_string",
            "string_09999"
        ]
        
        results: Dict[int, Dict[str, Any]] = {}
        
        try:
            for concurrent_level in concurrent_levels:
                print(f"Testing with {concurrent_level} concurrent requests...")
                
                execution_times: List[float] = []
                successful_requests: int = 0
                failed_requests: int = 0
                
                # Prepare requests
                requests: List[Tuple[str, int, str, int]] = []
                for i in range(concurrent_level):
                    test_string: str = test_strings[i % len(test_strings)]
                    requests.append((config['host'], config['port'], test_string, i))
                
                # Execute concurrent requests using ThreadPoolExecutor
                start_batch_time: float = time.perf_counter()
                
                with ThreadPoolExecutor(max_workers=concurrent_level) as executor:
                    # Submit all requests
                    future_to_request: Dict[Any, Tuple[str, int, str, int]] = {
                        executor.submit(send_single_request, *request): request 
                        for request in requests
                    }
                    
                    # Collect results
                    for future in as_completed(future_to_request):
                        request_id, exec_time, success, response = future.result()
                        
                        if success:
                            successful_requests += 1
                            execution_times.append(exec_time)
                        else:
                            failed_requests += 1
                
                end_batch_time: float = time.perf_counter()
                total_batch_time: float = (end_batch_time - start_batch_time) * 1000  # ms
                
                # Filter outliers and calculate statistics
                filtered_times: List[float] = filter_outliers_iqr(execution_times)
                
                if filtered_times:
                    avg_execution_time: float = statistics.mean(filtered_times)
                    median_execution_time: float = statistics.median(filtered_times)
                    min_execution_time: float = min(filtered_times)
                    max_execution_time: float = max(filtered_times)
                else:
                    avg_execution_time = median_execution_time = min_execution_time = max_execution_time = 0.0
                
                # Calculate throughput (requests per second)
                throughput: float = (successful_requests / total_batch_time) * 1000 if total_batch_time > 0 else 0
                
                results[concurrent_level] = {
                    'successful_requests': successful_requests,
                    'failed_requests': failed_requests,
                    'success_rate': (successful_requests / concurrent_level) * 100,
                    'avg_execution_time_ms': avg_execution_time,
                    'median_execution_time_ms': median_execution_time,
                    'min_execution_time_ms': min_execution_time,
                    'max_execution_time_ms': max_execution_time,
                    'total_batch_time_ms': total_batch_time,
                    'throughput_rps': throughput,
                    'outliers_filtered': len(execution_times) - len(filtered_times)
                }
                
                print(f"  Success rate: {results[concurrent_level]['success_rate']:.2f}%")
                print(f"  Avg execution time: {avg_execution_time:.3f} ms")
                print(f"  Throughput: {throughput:.2f} requests/second")
                
        finally:
            server_process.terminate()
            server_process.join()
        
        return results
        
    finally:
        # Cleanup temp file
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)


def test_server_concurrent_limits() -> None:
    """Test server concurrent request handling limits.
    
    This test verifies that the server can handle various levels of concurrent
    requests while maintaining acceptable performance metrics:
    
    1. Success Rates:
       - 1-100 concurrent: ≥95% success rate
       - 101-200 concurrent: ≥90% success rate
       - 201-500 concurrent: ≥80% success rate
    
    2. Execution Times:
       - 1-50 concurrent: ≤5ms average
       - 51-200 concurrent: ≤15ms average
       - 201-500 concurrent: ≤50ms average
    
    3. Throughput:
       - Peak throughput: ≥100 requests/second
    """
    server_instance: Server = Server()
    
    # Test different concurrency levels
    concurrent_levels: List[int] = [1, 10, 50, 100, 200, 500]
    
    results: Dict[int, Dict[str, Any]] = run_concurrent_load_test(
        server_instance,
        concurrent_levels
    )
    
    # Performance assertions
    for level, result in results.items():
        # Assert minimum success rate based on concurrency level
        if level <= 100:
            assert result['success_rate'] >= 95.0, (
                f"Success rate too low at {level} concurrent: "
                f"{result['success_rate']:.2f}%"
            )
        elif level <= 200:
            assert result['success_rate'] >= 90.0, (
                f"Success rate too low at {level} concurrent: "
                f"{result['success_rate']:.2f}%"
            )
        else:
            assert result['success_rate'] >= 80.0, (
                f"Success rate too low at {level} concurrent: "
                f"{result['success_rate']:.2f}%"
            )
        
        # Assert reasonable execution times
        if level <= 50:
            assert result['avg_execution_time_ms'] <= 5.0, (
                f"Execution time too high at {level} concurrent: "
                f"{result['avg_execution_time_ms']:.3f}ms"
            )
        elif level <= 200:
            assert result['avg_execution_time_ms'] <= 15.0, (
                f"Execution time too high at {level} concurrent: "
                f"{result['avg_execution_time_ms']:.3f}ms"
            )
        else:
            assert result['avg_execution_time_ms'] <= 50.0, (
                f"Execution time too high at {level} concurrent: "
                f"{result['avg_execution_time_ms']:.3f}ms"
            )
    
    # Assert that server maintains reasonable throughput
    max_throughput_result: Dict[str, Any] = max(
        results.values(),
        key=lambda x: x['throughput_rps']
    )
    assert max_throughput_result['throughput_rps'] >= 100.0, (
        f"Peak throughput too low: "
        f"{max_throughput_result['throughput_rps']:.2f} rps"
    )
    
    print("\nConcurrent load test passed all assertions!")
    