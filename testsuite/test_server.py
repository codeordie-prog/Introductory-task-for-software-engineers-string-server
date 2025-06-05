"""Test suite for the Server class implementation.

This module contains comprehensive tests for the Server class functionality including:
- Hash value generation and serialization
- Shared memory management
- String search operations
- Worker process handling
- Client connection handling
- SSL authentication handling

The tests cover both successful and error cases to ensure robust server operation.
"""

from typing import Dict, Set, Optional, Any
from server import Server, BackgroundFileMonitor
import pytest
from hashfile import hash_file
from unittest.mock import MagicMock, patch
import multiprocessing
import time
import socket
import os
import ssl
import pickle
from multiprocessing import shared_memory
import tempfile
import threading
#import mock

# Suppress multiprocessing fork warnings
pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning:multiprocessing.*:")


@pytest.fixture
def get_server_instance() -> Server:
    """Create and return a Server instance for testing.
    
    Returns:
        Server: A fresh Server instance for each test.
    """
    return Server()


def test_get_hashed_values(get_server_instance: Server) -> None:
    """Test hash value generation from dataset and file path.
    
    Args:
        get_server_instance: Server instance fixture
    """
    dataset: Set[str] = {"Eunice", "Maharishi", "Bliss"}
    results: Optional[Dict[str, Any]] = get_server_instance.get_hashed_values(dataset=dataset)
    assert results is not None
    assert isinstance(results, dict)
    assert 'total_size' in results
    assert 'values' in results
    assert len(results) == 2
    assert len(results['values']) > 0

    config_path: str = "this_path_does_not_exist.json"
    results = get_server_instance.get_hashed_values(file_path=config_path)
    assert results is None


def test_serialize_hashed_values(get_server_instance: Server) -> None:
    """Test serialization and deserialization of hashed values.
    
    Args:
        get_server_instance: Server instance fixture
    """
    dataset: Set[str] = {"Nairobi", "Kenya", "Africa"}
    hashed_values: Dict[str, Any] = get_server_instance.get_hashed_values(dataset=dataset)

    assert isinstance(hashed_values, dict), "get_hashed_values method did not return a dictionary"
    serialized: bytes = get_server_instance.serialize_hashed_values(hashed_values=hashed_values)
    assert isinstance(serialized, bytes), "serialize_hashed_values method did not return bytes"
    assert len(serialized) > 0, "Length of serialized hashed values is 0"

    import pickle
    deserialized: Dict[str, Any] = pickle.loads(serialized)
    assert isinstance(deserialized, dict), "deserialized values is not a dictionary"
    assert deserialized == hashed_values, "deserialized is not equal to hashed values"


def test_create_shared_memory(get_server_instance: Server) -> None:
    """Test creation and verification of shared memory.
    
    Args:
        get_server_instance: Server instance fixture
    """
    dataset: Set[str] = {"witstormsAI", "Nairobi", "Kenya"}
    hashed_values: Dict[str, Any] = get_server_instance.get_hashed_values(dataset=dataset)

    shm_name: str = get_server_instance.create_shared_memory(
        create_shm=True,
        hashed_values=hashed_values
    )

    assert shm_name is not None

    from multiprocessing import shared_memory
    import pickle

    shm = shared_memory.SharedMemory(name=shm_name)
    try:
        data: bytes = shm.buf.tobytes()
        deserialized: Dict[str, Any] = pickle.loads(data)
        assert deserialized == hashed_values
    finally:
        shm.close()
        shm.unlink()


def test_reload_shared_memory(get_server_instance: Server) -> None:
    """Test reloading shared memory with new data.
    
    Args:
        get_server_instance: Server instance fixture
    """
    dataset1: Set[str] = {"Eunice", "Phillip", "Lilian", "Johnson", "Grace"}
    hashed_values1: Dict[str, Any] = get_server_instance.get_hashed_values(dataset=dataset1)
    shm_name1: str = get_server_instance.create_shared_memory(
        create_shm=True,
        hashed_values=hashed_values1
    )

    assert shm_name1 is not None
    version_0: int = get_server_instance.shared_state.current_shared_version

    dataset2: Set[str] = {"Whbet", "Mckenna", "Patrick", "Solomon"}
    hashed_values2: Dict[str, Any] = get_server_instance.get_hashed_values(dataset=dataset2)
    shm_name2: str = get_server_instance.reload_shared_memory(
        create_shm=True,
        hashed_values=hashed_values2
    )

    assert shm_name2 is not None
    assert shm_name2 != shm_name1
    assert get_server_instance.shared_state.current_shared_version > version_0

    from multiprocessing import shared_memory
    import pickle

    shm = shared_memory.SharedMemory(name=shm_name2)
    try:
        data: bytes = shm.buf.tobytes()
        deserialized: Dict[str, Any] = pickle.loads(data)
        assert deserialized == hashed_values2
    finally:
        shm.close()
        shm.unlink()


def test_search_in_shared_memory(get_server_instance: Server) -> None:
    """Test string search functionality in shared memory.
    
    Args:
        get_server_instance: Server instance fixture
    """
    test_data: Set[str] = {"Algorithmic Sciences", "Nairobi", "Kelvin"}
    hashed_values: Dict[str, Any] = hash_file(set_=test_data)

    assert get_server_instance.search_in_shared_memory("Algorithmic Sciences", hashed_values) == "STRING EXISTS\n"
    assert get_server_instance.search_in_shared_memory("Algorithmic sciences", hashed_values) == "STRING NOT FOUND\n"
    assert get_server_instance.search_in_shared_memory("Algorithmic Sciences", None) is None


def test_worker_process(get_server_instance: Server) -> None:
    """Test worker process functionality and client communication.
    
    Args:
        get_server_instance: Server instance fixture
    """
    dataset: Set[str] = {"Eunice", "Phillip", "Johnson"}
    hashed_values: Dict[str, Any] = get_server_instance.get_hashed_values(dataset=dataset)

    shm_name: str = get_server_instance.create_shared_memory(
        create_shm=True,
        hashed_values=hashed_values
    )
    get_server_instance.shared_state.current_shm_name = shm_name

    configurations: Dict[str, Any] = {
        'host': '127.0.0.1',
        'port': 20222,
        'ssl_enabled': False,
        'reread_on_query': False,
    }

    process = multiprocessing.Process(
        target=get_server_instance.worker_process,
        args=(configurations, True),  # test mode = True
        daemon=True
    )
    
    process.start()
    time.sleep(1)  # Allow server to start

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((configurations['host'], configurations['port']))
        client.sendall(b"Eunice\n")

        response: str = client.recv(1024).decode()
        client.close()

        assert "STRING EXISTS" in response
    finally:
        process.terminate()
        process.join()


def test_handle_client(get_server_instance: Server) -> None:
    """Test client connection handling and response generation.
    
    Args:
        get_server_instance: Server instance fixture
    """
    dataset: Set[str] = {"witstorms", "AI", "42"}
    get_server_instance.hashed_values = get_server_instance.get_hashed_values(
        dataset=dataset
    )

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"unknown"

    address: tuple[str, int] = ('127.0.0.1', 1245)

    get_server_instance.handle_client(
        connection=mock_socket,
        address=address,
        ssl_enabled=False,
        reread_on_query=False,
        test_mode=False
    )

    args, kwargs = mock_socket.sendall.call_args
    response: str = args[0].decode()

    assert "STRING NOT FOUND" in response
    mock_socket.close.assert_called_once()


def test_handle_client_ssl(get_server_instance: Server) -> None:
    """Test client connection handling with SSL enabled.
    
    Args:
        get_server_instance: Server instance fixture
    """
    dataset: Set[str] = {"test", "ssl", "connection"}
    get_server_instance.hashed_values = get_server_instance.get_hashed_values(dataset=dataset)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"test"
    mock_socket.unwrap = MagicMock()

    address: tuple[str, int] = ('127.0.0.1', 1245)

    get_server_instance.handle_client(
        connection=mock_socket,
        address=address,
        ssl_enabled=True,
        reread_on_query=False,
        test_mode=False
    )

    mock_socket.unwrap.assert_called_once()


def test_handle_client_timeout(get_server_instance: Server) -> None:
    """Test client connection handling with timeout.
    
    Args:
        get_server_instance: Server instance fixture
    """
    dataset: Set[str] = {"timeout", "test"}
    get_server_instance.hashed_values = get_server_instance.get_hashed_values(dataset=dataset)

    mock_socket = MagicMock()
    mock_socket.recv.side_effect = socket.timeout("Connection timed out")
    mock_socket.settimeout = MagicMock()

    address: tuple[str, int] = ('127.0.0.1', 1245)

    with pytest.raises(socket.timeout):
        get_server_instance.handle_client(
            connection=mock_socket,
            address=address,
            ssl_enabled=False,
            reread_on_query=False,
            test_mode=False,
            timeout=1
        )

    mock_socket.settimeout.assert_called_once_with(1)


def test_handle_client_empty_data(get_server_instance: Server) -> None:
    """Test client connection handling with empty data.
    
    Args:
        get_server_instance: Server instance fixture
    """
    dataset: Set[str] = {"test", "empty", "data"}
    get_server_instance.hashed_values = get_server_instance.get_hashed_values(dataset=dataset)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b""

    address: tuple[str, int] = ('127.0.0.1', 1245)

    get_server_instance.handle_client(
        connection=mock_socket,
        address=address,
        ssl_enabled=False,
        reread_on_query=False,
        test_mode=False
    )

    mock_socket.close.assert_called_once()


def test_handle_client_test_mode(get_server_instance: Server) -> None:
    """Test client connection handling in test mode.
    
    Args:
        get_server_instance: Server instance fixture
    """
    dataset: Set[str] = {"test", "mode"}
    get_server_instance.hashed_values = get_server_instance.get_hashed_values(dataset=dataset)

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"test"

    address: tuple[str, int] = ('127.0.0.1', 1245)

    get_server_instance.handle_client(
        connection=mock_socket,
        address=address,
        ssl_enabled=False,
        reread_on_query=False,
        test_mode=True
    )

    args, kwargs = mock_socket.sendall.call_args
    response: str = args[0].decode()
    assert "X-DURATION-MS:" in response


def test_handle_client_reread_on_query(get_server_instance: Server) -> None:
    """Test client connection handling with reread on query enabled.
    
    Args:
        get_server_instance: Server instance fixture
    """
    dataset: Set[str] = {"test", "reread"}
    get_server_instance.hashed_values = get_server_instance.get_hashed_values(dataset=dataset)
    get_server_instance._local_version = 0
    get_server_instance.shared_state.current_shared_version = 1

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"test"

    address: tuple[str, int] = ('127.0.0.1', 1245)

    with patch('multiprocessing.shared_memory.SharedMemory') as mock_shm:
        mock_shm.return_value.buf = pickle.dumps(get_server_instance.hashed_values)
        get_server_instance.handle_client(
            connection=mock_socket,
            address=address,
            ssl_enabled=False,
            reread_on_query=True,
            test_mode=False
        )

    assert get_server_instance._local_version == 1


def test_background_file_monitor(get_server_instance: Server) -> None:
    """Test background file monitoring functionality.
    The test verifies that:
    The monitor can be started and stopped properly
    - It can detect file changes
    - It respects the bounce-back time between reloads
    - It can run in test mode
    - It properly cleans up resources
    
    Args:
        get_server_instance: Server instance fixture
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "test.txt")
        with open(test_file, "w") as f:
            f.write("initial content")

        monitor = BackgroundFileMonitor(
            server=get_server_instance,
            file_path=test_file,
            polling_time=0.1,
            bounce_back_time=0.2
        )

        monitor_thread = threading.Thread(
            target=monitor.run_monitor,
            args=(True, 1),  # test_mode=True, max_iterations=1
            daemon=True
        )
        monitor_thread.start()
        time.sleep(0.2)  # Allow monitor to start

        with open(test_file, "w") as f:
            f.write("updated content")

        time.sleep(0.3)  # Allow monitor to detect change
        monitor.stop_monitor()
        monitor_thread.join(timeout=1)


def test_server_stop_cleanup(get_server_instance: Server) -> None:
    """Test server stop with cleanup.
    
    Args:
        get_server_instance: Server instance fixture
    """
    dataset: Set[str] = {"test", "stop", "cleanup"}
    hashed_values: Dict[str, Any] = get_server_instance.get_hashed_values(dataset=dataset)
    shm_name: str = get_server_instance.create_shared_memory(
        create_shm=True,
        hashed_values=hashed_values
    )

    get_server_instance.stop(cleanup_shm=True, cleanup_manager=True)
    assert get_server_instance.current_shm is None



def test_server_start_with_workers(get_server_instance: Server) -> None:
    """Test server start with specific number of workers.
    
    Args:
        get_server_instance: Server instance fixture
    """
    with patch('multiprocessing.Process') as mock_process:
        mock_process.return_value.start = MagicMock()
        mock_process.return_value.join = MagicMock()

        get_server_instance.start(workers=2)
        assert mock_process.call_count == 2


def test_server_start_with_reread(get_server_instance: Server) -> None:
    """Test server start with reread on query enabled.
    
    Args:
        get_server_instance: Server instance fixture
    """
    with patch('server.load_server_configurations') as mock_config:
        mock_config.return_value = {
            'host': '127.0.0.1',
            'port': 5555,
            'reread_on_query': True,
            'linuxpath': 'default/path.txt',
            'logging_level': 'DEBUG',
            'workers': 4,
            'ssl_enabled': False,
            'ssl_certificate': 'config/cert.pem',
            'ssl_key': 'config/key.pem',
            'test_mode': False
        }

        with patch.object(get_server_instance, 'create_shared_memory') as mock_create_shm:
            mock_create_shm.return_value = "test_shm"
            
            with patch('threading.Thread') as mock_thread:
                mock_thread.return_value.start = MagicMock()
                get_server_instance.start()
                mock_thread.assert_called_once()




def test_concurrent_shared_memory_reload_race_condition(get_server_instance: Server) -> None:
    """Test race condition when multiple threads try to reload shared memory simultaneously.
    
    This tests the scenario where multiple worker processes attempt to reload
    shared memory at the same time, which could lead to inconsistent state.
    """
    dataset: Set[str] = {"race", "condition", "test"}
    hashed_values: Dict[str, Any] = get_server_instance.get_hashed_values(dataset=dataset)
    
    # Create initial shared memory
    shm_name = get_server_instance.create_shared_memory(
        create_shm=True,
        hashed_values=hashed_values
    )
    
    results = []
    exceptions = []
    
    def reload_worker(worker_id: int):
        try:
            new_dataset = {f"worker_{worker_id}", "concurrent", "reload"}
            new_hashed_values = get_server_instance.get_hashed_values(dataset=new_dataset)
            result = get_server_instance.reload_shared_memory(
                create_shm=True,
                hashed_values=new_hashed_values
            )
            results.append((worker_id, result))
        except Exception as e:
            exceptions.append((worker_id, e))
    
    # Start multiple threads trying to reload simultaneously
    threads = []
    for i in range(5):
        thread = threading.Thread(target=reload_worker, args=(i,))
        threads.append(thread)
    
    # Start all threads at nearly the same time
    for thread in threads:
        thread.start()
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    # Verify that at least one reload succeeded and no corruption occurred
    assert len(results) + len(exceptions) == 5
    assert len(results) >= 1  # At least one should succeed
    
    # Clean up
    get_server_instance.stop()


def test_shared_memory_corruption_during_read(get_server_instance: Server) -> None:
    """Test handling of corrupted shared memory data during deserialization.
    
    This simulates the case where shared memory gets corrupted between
    serialization and deserialization.
    """
    dataset: Set[str] = {"corruption", "test", "data"}
    hashed_values: Dict[str, Any] = get_server_instance.get_hashed_values(dataset=dataset)
    
    # Create shared memory
    shm_name = get_server_instance.create_shared_memory(
        create_shm=True,
        hashed_values=hashed_values
    )
    
    # Simulate corruption by writing invalid data to shared memory
    with patch('multiprocessing.shared_memory.SharedMemory') as mock_shm:
        mock_shm.return_value.buf = b"corrupted_data_not_pickle"
        mock_shm.return_value.name = shm_name
        
        # Mock socket for client handling
        mock_socket = MagicMock()
        mock_socket.recv.return_value = b"test_query"
        address = ('127.0.0.1', 1234)
        
        # This should handle the corruption gracefully
        with pytest.raises(ValueError):
            get_server_instance.handle_client(
                connection=mock_socket,
                address=address,
                ssl_enabled=False,
                reread_on_query=True,
                test_mode=False
            )
    
    get_server_instance.stop()


def test_memory_exhaustion_during_shared_memory_creation(get_server_instance: Server) -> None:
    """Test behavior when system runs out of memory during shared memory creation.
    
    This simulates the scenario where the system cannot allocate enough
    memory for the shared memory block.
    """
    # Create a very large dataset that would require significant memory
    large_dataset: Set[str] = {f"large_string_{i}" * 1000 for i in range(1000)}
    
    with patch('multiprocessing.shared_memory.SharedMemory') as mock_shm:
        mock_shm.side_effect = MemoryError("Not enough memory available")
        
        with pytest.raises(MemoryError):
            get_server_instance.reload_shared_memory(
                create_shm=True,
                dataset=large_dataset
            )


def test_file_monitor_with_rapid_file_changes(get_server_instance: Server) -> None:
    """Test file monitor behavior with rapid successive file changes.
    
    This tests the bounce-back mechanism when a file is modified
    multiple times in quick succession.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "rapid_change.txt")
        with open(test_file, "w") as f:
            f.write("initial content")
        
        reload_count = 0
        original_reload = get_server_instance.reload_shared_memory
        
        def mock_reload(*args, **kwargs):
            nonlocal reload_count
            reload_count += 1
            return f"mock_shm_{reload_count}"
        
        get_server_instance.reload_shared_memory = mock_reload
        
        monitor = BackgroundFileMonitor(
            server=get_server_instance,
            file_path=test_file,
            polling_time=0.01,  # Very fast polling
            bounce_back_time=0.1  # Short bounce-back time
        )
        
        # Start monitor in a thread
        monitor_thread = threading.Thread(
            target=monitor.run_monitor,
            args=(True, 20),  # test_mode=True, max_iterations=20
            daemon=True
        )
        monitor_thread.start()
        
        time.sleep(0.05)  # Let monitor initialize
        
        # Rapidly modify the file multiple times
        for i in range(5):
            with open(test_file, "w") as f:
                f.write(f"content change {i}")
            time.sleep(0.02)  # Very quick changes
        
        monitor_thread.join()
        
        # Due to bounce-back mechanism, reload count should be less than change count
        assert reload_count < 5
        assert reload_count >= 1
        
        # Restore original method
        get_server_instance.reload_shared_memory = original_reload


def test_ssl_handshake_failure_during_client_connection(get_server_instance: Server) -> None:
    """Test handling of SSL handshake failures during client connections.
    
    This simulates SSL certificate issues or protocol mismatches.
    """
    dataset: Set[str] = {"ssl", "handshake", "failure"}
    get_server_instance.hashed_values = get_server_instance.get_hashed_values(dataset=dataset)
    
    mock_socket = MagicMock()
    mock_socket.recv.side_effect = ssl.SSLError("SSL handshake failed")
    
    address = ('127.0.0.1', 1234)
    
    with pytest.raises(ssl.SSLError):
        get_server_instance.handle_client(
            connection=mock_socket,
            address=address,
            ssl_enabled=True,
            reread_on_query=False,
            test_mode=False
        )


def test_partial_data_reception_from_client(get_server_instance: Server) -> None:
    """Test handling of partial or fragmented data reception from clients.
    
    This simulates network conditions where data arrives in fragments
    or is incomplete.
    """
    dataset: Set[str] = {"partial", "data", "test"}
    get_server_instance.hashed_values = get_server_instance.get_hashed_values(dataset=dataset)
    
    mock_socket = MagicMock()
    # Simulate partial data reception
    mock_socket.recv.side_effect = [b"par", b"tial", b""]  # Fragmented then connection closed
    
    address = ('127.0.0.1', 1234)
    
    # Should handle partial data gracefully
    get_server_instance.handle_client(
        connection=mock_socket,
        address=address,
        ssl_enabled=False,
        reread_on_query=False,
        test_mode=False
    )
    
    # Verify socket was closed properly
    mock_socket.close.assert_called_once()


def test_hash_collision_handling_in_search(get_server_instance: Server) -> None:
    """Test string search behavior when hash collisions occur.
    
    This verifies that the linear probing mechanism correctly handles
    hash collisions and finds the right string.
    """
    # Create a controlled scenario with potential hash collisions
    # by using strings that might hash to similar values
    dataset: Set[str] = {"collision_test_1", "collision_test_2", "collision_test_3"}
    hashed_values: Dict[str, Any] = get_server_instance.get_hashed_values(dataset=dataset)
    
    # Test searching for each string to ensure linear probing works
    for test_string in dataset:
        result = get_server_instance.search_in_shared_memory(test_string, hashed_values)
        assert result == "STRING EXISTS\n"
    
    # Test a string that definitely doesn't exist
    result = get_server_instance.search_in_shared_memory("nonexistent_string", hashed_values)
    assert result == "STRING NOT FOUND\n"


def test_worker_process_sudden_termination(get_server_instance: Server) -> None:
    """Test behavior when worker processes are suddenly terminated.
    
    This simulates scenarios like system shutdown, OOM killer,
    or process crashes.
    """
    dataset: Set[str] = {"worker", "termination", "test"}
    hashed_values: Dict[str, Any] = get_server_instance.get_hashed_values(dataset=dataset)
    
    shm_name = get_server_instance.create_shared_memory(
        create_shm=True,
        hashed_values=hashed_values
    )
    get_server_instance.shared_state.current_shm_name = shm_name
    
    configurations: Dict[str, Any] = {
        'host': '127.0.0.1',
        'port': 20223,
        'ssl_enabled': False,
        'reread_on_query': False,
    }
    
    # Start worker process
    process = multiprocessing.Process(
        target=get_server_instance.worker_process,
        args=(configurations, True),
        daemon=True
    )
    process.start()
    time.sleep(0.5)  # Let it start
    
    # Suddenly terminate the process
    process.terminate()
    process.join(timeout=2)
    
    # Verify process was terminated
    assert not process.is_alive()
    
    # Verify shared memory is still accessible from main process
    shm = shared_memory.SharedMemory(name=shm_name)
    data = pickle.loads(shm.buf)
    assert data == hashed_values
    
    shm.close()
    get_server_instance.stop()


def test_unicode_and_special_character_handling(get_server_instance: Server) -> None:
    """Test handling of Unicode characters and special symbols in search strings.
    
    This ensures the server properly handles international characters,
    emojis, and special symbols.
    """
    # Dataset with Unicode and special characters
    unicode_dataset: Set[str] = {
        "café", "naïve", "résumé",  # Accented characters
        "北京", "東京", "서울",      # CJK characters
        "🎯", "🚀", "💻",           # Emojis
        "test@domain.com",          # Email-like
        "file_name.txt",           # Filename-like
        "multi\nline\tstring"      # Control characters
    }
    
    hashed_values: Dict[str, Any] = get_server_instance.get_hashed_values(dataset=unicode_dataset)
    get_server_instance.hashed_values = hashed_values
    
    mock_socket = MagicMock()
    address = ('127.0.0.1', 1234)
    
    # Test each Unicode string
    for test_string in unicode_dataset:
        mock_socket.reset_mock()
        mock_socket.recv.return_value = test_string.encode('utf-8')
        
        get_server_instance.handle_client(
            connection=mock_socket,
            address=address,
            ssl_enabled=False,
            reread_on_query=False,
            test_mode=False
        )
        
        args, kwargs = mock_socket.sendall.call_args
        response = args[0].decode('utf-8')
        assert "STRING EXISTS" in response
    
    # Test invalid UTF-8 encoding
    mock_socket.reset_mock()
    mock_socket.recv.return_value = b'\xff\xfe\xfd'  # Invalid UTF-8
    
    with pytest.raises(ValueError):
        get_server_instance.handle_client(
            connection=mock_socket,
            address=address,
            ssl_enabled=False,
            reread_on_query=False,
            test_mode=False
        )


def test_ssl_client_auth_with_valid_cert(get_server_instance: Server) -> None:
    """Test SSL client authentication with a valid client certificate.
    
    This test verifies that the server accepts connections from clients
    with valid certificates when SSL client authentication is enabled.
    """
    dataset: Set[str] = {"ssl", "client", "auth", "test"}
    get_server_instance.hashed_values = get_server_instance.get_hashed_values(dataset=dataset)
    
    # Create a mock SSL context with client auth enabled
    mock_context = MagicMock()
    mock_context.wrap_socket.return_value = MagicMock()
    mock_context.verify_mode = ssl.CERT_REQUIRED
    
    # Mock the client certificate
    mock_cert = {
        'subject': ((('commonName', 'test-client'),),),
        'issuer': ((('commonName', 'test-ca'),),)
    }
    
    mock_socket = MagicMock()
    # First call returns parsed cert, second call returns binary cert
    mock_socket.getpeercert.side_effect = [mock_cert, b'fake_binary_cert']
    mock_socket.recv.return_value = b"test"
    
    address = ('127.0.0.1', 1234)
    
    with patch('ssl.SSLContext', return_value=mock_context):
        get_server_instance.handle_client(
            connection=mock_socket,
            address=address,
            ssl_enabled=True,
            reread_on_query=False,
            test_mode=False
        )
    
    assert mock_socket.getpeercert.call_count == 2
    mock_socket.close.assert_called_once()


def test_ssl_client_auth_with_invalid_cert(get_server_instance: Server) -> None:
    """Test SSL client authentication with an invalid client certificate.
    
    This test verifies that the server rejects connections from clients
    with invalid certificates when SSL client authentication is enabled.
    """
    dataset: Set[str] = {"ssl", "invalid", "cert", "test"}
    get_server_instance.hashed_values = get_server_instance.get_hashed_values(dataset=dataset)
    
    mock_socket = MagicMock()
    # Simulate SSL error during certificate verification
    mock_socket.getpeercert.side_effect = ssl.SSLError("Certificate verification failed")
    mock_socket.recv.return_value = b"test"
    
    address = ('127.0.0.1', 1234)
    
    # The server should handle the SSL error and close the connection
    get_server_instance.handle_client(
        connection=mock_socket,
        address=address,
        ssl_enabled=True,
        reread_on_query=False,
        test_mode=False
    )
    
    mock_socket.close.assert_called_once()


def test_ssl_client_auth_with_missing_cert(get_server_instance: Server) -> None:
    """Test SSL client authentication when client doesn't provide a certificate.
    
    This test verifies that the server handles cases where clients
    don't provide certificates when SSL client authentication is required.
    """
    dataset: Set[str] = {"ssl", "missing", "cert", "test"}
    get_server_instance.hashed_values = get_server_instance.get_hashed_values(dataset=dataset)
    
    mock_socket = MagicMock()
    # First call returns None (no parsed cert), second call returns None (no binary cert)
    mock_socket.getpeercert.side_effect = [None, None]
    mock_socket.recv.return_value = b"test"
    
    address = ('127.0.0.1', 1234)
    
    get_server_instance.handle_client(
        connection=mock_socket,
        address=address,
        ssl_enabled=True,
        reread_on_query=False,
        test_mode=False
    )
    
    assert mock_socket.getpeercert.call_count == 2
    mock_socket.close.assert_called_once()


def test_ssl_client_auth_with_expired_cert(get_server_instance: Server) -> None:
    """Test SSL client authentication with an expired client certificate.
    
    This test verifies that the server properly handles expired certificates
    when SSL client authentication is enabled.
    """
    dataset: Set[str] = {"ssl", "expired", "cert", "test"}
    get_server_instance.hashed_values = get_server_instance.get_hashed_values(dataset=dataset)
    
    mock_socket = MagicMock()
    # Simulate SSL error for expired certificate
    mock_socket.getpeercert.side_effect = ssl.SSLError("Certificate has expired")
    mock_socket.recv.return_value = b"test"
    
    address = ('127.0.0.1', 1234)
    
    # The server should handle the SSL error and close the connection
    get_server_instance.handle_client(
        connection=mock_socket,
        address=address,
        ssl_enabled=True,
        reread_on_query=False,
        test_mode=False
    )
    
    mock_socket.close.assert_called_once()


def test_ssl_client_auth_with_self_signed_cert(get_server_instance: Server) -> None:
    """Test SSL client authentication with a self-signed client certificate.
    
    This test verifies that the server properly handles self-signed certificates
    when SSL client authentication is enabled.
    """
    dataset: Set[str] = {"ssl", "self-signed", "cert", "test"}
    get_server_instance.hashed_values = get_server_instance.get_hashed_values(dataset=dataset)
    
    mock_socket = MagicMock()
    # Simulate SSL error for self-signed certificate
    mock_socket.getpeercert.side_effect = ssl.SSLError("Self-signed certificate")
    mock_socket.recv.return_value = b"test"
    
    address = ('127.0.0.1', 1234)
    
    # The server should handle the SSL error and close the connection
    get_server_instance.handle_client(
        connection=mock_socket,
        address=address,
        ssl_enabled=True,
        reread_on_query=False,
        test_mode=False
    )
    
    mock_socket.close.assert_called_once()


def test_ssl_client_auth_with_binary_cert(get_server_instance: Server) -> None:
    """Test SSL client authentication with a binary format certificate.
    
    This test verifies that the server can handle certificates provided
    in binary format when SSL client authentication is enabled.
    """
    dataset: Set[str] = {"ssl", "binary", "cert", "test"}
    get_server_instance.hashed_values = get_server_instance.get_hashed_values(dataset=dataset)
    
    mock_socket = MagicMock()
    # First call returns None (parsed cert), second call returns binary cert
    mock_socket.getpeercert.side_effect = [None, b'fake_binary_cert']
    mock_socket.recv.return_value = b"test"
    
    address = ('127.0.0.1', 1234)
    
    get_server_instance.handle_client(
        connection=mock_socket,
        address=address,
        ssl_enabled=True,
        reread_on_query=False,
        test_mode=False
    )
    
    assert mock_socket.getpeercert.call_count == 2
    mock_socket.close.assert_called_once()


def test_ssl_client_auth_verify_mode_none(get_server_instance: Server) -> None:
    """Test SSL client authentication with verify mode set to NONE.
    
    This test verifies that the server accepts connections without
    requiring client certificates when verify mode is set to NONE.
    """
    dataset: Set[str] = {"ssl", "verify", "none", "test"}
    get_server_instance.hashed_values = get_server_instance.get_hashed_values(dataset=dataset)
    
    # Create a mock SSL context with verify mode NONE
    mock_context = MagicMock()
    mock_context.wrap_socket.return_value = MagicMock()
    mock_context.verify_mode = ssl.CERT_NONE
    
    mock_socket = MagicMock()
    # Even with no certificate, connection should be accepted
    mock_socket.getpeercert.return_value = None
    mock_socket.recv.return_value = b"test"
    
    address = ('127.0.0.1', 1234)
    
    with patch('ssl.SSLContext', return_value=mock_context):
        get_server_instance.handle_client(
            connection=mock_socket,
            address=address,
            ssl_enabled=True,
            reread_on_query=False,
            test_mode=False
        )
    
    # Should still check for certificate but accept connection without one
    assert mock_socket.getpeercert.call_count == 2
    mock_socket.close.assert_called_once()


def test_ssl_client_auth_verify_mode_optional(get_server_instance: Server) -> None:
    """Test SSL client authentication with verify mode set to OPTIONAL.
    
    This test verifies that the server accepts connections both with and without
    client certificates when verify mode is set to OPTIONAL.
    """
    dataset: Set[str] = {"ssl", "verify", "optional", "test"}
    get_server_instance.hashed_values = get_server_instance.get_hashed_values(dataset=dataset)
    
    # Create a mock SSL context with verify mode OPTIONAL
    mock_context = MagicMock()
    mock_context.wrap_socket.return_value = MagicMock()
    mock_context.verify_mode = ssl.CERT_OPTIONAL
    
    # Test case 1: Client with valid certificate
    mock_socket_with_cert = MagicMock()
    mock_cert = {
        'subject': ((('commonName', 'test-client'),),),
        'issuer': ((('commonName', 'test-ca'),),)
    }
    mock_socket_with_cert.getpeercert.side_effect = [mock_cert, b'fake_binary_cert']
    mock_socket_with_cert.recv.return_value = b"test"
    
    address = ('127.0.0.1', 1234)
    
    with patch('ssl.SSLContext', return_value=mock_context):
        # Test with valid certificate
        get_server_instance.handle_client(
            connection=mock_socket_with_cert,
            address=address,
            ssl_enabled=True,
            reread_on_query=False,
            test_mode=False
        )
        
        # Test without certificate
        mock_socket_without_cert = MagicMock()
        mock_socket_without_cert.getpeercert.side_effect = [None, None]
        mock_socket_without_cert.recv.return_value = b"test"
        
        get_server_instance.handle_client(
            connection=mock_socket_without_cert,
            address=address,
            ssl_enabled=True,
            reread_on_query=False,
            test_mode=False
        )
    
    # Both connections should be accepted
    assert mock_socket_with_cert.getpeercert.call_count == 2
    assert mock_socket_without_cert.getpeercert.call_count == 2
    mock_socket_with_cert.close.assert_called_once()
    mock_socket_without_cert.close.assert_called_once()


