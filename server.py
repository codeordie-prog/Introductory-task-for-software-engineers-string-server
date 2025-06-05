from logger_setup import Logger
from config import load_server_configurations
from hashfile import (remove_duplicates, hash_file)
from typing import Optional, Dict, Any, List, Union, Tuple, Set
from multiprocessing import shared_memory, Process, Manager
import uuid
import datetime
import os
import multiprocessing
import threading
import time
import pickle
import ssl
import socket
import mmh3
import re


class Server:
    """A high-performance server implementation for string search operations.
    
    This server implements a multi-process architecture with shared memory for efficient
    string search operations. It uses SSL for secure communications and supports
    multiple worker processes for handling concurrent requests.
    
    Key Features:
        - Multi-process architecture with shared memory.
        - SSL/TLS support for secure communications.
        - Concurrent request handling with worker processes.
        - Efficient string search using hash-based lookup.
        - Configurable number of worker processes.
        - Comprehensive logging.
        
    Attributes:
        logger (Logger): Logger instance for tracking server operations.
        shm_name (str): Name of the shared memory block.
        manager (Manager): Multiprocessing manager for shared state.
        shared_state (Namespace): Shared state across processes.
        current_shm (Optional[shared_memory.SharedMemory]): Current shared memory block.
        hashed_values (Optional[Dict[str, Any]]): Current hashed values.
        thread_lock (threading.Lock): Lock for thread synchronization.
    """
    
    def __init__(self, logger: Logger = Logger(logging_level="DEBUG")) -> None:
        """Initialize the server with a logger.
        
        Args:
            logger (Logger, optional): Logger instance. Defaults to a new Logger instance.
        """
        self.logger: Logger = logger
        self.shm_name: str = "200k_shm"
        self.manager = multiprocessing.Manager()
        self.shared_state = self.manager.Namespace()
        self.shared_state.current_shm_name = None 
        self.current_shm: Optional[shared_memory.SharedMemory] = None
        self._local_version: int = -1
        self.shared_state.current_shared_version = 0
        self.hashed_values: Optional[Dict[str, Any]] = None
        self.thread_lock: threading.Lock = threading.Lock()

    def get_hashed_values(
        self,
        config_file_path: Optional[str] = None,
        dataset: Optional[Set] = None,
        file_path: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Get the hashed values of the file.
        
        Args:
            config_file_path (Optional[str]): Path to the configuration file. If None, uses the default configurations.
            dataset (Optional[Set]): Pre-existing dataset to use instead of reading from file.
            file_path (Optional[str]): Direct path to the input file. If provided, overrides config file path.
            
        Returns:
            Optional[Dict[str, Any]]: Dictionary containing hashed values if successful,
                                    None if file not found or an error occurs.
                                    
        Raises:
            FileNotFoundError: If the specified file path does not exist and no dataset is provided.
            ValueError: If the configuration file is invalid or missing required fields.
            PermissionError: If there are insufficient permissions to read the file.
            OSError: For general file system related errors.
        """
        config: Dict[str, Any] = (load_server_configurations(config_file_path) if config_file_path
                                  else load_server_configurations())
        
        # Use provided file_path if available, otherwise use from the server configuration file.
        linuxpath: str = file_path if file_path is not None else config.get("linuxpath", "")

        try:
            if not os.path.exists(linuxpath) and dataset is None:
                self.logger.error(f"File not found in the Linux path provided: {linuxpath}")
                raise FileNotFoundError(f"Input file not found at path: {linuxpath}. Please verify the file exists and the path is correct.")

            start_time: float = time.time()

            if dataset is not None:
                myset = dataset
            else:
                try:
                    myset = remove_duplicates(linuxpath)
                except PermissionError as e:
                    self.logger.error(f"Permission denied while reading file {linuxpath}: {e}")
                    raise PermissionError(f"Insufficient permissions to read file {linuxpath}. Please check file permissions.") from e
                except OSError as e:
                    self.logger.error(f"OS error while reading file {linuxpath}: {e}")
                    raise OSError(f"Error accessing file {linuxpath}: {e}") from e

            try:
                index: Dict[str, Any] = hash_file(myset)
            except ValueError as e:
                self.logger.error(f"Error during hash file operation: {e}")
                raise ValueError(f"Failed to hash file contents: {e}") from e

            duration: float = time.time() - start_time
            self.logger.debug(f"Generated hashed values in {duration * 1000:.5f} ms")
            
            return index
            
        except FileNotFoundError as e:
            self.logger.error(f"File not found error: {e}")
            self.logger.debug("""Troubleshooting steps:
                1. Verify the linuxpath key in the configuration file points to a valid file
                2. Ensure the dataset argument is not None if using a dataset
                3. Check if the file exists at the specified path
                4. Verify file permissions and access rights""")
            return None
        
        except ValueError as e:
            self.logger.error(f"Value error during hash generation: {e}")
            return None
            
        except PermissionError as e:
            self.logger.error(f"Permission error: {e}")
            return None
            
        except OSError as e:
            self.logger.error(f"OS error during file operations: {e}")
            return None
            
        except Exception as e:
            self.logger.error(f"Unexpected error in get_hashed_values method: {e}")
            self.logger.debug(f"Error type: {type(e).__name__}, Error details: {str(e)}")
            return None

    def serialize_hashed_values(self, hashed_values: Dict[str, Any]) -> bytes:
        """Serialize hashed values for shared memory storage.
        
        Args:
            hashed_values (Dict[str, Any]): Dictionary containing hashed values.
            
        Returns:
            bytes: Serialized hashed values.
        """
        return pickle.dumps(hashed_values, protocol=pickle.HIGHEST_PROTOCOL)

    def create_shared_memory(
        self,
        shm_name: str = "200k_shm",
        create_shm: bool = True,
        hashed_values: Optional[Dict[str, Any]] = None,
        config_file_path: Optional[str] = None,
        dataset: Optional[Set] = None,
        file_path: Optional[str] = None
    ) -> Optional[str]:
        """Create shared memory for storing hashed values.
        
        Args:
            shm_name (str, optional): Name of shared memory block. Defaults to "200k_shm".
            create_shm (bool, optional): Whether to actually create shared memory. Defaults to True.
            hashed_values (Optional[Dict[str, Any]], optional): Pre-computed hashed values.
            config_file_path (Optional[str], optional): Path to config file for getting hashed values.
            dataset (Optional[Set], optional): Dataset to use for generating hashed values.
            file_path (Optional[str], optional): Direct path to input file for generating hashed values.
            
        Returns:
            Optional[str]: Name of the created shared memory block if successful,
                         None if creation fails.
        """
        try:
            if create_shm:
                try:
                    # Clean up shared memory if it exists.
                    name: str = self.current_shm.name if self.current_shm else shm_name
                    previous: shared_memory.SharedMemory = shared_memory.SharedMemory(name=name)
                    previous.close()
                    previous.unlink()
                    self.logger.warning(f"Previous shared memory: '{name}' unlinked")
                
                except FileNotFoundError:
                    pass  # It's not yet created

            # Get hashed values from provided source or generate new ones.
            if hashed_values is None:
                hashed_values = self.get_hashed_values(
                    config_file_path=config_file_path,
                    dataset=dataset,
                    file_path=file_path
                )
                
            if hashed_values is None:
                raise ValueError("Failed to get hashed values")
                
            serialized_values: bytes = self.serialize_hashed_values(hashed_values)
            size: int = len(serialized_values)

            if create_shm:
                # Set serialized values in block.
                shm: shared_memory.SharedMemory = shared_memory.SharedMemory(
                    name=shm_name, create=True, size=size
                )
                shm.buf[:size] = serialized_values

                # Update current shared memory name.
                self.current_shm = shm
                self.shared_state.current_shm_name = shm.name  # Shared across the workers.
                self.shared_state.current_shared_version += 1

                self.logger.debug(f"Shared memory '{shm_name}' created with size: {size / 1024:.2f} KB")
                return shm.name
            else:
                # Return the name that would have been used.
                return shm_name
        
        except ValueError as e:
            self.logger.error(f"Failed to get hashed values: {e}")
            return None

    def reload_shared_memory(
        self,
        create_shm: bool = True,
        hashed_values: Optional[Dict[str, Any]] = None,
        config_file_path: Optional[str] = None,
        dataset: Optional[Set] = None,
        file_path: Optional[str] = None
    ) -> Optional[str]:
        """Reload shared memory with updated hashed values.
        
        This method creates a new shared memory block with updated values
        and safely swaps it with the old one.
        
        Args:
            create_shm (bool, optional): Whether to actually create shared memory. Defaults to True.
            hashed_values (Optional[Dict[str, Any]], optional): Pre-computed hashed values to use.
            config_file_path (Optional[str], optional): Path to the server configuration file.
            dataset (Optional[Set], optional): Dataset to use for generating hashed values.
            file_path (Optional[str], optional): Direct path to input file for generating hashed values.
        
        Returns:
            Optional[str]: Name of the new shared memory block if successful, None if reload fails.
            
        Raises:
            ValueError: If hashed values cannot be generated or are invalid.
            OSError: If there are issues with shared memory operations.
            MemoryError: If there is insufficient memory to create shared memory block.
            RuntimeError: If there are issues with the shared memory state.
        """
        with self.thread_lock:
            try:
                # Get hashed values from provided source or generate new ones.
                if hashed_values is None:
                    hashed_values = self.get_hashed_values(
                        config_file_path=config_file_path,
                        dataset=dataset,
                        file_path=file_path
                    )
                    
                if hashed_values is None:
                    raise ValueError("Failed to get hashed values for reload")

                # Serialize the values.
                try:
                    serialized_values: bytes = self.serialize_hashed_values(hashed_values)
                except (pickle.PicklingError, TypeError) as e:
                    self.logger.error(f"Failed to serialize hashed values: {e}")
                    raise ValueError(f"Invalid hashed values format: {e}")
                    
                size: int = len(serialized_values)

                if not create_shm:
                    return f"200k_shm_{uuid.uuid4().hex}"

                try:
                    new_shm_name: str = f"200k_shm_{uuid.uuid4().hex}"
                    new_shm: shared_memory.SharedMemory = shared_memory.SharedMemory(
                        new_shm_name, create=True, size=size
                    )
                    new_shm.buf[:size] = serialized_values
                    self.shared_state.current_shm_name = new_shm.name

                    # Update the shared state version.
                    self.shared_state.current_shared_version += 1
                
                except FileExistsError:
                    import random
                    try:
                        # Recreate shared memory with a different name.
                        new_shm = shared_memory.SharedMemory(
                            f"{self.current_shm.name + str(random.randint(0, 100))}",
                            create=True,
                            size=size
                        )
                        self.shared_state.current_shm_name = new_shm.name

                        # Update the shared state version.
                        self.shared_state.current_shared_version += 1
                    except Exception as e:
                        self.logger.error(f"Failed to create alternative shared memory: {e}")
                        raise RuntimeError(f"Failed to create alternative shared memory after name conflict: {e}")

                except MemoryError as e:
                    self.logger.error(f"Insufficient memory to create shared memory block: {e}")
                    raise MemoryError(f"Not enough memory to create shared memory block of size {size} bytes") from e

                # Swap the old shared memory with the new shared memory.
                old_shm: Optional[shared_memory.SharedMemory] = self.current_shm
                self.current_shm = new_shm
                self.hashed_values = hashed_values

                # Briefly pause to let any in-flight reads finish.
                time.sleep(0.01)

                # Unlink old shared memory.
                if old_shm:
                    try:
                        old_shm.close()
                        try:
                            old_shm.unlink()
                            self.logger.debug(f"Successfully unlinked old shared memory: {old_shm.name}")
                        except FileNotFoundError:
                            self.logger.warning(f"Old shared memory {old_shm.name} already unlinked")
                    except Exception as e:
                        self.logger.error(f"Error cleaning up old shared memory: {e}")
                        # Don't raise here as the new memory is already set up

                self.shm_name = new_shm_name
                self.logger.debug(f"New shared memory block created with name: {new_shm_name}")
                return new_shm_name

            except ValueError as e:
                self.logger.error(f"Value error during shared memory reload: {e}")
                raise
            except OSError as e:
                self.logger.error(f"OS error during shared memory operations: {e}")
                raise
            except MemoryError as e:
                self.logger.error(f"Memory error during shared memory creation: {e}")
                raise
            except RuntimeError as e:
                self.logger.error(f"Runtime error during shared memory reload: {e}")
                raise
            except Exception as e:
                self.logger.error(f"Unexpected error during shared memory reload: {e}")
                self.logger.debug(f"Error type: {type(e).__name__}, Error details: {str(e)}")
                raise RuntimeError(f"Failed to reload shared memory: {e}") from e

    def search_in_shared_memory(
        self,
        string: str,
        hashed_values: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """Search for a string in shared memory using hash-based lookup.
        
        Args:
            string (str): String to search for
            hashed_values (Optional[Dict[str, Any]], optional): Dictionary containing hashed values.
                                                              If None, uses instance hashed_values.
            
        Returns:
            Optional[str]: "STRING EXISTS" if found, "STRING NOT FOUND" if not found,
                          None if an error occurs.
        """
        try:
            # Use provided hashed_values or instance hashed_values.
            values_dict = hashed_values if hashed_values is not None else self.hashed_values
            if values_dict is None:
                raise ValueError("No hashed values provided")

            total_size: int = values_dict['total_size']
            values: List[Optional[str]] = values_dict['values']

            # Hash the string.
            hashed_string_index: int = mmh3.hash(string, signed=False) % total_size
            start_index: int = hashed_string_index

            # Use regular expression to compare the string with the value retrieved.
            if values[hashed_string_index] is not None and re.fullmatch(re.escape(string), values[hashed_string_index]):
                return "STRING EXISTS\n"

            # Linear probing.
            while values[hashed_string_index] is not None:
                if values[hashed_string_index] is not None and re.fullmatch(re.escape(string), values[hashed_string_index]):
                    return "STRING EXISTS\n"
                
                # Increment index.
                hashed_string_index = (hashed_string_index + 1) % total_size
                if hashed_string_index == start_index:  # You've returned where you started.
                    break

            return "STRING NOT FOUND\n"

        except Exception as e:
            self.logger.error(f"An error occurred in shared memory String lookup process: {e}")
            return None

    def worker_process(
        self,
        configurations: Dict[str, Any],
        test_mode: bool = False
    ) -> None:
        """Worker process that handles client connections.
        
        Args:
            configurations (Dict[str, Any]): Dictionary containing server configurations.
            test_mode (bool, optional): Whether to run in test mode. Defaults to False.
        """
        # Get current name from the shared state.
        shm_name: str = self.shared_state.current_shm_name
        shm: shared_memory.SharedMemory = shared_memory.SharedMemory(shm_name)

        # Deserialize and update hashed values.
        hashed_values: Dict[str, Any] = pickle.loads(shm.buf)
        self.hashed_values = hashed_values

        # Set the local version.
        self._local_version = self.shared_state.current_shared_version
      
        server_socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Reuse address and port.
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        # Check if SSL is enabled.
        if configurations.get('ssl_enabled'):
            context: ssl.SSLContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(
                certfile=configurations['ssl_certificate'],
                keyfile=configurations['ssl_key'],
            )

            # Configure client's authentication if enabled
            if configurations.get('ssl_client_auth', False):
                # Load Client Authority certificate for verification
                context.load_verify_locations(cafile=configurations['ssl_ca_certificate'])
                self.logger.debug("Client Authority cert loaded")
            
                # set verification mode
                verify_mode: str = configurations.get('ssl_verify_mode','CERT_REQUIRED')
                if verify_mode == 'CERT_REQUIRED':
                    context.verify_mode = ssl.CERT_REQUIRED
                elif verify_mode == 'CERT_OPTIONAL':
                    context.verify_mode = ssl.CERT_OPTIONAL
                else:
                    context.verify_mode = ssl.CERT_NONE

                
                # check hostname if required
                context.check_hostname = False # Set to True for hostname verification

            if configurations.get('ssl_ciphers'):
                context.set_ciphers(configurations['ssl_ciphers'])

            # Additional security settings
            context.minimum_version = ssl.TLSVersion.TLSv1_2
           
            server_socket = context.wrap_socket(server_socket, server_side=True)

        # Bind and listen.
        server_socket.bind((configurations['host'], configurations['port']))
        server_socket.listen(100)

        self.logger.debug(
            f"Worker: {os.getpid()} listening on {configurations['host']}:{configurations['port']}"
        )

        while True:
            try:
                connection: socket.socket
                address: Tuple[str, int]
                connection, address = server_socket.accept()

                if configurations.get('ssl_enabled') and hasattr(connection, 'getpeercert'):
                    try:
                        client_cert: Dict[str, Any] = connection.getpeercert()
                        if client_cert:
                            subject: Dict[str, str] = dict(x[0] for x in client_cert['subject'])
                            client_name: str = subject.get('commonName','Unknown')
                        
                            self.logger.debug(f"Client authenticated - CN: {client_name} from {address[0]}:{address[1]}")
                        else:
                            self.logger.warning(f"No client certificate from {address[0]}:{address[1]}")

                    except ssl.SSLError as e:
                        self.logger.error(f"SSL certificate verification failed for {address[0]}:{address[1]}: {e}")
                        connection.close()
                        continue
              
                # Handle client in a new thread.
                threading.Thread(
                    target=self.handle_client,
                    args=(
                        connection,
                        address,
                        configurations['ssl_enabled'],
                        configurations['reread_on_query'],
                        test_mode
                    ),
                    daemon=True
                ).start()

            except KeyboardInterrupt:
                break

            except ssl.SSLError as e:
                self.logger.error(f"SSL handshake failed: {e}")
                continue

            except Exception as e:
                self.logger.error(f"Error in worker {os.getpid()}: {e}")

    def handle_client(
        self,
        connection: socket.socket,
        address: Tuple[str, int],
        ssl_enabled: bool = False,
        reread_on_query: bool = False,
        test_mode: bool = False,
        timeout: int = 1500
    ) -> None:
        """Handle individual client connections.
        
        Args:
            connection (socket.socket): Client socket connection.
            address (Tuple[str, int]): Client IP address and port.
            ssl_enabled (bool, optional): Whether SSL is enabled. Defaults to False.
            reread_on_query (bool, optional): Whether to reread shared memory on query. Defaults to False.
            test_mode (bool, optional): Whether to include execution time in response. Defaults to False.
            timeout (int, optional): Connection timeout in seconds. Defaults to 1500.
            
        Raises:
            socket.timeout: If the connection times out during operations.
            ConnectionError: If there are issues with the client connection.
            ssl.SSLError: If there are SSL/TLS related errors.
            ValueError: If there are issues with data encoding/decoding.
            OSError: For general socket or file system related errors.
        """
        try:
            # Set the connection timeout.
            connection.settimeout(timeout)

            #Verify client certificate if ssl authentication is enabled
            if ssl_enabled and hasattr(connection, 'getpeercert'):
                try:
                    client_cert: Dict[str, Any] = connection.getpeercert()

                    # Also try binary form to double check
                    client_cert_binary: Optional[bytes] = connection.getpeercert(binary_form=True)

                    if client_cert:
                        # Log client certificate details
                        subject: Dict[str, str] = dict(x[0] for x in client_cert['subject'])
                        issuer: Dict[str, str] = dict(x[0] for x in client_cert.get('issuer',[]))

                        client_name: str = subject.get('commonName', 'Unknown')
                        issuer_name: str = issuer.get('commonName', 'Unknown')

                        # Log detailed certificate info
                        self.logger.debug(f"Client authenticated - CN: {client_name}, Issuer: {issuer_name}, from {address[0]}:{address[1]}")
                    
                    elif client_cert_binary:
                        # Got certificate in binary form but not parsed - still valid
                        self.logger.debug(f"Client certificate verified (binary form) from {address[0]}:{address[1]}")

                    else:
                        # This should not happen with CERT_REQUIRED, but log for debugging
                        self.logger.debug(f"SSL connection established (no cert info available) from {address[0]}:{address[1]}")

                except ssl.SSLError as e:
                    self.logger.error(f"SSL certificate verification failed for {address[0]}:{address[1]}")
                    return

            try:
                # Get the requested string.
                data: bytes = connection.recv(1024)
                if not data:
                    self.logger.warning(f"Empty data received from client {address[0]}:{address[1]}")
                    return
                    
                string: str = data.decode().strip()
                self.logger.debug(f"Received request from IP: {address[0]}:{address[1]} for search query: {string}")
                
            except socket.timeout:
                self.logger.error(f"Connection timeout for client {address[0]}:{address[1]}")
                raise socket.timeout(f"Client connection timed out after {timeout} seconds")
            except UnicodeDecodeError as e:
                self.logger.error(f"Failed to decode client data: {e}")
                raise ValueError(f"Invalid data encoding from client: {e}")
                
            start_time: float = time.perf_counter()

            if reread_on_query:
                try:
                    with self.thread_lock:
                        current_version: int = self.shared_state.current_shared_version
                        if current_version != self._local_version:
                            # Deserialize new shared memory.
                            shm_name: str = self.shared_state.current_shm_name
                            shm: shared_memory.SharedMemory = shared_memory.SharedMemory(shm_name)
                            self.hashed_values = pickle.loads(shm.buf)
                            self._local_version = current_version
                except FileNotFoundError as e:
                    self.logger.error(f"Shared memory not found during reread: {e}")
                    raise OSError(f"Failed to access shared memory during reread: {e}")
                except pickle.UnpicklingError as e:
                    self.logger.error(f"Failed to unpickle shared memory data: {e}")
                    raise ValueError(f"Invalid shared memory data format: {e}")
        
            hashed_values: Optional[Dict[str, Any]] = self.hashed_values

            if not string:
                result: str = "STRING NOT FOUND"
            else:
                result = self.search_in_shared_memory(string, hashed_values)

            duration: float = time.perf_counter() - start_time
            self.logger.debug(f"Execution time: {duration * 1000:.5f} milliseconds")

            if result is None:
                result = "ERROR - Returned NONE object\n"

            try:
                # Include execution time if in test mode.
                if test_mode:
                    response: str = f"{result.strip()}\nX-DURATION-MS:{duration*1000:.5f}\n"
                    connection.sendall(response.encode())
                else:
                    connection.sendall(result.encode())
            except socket.error as e:
                self.logger.error(f"Failed to send response to client: {e}")
                raise ConnectionError(f"Failed to send response to client {address[0]}:{address[1]}: {e}")
            
            if ssl_enabled:
                try:
                    connection.unwrap()

                except ssl.SSLError as e:
                    self.logger.error(f"SSL error during connection unwrap: {e}")
                    raise ssl.SSLError(f"Failed to properly close SSL connection: {e}")

        except socket.timeout as e:
            self.logger.error(f"Socket timeout error: {e}")
            raise
        except ConnectionError as e:
            self.logger.error(f"Connection error: {e}")
            raise
        except ssl.SSLError as e:
            self.logger.error(f"SSL error: {e}")
            raise
        except ValueError as e:
            self.logger.error(f"Value error: {e}")
            raise
        except OSError as e:
            self.logger.error(f"OS error: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error handling client {address[0]}:{address[1]}: {e}")
            self.logger.debug(f"Error type: {type(e).__name__}, Error details: {str(e)}")
            raise

        finally:
            try:
                connection.close()
                self.logger.debug(f"Closed connection to client {address[0]}:{address[1]}")
            except Exception as e:
                self.logger.error(f"Error closing client connection: {e}")

    def start(
        self,
        test_mode: bool = False,
        workers: Optional[int] = None,
        file_path: Optional[str] = None
    ) -> None:
        """Start the server with multiple worker processes.
        
        Args:
            test_mode (bool, optional): Whether to run in test mode. Defaults to False.
            workers (Optional[int], optional): Number of worker processes. If None, uses CPU count.
            file_path (Optional[str], optional): Direct path to input file. If None, uses config path.
        """
        # Set and load server configurations.
        configurations: Dict[str, Any] = load_server_configurations()

        # Use the provided file path or get from the server configuration file.
        base_dir: str = os.path.dirname(os.path.abspath(__file__))
        config_file_name: str = file_path if file_path is not None else configurations['linuxpath']
        full_path: str = os.path.join(base_dir, config_file_name)

        # File monitor object.
        file_monitor: BackgroundFileMonitor = BackgroundFileMonitor(
            server=self,
            file_path=full_path
        )

        # Create shared memory block.
        shm_name = self.create_shared_memory()
        if not shm_name:
            self.logger.error("Failed to create shared memory")
            return
        self.shared_state.current_shm_name = shm_name

        # Launch file monitor if reread is enabled.
        if configurations['reread_on_query']:
            threading.Thread(
                target=file_monitor.run_monitor,
                daemon=True
            ).start()

        # Get workers - use provided count or default to CPU count.
        worker_count: int = workers if workers is not None else multiprocessing.cpu_count()
        self.logger.debug(f"Launching an army of {worker_count} worker processes.")

        # Create processes.
        processes: List[Process] = []

        try:
            for _ in range(worker_count):
                p: Process = multiprocessing.Process(
                    target=self.worker_process,
                    args=(configurations, test_mode)
                )
                p.start()
                processes.append(p)

            for p in processes:
                p.join()

        except KeyboardInterrupt:
            self.logger.debug("Shutting down workers...")
            # Stop the file monitor.
            if configurations['reread_on_query']:
                file_monitor.stop_monitor()

            for p in processes:
                p.terminate()
                p.join()

    def stop(
        self,
        force: bool = False,
        cleanup_shm: bool = True,
        cleanup_manager: bool = True
    ) -> None:
        """Stop the server gracefully, cleaning up shared memory and resources.
        
        Args:
            force (bool, optional): Whether to force stop without waiting for cleanup. Defaults to False.
            cleanup_shm (bool, optional): Whether to cleanup shared memory. Defaults to True.
            cleanup_manager (bool, optional): Whether to cleanup multiprocessing manager. Defaults to True.
        """
        with self.thread_lock:
            try:
                # Close and unlink shared memory.
                if cleanup_shm and self.current_shm:
                    self.logger.debug(f"Closing shared memory: {self.current_shm.name}")
                    self.current_shm.close()
                    try:
                        self.current_shm.unlink()
                        self.logger.debug(f"Unlinked shared memory: {self.current_shm.name}")
                    except FileNotFoundError:
                        self.logger.warning(f"Shared memory {self.current_shm.name} already unlinked")
                    self.current_shm = None

            except Exception as e:
                self.logger.error(f"Error while stopping server shared memory: {e}")
                if not force:
                    raise

            try:
                # Terminate manager (if its not being used elsewhere).
                if cleanup_manager and self.manager:
                    self.manager.shutdown()
                    self.logger.debug("Multiprocessing manager shut down successfully")
            except Exception as e:
                self.logger.error(f"Error while shutting down manager: {e}")
                if not force:
                    raise

            self.logger.info("Server stopped successfully.")


class BackgroundFileMonitor:
    """Monitor for file changes and trigger shared memory reload.
    
    This class monitors a specified file for changes and triggers a reload
    of the shared memory when changes are detected.
    
    Attributes:
        server (Server): Server instance to reload shared memory.
        logger (Logger): Logger instance for tracking operations.
        file_path (str): Path to the file to monitor.
        stop_flag (bool): Flag to control monitoring loop.
        polling_time (float): Time between checks in seconds.
        bounce_back_time (float): Minimum time between reloads in seconds.
        last_update (Optional[float]): Last modification time of the file.
        last_reload_time (float): Last time a reload was performed.
    """
    
    def __init__(
        self,
        server: Server,
        file_path: str,
        logger: Optional[Logger] = None,
        polling_time: float = 0.05,
        bounce_back_time: float = 0.5
    ) -> None:
        """Initialize the file monitor.
        
        Args:
            server (Server): Server instance to reload shared memory.
            file_path (str): Path to the file to monitor.
            logger (Optional[Logger], optional): Logger instance. Defaults to new Logger instance.
            polling_time (float, optional): Time between checks in seconds. Defaults to 0.05.
            bounce_back_time (float, optional): Minimum time between reloads in seconds. Defaults to 0.5.
        """
        self.server: Server = server
        self.logger: Logger = logger if logger is not None else Logger()
        self.file_path: str = file_path
        self.stop_flag: bool = False
        self.polling_time: float = polling_time
        self.bounce_back_time: float = bounce_back_time
        self.last_update: Optional[float] = None
        self.last_reload_time: float = 0.0

    def run_monitor(
        self,
        test_mode: bool = False,
        max_iterations: Optional[int] = None
    ) -> None:
        """Run the file monitoring loop.
        
        This method continuously monitors the specified file for changes
        and triggers a reload of shared memory when changes are detected.
        
        Args:
            test_mode (bool, optional): Whether to run in test mode. Defaults to False.
            max_iterations (Optional[int], optional): Maximum number of iterations to run. 
                                                    If None, runs indefinitely. Defaults to None.
        """
        try:
            if not os.path.exists(self.file_path):
                raise FileNotFoundError

            self.last_update = os.path.getmtime(self.file_path)
            self.last_reload_time = 0.0
            iteration_count: int = 0

            while not self.stop_flag:
                if max_iterations is not None and iteration_count >= max_iterations:
                    break

                current_update: float = os.path.getmtime(self.file_path)
                current_time = time.time()

                if (current_update != self.last_update and 
                    (current_time - self.last_reload_time) >= self.bounce_back_time):
                    self.logger.debug(
                        f"File has been updated on: {datetime.datetime.fromtimestamp(current_update)}"
                    )
                    self.last_update = current_update
                    self.last_reload_time = current_time
                    self.server.reload_shared_memory()

                time.sleep(self.polling_time)
                iteration_count += 1

                if test_mode:
                    self.logger.debug(f"Monitor iteration {iteration_count}")

        except FileNotFoundError as e:
            self.logger.error(
                f"File path provided to background monitor does not exist: {self.file_path} error: {e}"
            )
            raise

    def stop_monitor(self) -> None:
        """Stop the file monitoring loop."""
        self.stop_flag = True


if __name__ == "__main__":
    server: Server = Server()
    server.start()