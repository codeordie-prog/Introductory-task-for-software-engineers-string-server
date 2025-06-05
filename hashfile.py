import mmh3
import os
from typing import Set, Dict, List, Optional, Any
from logger_setup import Logger

# Remove duplicate lines from a given file.
def remove_duplicates(file: str) -> Set[str]:
    """Remove duplicate lines from a file and return a set of unique lines.
    
    This function reads a file line by line, strips whitespaces, and stores
    unique non-empty lines in a set. It handles file not found and other
    potential errors gracefully.
    
    Args:
        file (str): Path to the input file.
        
    Returns:
        Set[str]: Set containing unique non-empty lines from the file.
        
    Raises:
        FileNotFoundError: If the specified file does not exist.
        PermissionError: If there are insufficient permissions to read the file.
        OSError: For general file system related errors.
        UnicodeDecodeError: If the file contains invalid UTF-8 characters.
        
    Example:
        >>> unique_lines = remove_duplicates("path/to/file.txt")
        >>> print(len(unique_lines))  # Number of unique lines
    """
    # Initialize a set to store the unique lines.
    unique_lines: Set[str] = set()

    # Initialize the logger object.
    logger: Logger = Logger()
    
    try:
        # Check if the file exists.
        if not os.path.exists(file):
            raise FileNotFoundError(f"File '{file}' not found in the path provided")
            
        # Check if we have read permissions.
        if not os.access(file, os.R_OK):
            raise PermissionError(f"Insufficient permissions to read file '{file}'")
            
        # Open the file and read the lines.
        try:
            with open(file, "r", encoding='utf-8') as f:
                lines: List[str] = f.readlines()
                for line in lines:
                    stripped_line: str = line.strip()
                    if stripped_line:
                        # Add the line to the set.
                        unique_lines.add(stripped_line)
        except UnicodeDecodeError as e:
            logger.error(f"Failed to decode file '{file}' as UTF-8: {e}")
            raise UnicodeDecodeError(
                'utf-8',
                b'',  # We don't have the actual bytes that failed
                0,    # We don't have the position
                len(file),
                f"File '{file}' contains invalid UTF-8 characters"
            ) from e
            
    except FileNotFoundError as e:
        logger.error(f"File not found error: {e}")
        logger.debug(f"Troubleshooting steps:\n"
                    f"1. Verify the file path is correct\n"
                    f"2. Check if the file exists\n"
                    f"3. Ensure the file path is absolute or relative to the current directory")
        raise
    except PermissionError as e:
        logger.error(f"Permission error: {e}")
        logger.debug(f"Troubleshooting steps:\n"
                    f"1. Check file permissions\n"
                    f"2. Ensure the process has read access\n"
                    f"3. Try running with elevated privileges if necessary")
        raise
    except OSError as e:
        logger.error(f"OS error while reading file '{file}': {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error while removing duplicates from file '{file}': {e}")
        logger.debug(f"Error type: {type(e).__name__}, Error details: {str(e)}")
        raise RuntimeError(f"Failed to process file '{file}': {e}") from e

    # Return the set of unique lines.
    return unique_lines

def hash_file(set_: Set[str]) -> Dict[str, Any]:
    """Hash the contents of the set using MurmurHash3 library.
    
    This function creates a hash table from the input set using MurmurHash3
    for hashing and linear probing for collision resolution. The table size
    is increased by 30% to reduce collisions.
    
    Args:
        set_ (Set[str]): Set of strings to be hashed.
        
    Returns:
        Dict[str, Any]: Dictionary containing:
            - total_size (int): Size of the hash table.
            - values (List[Optional[str]]): Array containing the hashed values.
            
    Raises:
        ValueError: If the input set is empty or contains invalid data.
        TypeError: If the input set contains non-string elements.
        MemoryError: If there is insufficient memory to create the hash table.
        
    Example:
        >>> unique_strings = {"hello", "world"}
        >>> hashed_data = hash_file(unique_strings)
        >>> print(hashed_data["total_size"])  # Size of hash table
    """
    # Initialize the logger object.
    logger: Logger = Logger()
    
    try:
        # Validate input set.
        if not set_:
            raise ValueError("Input set cannot be empty")
            
        # Check if all elements are strings.
        if not all(isinstance(x, str) for x in set_):
            raise TypeError("All elements in the input set must be strings")
            
        # Get length of the set.
        length_of_set: int = len(set_) 

        # Increment size by 30% to prevent collisions.
        total_size: int = int(length_of_set * 1.3) or 1
        
        try:
            # Create array.
            values: List[Optional[str]] = [None] * total_size
        except MemoryError as e:
            logger.error(f"Failed to allocate memory for hash table of size {total_size}")
            raise MemoryError(f"Insufficient memory to create hash table of size {total_size}") from e
   
        # Iterate the set.
        for string in set_:
            try:
                # Hash the string.
                index: int = mmh3.hash(string, signed=False) % total_size

                # Linear probing to handle collisions.
                while values[index] is not None and values[index] != string:
                    # Increment index until you find an empty slot.
                    index = (index + 1) % total_size

                # Add string to index.
                values[index] = string
            except Exception as e:
                logger.error(f"Error hashing string '{string}': {e}")
                raise ValueError(f"Failed to hash string '{string}': {e}") from e
        
        # Create dictionary.
        hashed_values: Dict[str, Any] = {
            "total_size": total_size,
            "values": values,
        }

        return hashed_values
        
    except ValueError as e:
        logger.error(f"Value error during hashing: {e}")
        raise
    except TypeError as e:
        logger.error(f"Type error during hashing: {e}")
        raise
    except MemoryError as e:
        logger.error(f"Memory error during hashing: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during hashing: {e}")
        logger.debug(f"Error type: {type(e).__name__}, Error details: {str(e)}")
        raise RuntimeError(f"Failed to hash input set: {e}") from e



    