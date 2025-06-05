"""Test suite for string search functionality in shared memory.

This module contains tests for searching strings in the shared memory system,
including:
- Successful string matches
- Failed string searches
- Edge cases (empty strings)
"""

from typing import Dict, Any, Set
import pytest
from server import Server

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning:multiprocessing.*:")


@pytest.fixture
def get_server_instance() -> Server:
    """Create and return a Server instance for testing.
    
    Returns:
        Server: A fresh Server instance for each test.
    """
    return Server()


@pytest.fixture
def hashed_test_set(get_server_instance: Server) -> Dict[str, Any]:
    """Create a test dataset with hashed values.
    
    Args:
        get_server_instance: Server instance fixture
    
    Returns:
        Dict[str, Any]: Dictionary containing hashed values of test strings
    """
    dataset: Set[str] = {
        "Whbet", "Mckenna", "Paulos",
        "Hello, World!", "Test@123",
        "   Spaces   ", "Line\nBreak",
        "Unicode: 你好", "Very" + "Long" * 100,
        "Special!@#$%^&*()", "MixedCase"
    }
    return get_server_instance.get_hashed_values(dataset=dataset)


def test_search_string_exists(
    get_server_instance: Server,
    hashed_test_set: Dict[str, Any]
) -> None:
    """Test searching for a string that exists in the dataset.
    
    Args:
        get_server_instance: Server instance fixture
        hashed_test_set: Dictionary of hashed test strings
    """
    result: str = get_server_instance.search_in_shared_memory(
        "Whbet",
        hashed_test_set
    )
    assert result == "STRING EXISTS\n"


def test_search_string_not_found(
    get_server_instance: Server,
    hashed_test_set: Dict[str, Any]
) -> None:
    """Test searching for a string that doesn't exist in the dataset.
    
    Args:
        get_server_instance: Server instance fixture
        hashed_test_set: Dictionary of hashed test strings
    """
    result: str = get_server_instance.search_in_shared_memory(
        "Alvin",
        hashed_test_set
    )
    assert result == "STRING NOT FOUND\n"


def test_search_empty_string(
    get_server_instance: Server,
    hashed_test_set: Dict[str, Any]
) -> None:
    """Test searching for an empty string.
    
    Args:
        get_server_instance: Server instance fixture
        hashed_test_set: Dictionary of hashed test strings
    """
    result: str = get_server_instance.search_in_shared_memory(
        " ",
        hashed_test_set
    )
    assert result == "STRING NOT FOUND\n"


def test_search_special_characters(
    get_server_instance: Server,
    hashed_test_set: Dict[str, Any]
) -> None:
    """Test searching for strings with special characters.
    
    Args:
        get_server_instance: Server instance fixture
        hashed_test_set: Dictionary of hashed test strings
    """
    result: str = get_server_instance.search_in_shared_memory(
        "Special!@#$%^&*()",
        hashed_test_set
    )
    assert result == "STRING EXISTS\n"


def test_search_case_sensitivity(
    get_server_instance: Server,
    hashed_test_set: Dict[str, Any]
) -> None:
    """Test case sensitivity in string search.
    
    Args:
        get_server_instance: Server instance fixture
        hashed_test_set: Dictionary of hashed test strings
    """
    result: str = get_server_instance.search_in_shared_memory(
        "mixedcase",
        hashed_test_set
    )
    assert result == "STRING NOT FOUND\n"  # Should be case sensitive


def test_search_unicode_characters(
    get_server_instance: Server,
    hashed_test_set: Dict[str, Any]
) -> None:
    """Test searching for strings with Unicode characters.
    
    Args:
        get_server_instance: Server instance fixture
        hashed_test_set: Dictionary of hashed test strings
    """
    result: str = get_server_instance.search_in_shared_memory(
        "Unicode: 你好",
        hashed_test_set
    )
    assert result == "STRING EXISTS\n"


def test_search_very_long_string(
    get_server_instance: Server,
    hashed_test_set: Dict[str, Any]
) -> None:
    """Test searching for a very long string.
    
    Args:
        get_server_instance: Server instance fixture
        hashed_test_set: Dictionary of hashed test strings
    """
    result: str = get_server_instance.search_in_shared_memory(
        "Very" + "Long" * 100,
        hashed_test_set
    )
    assert result == "STRING EXISTS\n"


def test_search_string_with_spaces(
    get_server_instance: Server,
    hashed_test_set: Dict[str, Any]
) -> None:
    """Test searching for strings with leading/trailing spaces.
    
    Args:
        get_server_instance: Server instance fixture
        hashed_test_set: Dictionary of hashed test strings
    """
    result: str = get_server_instance.search_in_shared_memory(
        "   Spaces   ",
        hashed_test_set
    )
    assert result == "STRING EXISTS\n"


def test_search_string_with_newlines(
    get_server_instance: Server,
    hashed_test_set: Dict[str, Any]
) -> None:
    """Test searching for strings containing newlines.
    
    Args:
        get_server_instance: Server instance fixture
        hashed_test_set: Dictionary of hashed test strings
    """
    result: str = get_server_instance.search_in_shared_memory(
        "Line\nBreak",
        hashed_test_set
    )
    assert result == "STRING EXISTS\n"


def test_search_string_with_commas(
    get_server_instance: Server,
    hashed_test_set: Dict[str, Any]
) -> None:
    """Test searching for strings containing commas.
    
    Args:
        get_server_instance: Server instance fixture
        hashed_test_set: Dictionary of hashed test strings
    """
    result: str = get_server_instance.search_in_shared_memory(
        "Hello, World!",
        hashed_test_set
    )
    assert result == "STRING EXISTS\n"


def test_search_string_with_at_symbol(
    get_server_instance: Server,
    hashed_test_set: Dict[str, Any]
) -> None:
    """Test searching for strings containing @ symbol.
    
    Args:
        get_server_instance: Server instance fixture
        hashed_test_set: Dictionary of hashed test strings
    """
    result: str = get_server_instance.search_in_shared_memory(
        "Test@123",
        hashed_test_set
    )
    assert result == "STRING EXISTS\n"


def test_search_none_hashed_values(
    get_server_instance: Server
) -> None:
    """Test searching with None hashed values.
    
    Args:
        get_server_instance: Server instance fixture
    """
    result: str = get_server_instance.search_in_shared_memory(
        "test",
        None
    )
    assert result is None
