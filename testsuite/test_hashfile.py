"""Test suite for hashfile module.

This module contains tests for the hashfile module's functionality, including:
- remove_duplicates: Tests for removing duplicate lines from files.
- hash_file: Tests for hashing sets of strings using MurmurHash3.

The tests cover various edge cases including:
- Empty files.
- Files with only whitespace.
- Files with special characters.
- Large sets of strings.
- Collision handling in hash table.
- File not found scenarios.
"""

import tempfile
import pytest
import os
from typing import Set, Dict, Any, List
from hashfile import remove_duplicates, hash_file


def test_remove_duplicates() -> None:
    """Test remove_duplicates function with various scenarios."""
    # Test with duplicate lines
    temp_dir: str = tempfile.mkdtemp()
    temp_file: str = "temp_data.txt"
    temp_path: str = os.path.join(temp_dir, temp_file)
    
    with open(temp_path, 'w') as f:
        for _ in range(10):
            f.write('I love Algorithmic Sciences\n')
    
    result: Set[str] = remove_duplicates(file=temp_path)
    assert result == {'I love Algorithmic Sciences'}
    
    # Test with empty file
    with pytest.raises(FileNotFoundError):
        remove_duplicates(file="")
    
    # Test with file containing only whitespace
    with open(temp_path, 'w') as f:
        f.write('\n\n  \t\n')
    result3: Set[str] = remove_duplicates(file=temp_path)
    assert result3 == set()
    
    # Test with special characters
    with open(temp_path, 'w') as f:
        f.write('Line 1\n')
        f.write('Line 1\n')
        f.write('Line 2\n')
        f.write('Line 2\n')
        f.write('!@#$%^&*()\n')
        f.write('!@#$%^&*()\n')
    result4: Set[str] = remove_duplicates(file=temp_path)
    assert result4 == {'Line 1', 'Line 2', '!@#$%^&*()'}
    
    # Test with non-existent file
    with pytest.raises(FileNotFoundError):
        remove_duplicates(file="thisfiledoesnotexist.txt")
    
    # Test with very long lines
    with open(temp_path, 'w') as f:
        long_line = 'x' * 10000  # 10KB line
        f.write(f'{long_line}\n')
        f.write(f'{long_line}\n')
    result5: Set[str] = remove_duplicates(file=temp_path)
    assert result5 == {long_line}
    
    # Test with mixed line endings
    with open(temp_path, 'w', newline='') as f:
        f.write('Line 1\r\n')  # CRLF
        f.write('Line 1\n')    # LF
        f.write('Line 2\r')    # CR
        f.write('Line 2\r\n')  # CRLF
    result6: Set[str] = remove_duplicates(file=temp_path)
    assert result6 == {'Line 1', 'Line 2'}
    
    # Test with Unicode characters
    with open(temp_path, 'w', encoding='utf-8') as f:
        f.write('Hello 世界\n')
        f.write('Hello 世界\n')
        f.write('你好\n')
        f.write('你好\n')
    result7: Set[str] = remove_duplicates(file=temp_path)
    assert result7 == {'Hello 世界', '你好'}
    
    # Test with extremely large number of duplicates
    with open(temp_path, 'w') as f:
        for _ in range(10000):  # 10,000 duplicates
            f.write('Duplicate line\n')
    result8: Set[str] = remove_duplicates(file=temp_path)
    assert result8 == {'Duplicate line'}
    
   


def test_hash_file() -> None:
    """Test hash_file function with various scenarios."""
    # Test with normal set of strings
    test_data: Set[str] = set()
    names: List[str] = ['Phillip', 'Eunice', 'Lilian', 'Kennedy', 'Johnson', 'Grace', 'Paul']
    for name in names:
        test_data.add(name)
    
    result: Dict[str, Any] = hash_file(set_=test_data)
    assert isinstance(result, dict)
    assert 'total_size' in result and 'values' in result
    assert isinstance(result['values'], list)
    assert len(result['values']) == int(len(test_data) * 1.3)
    
    # Test with empty set
    test_data2: Set[str] = set()
    with pytest.raises(ValueError,):
        hash_file(set_=test_data2)
    
    # Test with mixed types (should raise TypeError)
    mixed_set: Set[Any] = {'string1', 42, 'string2', 100}
    with pytest.raises(TypeError, match="All elements in the input set must be strings"):
        hash_file(set_=mixed_set)
    
    # Test with large set to check collision handling
    large_set: Set[str] = {str(i) for i in range(1000)}
    result3: Dict[str, Any] = hash_file(set_=large_set)
    assert isinstance(result3, dict)
    assert len(result3['values']) == int(len(large_set) * 1.3)
    # Verify all values from original set are in hash table
    values_set: Set[str] = {v for v in result3['values'] if v is not None}
    assert values_set == large_set
    
    # Test with strings containing special characters
    special_chars: Set[str] = {'!@#$%^&*()', 'Hello\nWorld', 'Tab\tHere', 'Space Here'}
    result4: Dict[str, Any] = hash_file(set_=special_chars)
    assert isinstance(result4, dict)
    values_set2: Set[str] = {v for v in result4['values'] if v is not None}
    assert values_set2 == special_chars



    