"""
File Lifecycle Tests - Read Operations

Tests for reading files in protected directories:
- Reading with appropriate permissions
- Reading file metadata
- Reading partial content
"""

import pytest
import os


class TestFileReadOperations:
    """Test file read operations in protected directories."""
    
    def test_read_entire_file(self, effectiveness_dir, protected_file,
                               user_acl_entry, test_executor):
        """
        Test: Can read entire file with read permission.
        """
        file_path, original_content = protected_file
        # user_acl_entry provides 'r' permission
        
        result = test_executor.run(f"cat {file_path}")
        
        assert result.returncode == 0, "Read should succeed"
        assert original_content in result.stdout, "Content should match"
    
    def test_read_partial_file_head(self, effectiveness_dir, user_acl_entry, test_executor):
        """
        Test: Can read first N lines of file with head command.
        """
        # Create file with multiple lines
        test_file = os.path.join(effectiveness_dir, "multiline.txt")
        lines = [f"Line {i}" for i in range(10)]
        with open(test_file, 'w') as f:
            f.write('\n'.join(lines))
        
        # Read first 3 lines
        result = test_executor.run(f"head -3 {test_file}")
        
        assert result.returncode == 0, "Head should succeed"
        assert "Line 0" in result.stdout
        assert "Line 2" in result.stdout
        assert "Line 5" not in result.stdout
    
    def test_read_partial_file_tail(self, effectiveness_dir, user_acl_entry, test_executor):
        """
        Test: Can read last N lines of file with tail command.
        """
        # Create file with multiple lines
        test_file = os.path.join(effectiveness_dir, "multiline.txt")
        lines = [f"Line {i}" for i in range(10)]
        with open(test_file, 'w') as f:
            f.write('\n'.join(lines))
        
        # Read last 3 lines
        result = test_executor.run(f"tail -3 {test_file}")
        
        assert result.returncode == 0, "Tail should succeed"
        assert "Line 9" in result.stdout
        assert "Line 0" not in result.stdout
    
    def test_read_with_grep(self, effectiveness_dir, user_acl_entry, test_executor):
        """
        Test: Can search file content with grep.
        """
        # Create file with searchable content
        test_file = os.path.join(effectiveness_dir, "searchable.txt")
        content = "apple\nbanana\ncherry\napricot\n"
        with open(test_file, 'w') as f:
            f.write(content)
        
        # Search for pattern
        result = test_executor.run(f"grep 'ap' {test_file}")
        
        assert result.returncode == 0, "Grep should succeed"
        assert "apple" in result.stdout
        assert "apricot" in result.stdout
        assert "banana" not in result.stdout


class TestFileMetadataRead:
    """Test reading file metadata in protected directories."""
    
    def test_stat_file(self, effectiveness_dir, protected_file,
                        user_acl_entry, test_executor):
        """
        Test: Can stat file to get metadata with read permission.
        """
        file_path, _ = protected_file
        
        result = test_executor.run(f"stat {file_path}")
        
        assert result.returncode == 0, "Stat should succeed"
        assert "File:" in result.stdout or "file:" in result.stdout.lower()
    
    def test_list_directory(self, effectiveness_dir, protected_file,
                             user_acl_entry, test_executor):
        """
        Test: Can list directory contents with read permission.
        """
        result = test_executor.run(f"ls -la {effectiveness_dir}")
        
        assert result.returncode == 0, "Directory listing should succeed"
        assert "test_file.txt" in result.stdout
    
    def test_get_file_size(self, effectiveness_dir, protected_file,
                            user_acl_entry, test_executor):
        """
        Test: Can get file size with read permission.
        """
        file_path, original_content = protected_file
        
        result = test_executor.run(f"wc -c < {file_path}")
        
        assert result.returncode == 0, "wc should succeed"
        # File size should be at least the content length
        size = int(result.stdout.strip())
        assert size >= len(original_content)


class TestReadDenied:
    """Test read operations that should be denied."""
    
    def test_read_without_permission(self, effectiveness_dir, protected_file,
                                      unauthorized_executor):
        """
        Test: Cannot read file without any permission.
        """
        file_path, _ = protected_file
        
        result = unauthorized_executor.run(f"cat {file_path}")
        
        assert result.returncode != 0, "Read should fail without permission"
    
    def test_read_with_only_write_permission(self, effectiveness_dir, protected_file,
                                              qdocse_client, test_user, test_executor):
        """
        Test: Cannot read file with only write permission.
        """
        file_path, _ = protected_file
        
        # Add write-only permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="w"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        result = test_executor.run(f"cat {file_path}")
        
        assert result.returncode != 0, "Read should fail with only w permission"
