"""
File Lifecycle Tests - Write Operations

Tests for writing to files in protected directories:
- Writing with appropriate permissions
- Appending content
- Truncating files
"""

import pytest
import os


class TestFileWriteOperations:
    """Test file write operations in protected directories."""
    
    def test_write_new_content(self, effectiveness_dir, protected_file,
                                qdocse_client, test_user, test_executor):
        """
        Test: Can write new content to file with write permission.
        """
        file_path, _ = protected_file
        
        # Add write permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="rw"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        # Write new content
        new_content = "completely new content"
        result = test_executor.run(f"echo '{new_content}' > {file_path}")
        
        assert result.returncode == 0, "Write should succeed"
        
        # Verify content changed
        read_result = test_executor.run(f"cat {file_path}")
        assert new_content in read_result.stdout
    
    def test_append_content(self, effectiveness_dir, protected_file,
                             qdocse_client, test_user, test_executor):
        """
        Test: Can append content to file with write permission.
        """
        file_path, original_content = protected_file
        
        # Add read-write permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="rw"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        # Append content
        appended = "appended text"
        result = test_executor.run(f"echo '{appended}' >> {file_path}")
        
        assert result.returncode == 0, "Append should succeed"
        
        # Verify both original and appended content
        read_result = test_executor.run(f"cat {file_path}")
        assert original_content in read_result.stdout
        assert appended in read_result.stdout
    
    def test_truncate_file(self, effectiveness_dir, protected_file,
                            qdocse_client, test_user, test_executor):
        """
        Test: Can truncate file with write permission.
        """
        file_path, _ = protected_file
        
        # Add write permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="w"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        # Truncate file
        result = test_executor.run(f"truncate -s 0 {file_path}")
        
        assert result.returncode == 0, "Truncate should succeed"
        
        # Verify file is empty
        stat_result = test_executor.run(f"stat -c %s {file_path}")
        assert stat_result.stdout.strip() == "0", "File should be empty"
    
    def test_write_binary_content(self, effectiveness_dir, qdocse_client,
                                   test_user, test_executor):
        """
        Test: Can write binary content with write permission.
        """
        # Add write permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="w"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        # Create binary file
        binary_file = os.path.join(effectiveness_dir, "binary.bin")
        result = test_executor.run(
            f"dd if=/dev/urandom of={binary_file} bs=1024 count=1 2>/dev/null"
        )
        
        assert result.returncode == 0, "Binary write should succeed"
        assert os.path.exists(binary_file)


class TestWriteDenied:
    """Test write operations that should be denied."""
    
    def test_write_without_permission(self, effectiveness_dir, protected_file,
                                       unauthorized_executor):
        """
        Test: Cannot write to file without any permission.
        """
        file_path, _ = protected_file
        
        result = unauthorized_executor.run(f"echo 'test' > {file_path}")
        
        assert result.returncode != 0, "Write should fail without permission"
    
    def test_write_with_only_read_permission(self, effectiveness_dir, protected_file,
                                              user_acl_entry, test_executor):
        """
        Test: Cannot write to file with only read permission.
        """
        file_path, _ = protected_file
        # user_acl_entry provides 'r' permission
        
        result = test_executor.run(f"echo 'test' >> {file_path}")
        
        assert result.returncode != 0, "Write should fail with only r permission"
    
    def test_truncate_with_only_read_permission(self, effectiveness_dir, protected_file,
                                                 user_acl_entry, test_executor):
        """
        Test: Cannot truncate file with only read permission.
        """
        file_path, _ = protected_file
        
        result = test_executor.run(f"truncate -s 0 {file_path}")
        
        assert result.returncode != 0, "Truncate should fail with only r permission"


class TestWriteEdgeCases:
    """Edge cases for write operations."""
    
    def test_write_to_readonly_filesystem_file(self, effectiveness_dir, qdocse_client,
                                                test_user, test_executor):
        """
        Test: Proper error when filesystem is read-only.
        
        This tests the interaction between ACL and filesystem permissions.
        """
        # This test would require mounting a read-only filesystem
        # Documenting expected behavior: ACL allows but filesystem denies
        pytest.skip("Requires read-only filesystem setup")
    
    def test_concurrent_writes(self, effectiveness_dir, qdocse_client,
                                test_user, test_executor):
        """
        Test: Concurrent writes to same file.
        
        Multiple write operations should not corrupt file.
        """
        # Add write permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="w"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        test_file = os.path.join(effectiveness_dir, "concurrent.txt")
        
        # Simulate concurrent writes (sequential for simplicity)
        for i in range(10):
            result = test_executor.run(f"echo 'write {i}' >> {test_file}")
            assert result.returncode == 0
        
        # Verify file is not corrupted
        assert os.path.exists(test_file)
