"""
Access Mode Tests - Read Mode

Tests for read permission effectiveness:
- Files with read permission can be read
- Files without read permission cannot be read
- Read permission boundary conditions
"""

import pytest
import os


class TestReadModeAllow:
    """Test cases where read access should be allowed."""
    
    def test_read_with_r_permission(self, effectiveness_dir, protected_file, 
                                     user_acl_entry, access_helper, test_executor):
        """
        Test: User with 'r' permission can read files.
        
        Setup:
        - Protected directory with test file
        - User ACL entry with read permission
        
        Expected: Read operation succeeds
        """
        file_path, original_content = protected_file
        
        success, content = access_helper.test_read_access(
            file_path, test_executor, expected_success=True
        )
        
        assert success, "Read should succeed with r permission"
        assert original_content in content, "Content should match original"
    
    def test_read_with_rw_permission(self, effectiveness_dir, protected_file,
                                      qdocse_client, test_user, access_helper, test_executor):
        """
        Test: User with 'rw' permission can read files.
        
        Having write permission should not prevent reading.
        """
        file_path, original_content = protected_file
        
        # Add rw permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="rw"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        success, content = access_helper.test_read_access(
            file_path, test_executor, expected_success=True
        )
        
        assert success, "Read should succeed with rw permission"
    
    def test_read_with_rwx_permission(self, effectiveness_dir, protected_file,
                                       qdocse_client, test_user, access_helper, test_executor):
        """
        Test: User with 'rwx' (full) permission can read files.
        """
        file_path, _ = protected_file
        
        # Add full permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="rwx"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        success, _ = access_helper.test_read_access(
            file_path, test_executor, expected_success=True
        )
        
        assert success, "Read should succeed with rwx permission"


class TestReadModeDeny:
    """Test cases where read access should be denied."""
    
    def test_read_without_permission(self, effectiveness_dir, protected_file,
                                      access_helper, unauthorized_executor):
        """
        Test: User without any ACL entry cannot read files.
        
        No ACL entry means access is denied by default.
        """
        file_path, _ = protected_file
        
        success, error = access_helper.test_read_access(
            file_path, unauthorized_executor, expected_success=False
        )
        
        assert not success, "Read should fail without permission"
    
    def test_read_with_only_w_permission(self, effectiveness_dir, protected_file,
                                          qdocse_client, test_user, access_helper, test_executor):
        """
        Test: User with only 'w' permission cannot read files.
        
        Write-only permission should not allow reading.
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
        
        success, _ = access_helper.test_read_access(
            file_path, test_executor, expected_success=False
        )
        
        assert not success, "Read should fail with only w permission"
    
    def test_read_with_only_x_permission(self, effectiveness_dir, protected_file,
                                          qdocse_client, test_user, access_helper, test_executor):
        """
        Test: User with only 'x' permission cannot read files.
        
        Execute-only permission should not allow reading.
        """
        file_path, _ = protected_file
        
        # Add execute-only permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="x"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        success, _ = access_helper.test_read_access(
            file_path, test_executor, expected_success=False
        )
        
        assert not success, "Read should fail with only x permission"
    
    def test_read_with_explicit_deny(self, effectiveness_dir, protected_file,
                                      deny_entry, access_helper, test_executor):
        """
        Test: User with explicit deny entry cannot read files.
        
        Explicit deny should override any implicit allow.
        """
        file_path, _ = protected_file
        
        success, _ = access_helper.test_read_access(
            file_path, test_executor, expected_success=False
        )
        
        assert not success, "Read should fail with explicit deny"


class TestReadModeEdgeCases:
    """Edge cases for read permission testing."""
    
    def test_read_empty_file(self, effectiveness_dir, user_acl_entry,
                              access_helper, test_executor):
        """
        Test: Can read empty files with read permission.
        """
        # Create empty file
        empty_file = os.path.join(effectiveness_dir, "empty.txt")
        open(empty_file, 'w').close()
        
        success, content = access_helper.test_read_access(
            empty_file, test_executor, expected_success=True
        )
        
        assert success, "Should be able to read empty file"
        assert content.strip() == "", "Empty file should return empty content"
    
    def test_read_large_file(self, effectiveness_dir, user_acl_entry,
                              access_helper, test_executor):
        """
        Test: Can read large files with read permission.
        """
        # Create large file (1MB)
        large_file = os.path.join(effectiveness_dir, "large.txt")
        with open(large_file, 'w') as f:
            f.write("x" * (1024 * 1024))
        
        success, _ = access_helper.test_read_access(
            large_file, test_executor, expected_success=True
        )
        
        assert success, "Should be able to read large file"
    
    def test_read_binary_file(self, effectiveness_dir, user_acl_entry,
                               access_helper, test_executor):
        """
        Test: Can read binary files with read permission.
        """
        # Create binary file
        binary_file = os.path.join(effectiveness_dir, "binary.bin")
        with open(binary_file, 'wb') as f:
            f.write(bytes(range(256)))
        
        # Use cat to read - will return binary content
        result = test_executor.run(f"cat {binary_file}")
        assert result.returncode == 0, "Should be able to read binary file"
