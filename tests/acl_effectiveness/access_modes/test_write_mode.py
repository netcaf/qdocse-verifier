"""
Access Mode Tests - Write Mode

Tests for write permission effectiveness:
- Files with write permission can be modified
- Files without write permission cannot be modified
- Write permission boundary conditions
"""

import pytest
import os


class TestWriteModeAllow:
    """Test cases where write access should be allowed."""
    
    def test_write_with_w_permission(self, effectiveness_dir, protected_file,
                                      qdocse_client, test_user, access_helper, test_executor):
        """
        Test: User with 'w' permission can write to files.
        
        Setup:
        - Protected directory with test file
        - User ACL entry with write permission
        
        Expected: Write operation succeeds
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
        
        success, _ = access_helper.test_write_access(
            file_path, test_executor, content="new content", expected_success=True
        )
        
        assert success, "Write should succeed with w permission"
    
    def test_write_with_rw_permission(self, effectiveness_dir, protected_file,
                                       qdocse_client, test_user, access_helper, test_executor):
        """
        Test: User with 'rw' permission can write to files.
        """
        file_path, _ = protected_file
        
        # Add read-write permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="rw"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        success, _ = access_helper.test_write_access(
            file_path, test_executor, expected_success=True
        )
        
        assert success, "Write should succeed with rw permission"
    
    def test_append_with_w_permission(self, effectiveness_dir, protected_file,
                                       qdocse_client, test_user, test_executor):
        """
        Test: User with 'w' permission can append to files.
        """
        file_path, original_content = protected_file
        
        # Add write permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="w"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        # Append content
        append_content = "appended text"
        result = test_executor.run(f"echo '{append_content}' >> {file_path}")
        
        assert result.returncode == 0, "Append should succeed"
    
    def test_truncate_with_w_permission(self, effectiveness_dir, protected_file,
                                         qdocse_client, test_user, test_executor):
        """
        Test: User with 'w' permission can truncate files.
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


class TestWriteModeDeny:
    """Test cases where write access should be denied."""
    
    def test_write_without_permission(self, effectiveness_dir, protected_file,
                                       access_helper, unauthorized_executor):
        """
        Test: User without any ACL entry cannot write to files.
        """
        file_path, _ = protected_file
        
        success, _ = access_helper.test_write_access(
            file_path, unauthorized_executor, expected_success=False
        )
        
        assert not success, "Write should fail without permission"
    
    def test_write_with_only_r_permission(self, effectiveness_dir, protected_file,
                                           user_acl_entry, access_helper, test_executor):
        """
        Test: User with only 'r' permission cannot write to files.
        
        Read-only permission should not allow writing.
        """
        file_path, _ = protected_file
        # user_acl_entry fixture adds 'r' permission
        
        success, _ = access_helper.test_write_access(
            file_path, test_executor, expected_success=False
        )
        
        assert not success, "Write should fail with only r permission"
    
    def test_write_with_only_x_permission(self, effectiveness_dir, protected_file,
                                           qdocse_client, test_user, access_helper, test_executor):
        """
        Test: User with only 'x' permission cannot write to files.
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
        
        success, _ = access_helper.test_write_access(
            file_path, test_executor, expected_success=False
        )
        
        assert not success, "Write should fail with only x permission"
    
    def test_write_with_explicit_deny(self, effectiveness_dir, protected_file,
                                       deny_entry, access_helper, test_executor):
        """
        Test: User with explicit deny entry cannot write to files.
        """
        file_path, _ = protected_file
        
        success, _ = access_helper.test_write_access(
            file_path, test_executor, expected_success=False
        )
        
        assert not success, "Write should fail with explicit deny"


class TestWriteModeEdgeCases:
    """Edge cases for write permission testing."""
    
    def test_create_new_file_with_w_permission(self, effectiveness_dir,
                                                qdocse_client, test_user, test_executor):
        """
        Test: User with 'w' permission can create new files.
        """
        # Add write permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="w"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        # Create new file
        new_file = os.path.join(effectiveness_dir, "new_file.txt")
        result = test_executor.run(f"echo 'content' > {new_file}")
        
        assert result.returncode == 0, "Should be able to create new file"
        assert os.path.exists(new_file), "New file should exist"
    
    def test_overwrite_file_with_w_permission(self, effectiveness_dir, protected_file,
                                               qdocse_client, test_user, test_executor):
        """
        Test: User with 'w' permission can overwrite existing files.
        """
        file_path, original_content = protected_file
        
        # Add write permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="rw"  # Need read to verify overwrite
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        # Overwrite file
        new_content = "completely new content"
        result = test_executor.run(f"echo '{new_content}' > {file_path}")
        assert result.returncode == 0, "Overwrite should succeed"
        
        # Verify content changed
        read_result = test_executor.run(f"cat {file_path}")
        assert new_content in read_result.stdout, "Content should be overwritten"
        assert original_content not in read_result.stdout, "Original content should be gone"
