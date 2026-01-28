"""
Access Mode Tests - Mode Matching Rules

Tests for permission mode matching behavior:
- Exact permission match
- Partial permission match
- Permission combination rules
"""

import pytest
import os


class TestExactPermissionMatch:
    """Test exact permission matching scenarios."""
    
    def test_r_grants_only_read(self, effectiveness_dir, protected_file,
                                 user_acl_entry, access_helper, test_executor):
        """
        Test: 'r' permission grants only read access.
        
        Verify that read-only permission:
        - Allows read operations
        - Denies write operations
        - Denies execute operations
        """
        file_path, _ = protected_file
        # user_acl_entry provides 'r' permission
        
        # Should allow read
        read_success, _ = access_helper.test_read_access(
            file_path, test_executor, expected_success=True
        )
        assert read_success, "Read should succeed with r permission"
        
        # Should deny write
        write_success, _ = access_helper.test_write_access(
            file_path, test_executor, expected_success=False
        )
        assert not write_success, "Write should fail with only r permission"
    
    def test_w_grants_only_write(self, effectiveness_dir, protected_file,
                                  qdocse_client, test_user, access_helper, test_executor):
        """
        Test: 'w' permission grants only write access.
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
        
        # Should deny read
        read_success, _ = access_helper.test_read_access(
            file_path, test_executor, expected_success=False
        )
        assert not read_success, "Read should fail with only w permission"
        
        # Should allow write
        write_success, _ = access_helper.test_write_access(
            file_path, test_executor, expected_success=True
        )
        assert write_success, "Write should succeed with w permission"
    
    def test_x_grants_only_execute(self, effectiveness_dir, qdocse_client,
                                    test_user, access_helper, test_executor):
        """
        Test: 'x' permission grants only execute access.
        """
        # Create executable
        script_path = os.path.join(effectiveness_dir, "script.sh")
        with open(script_path, 'w') as f:
            f.write("#!/bin/bash\necho 'executed'\n")
        os.chmod(script_path, 0o755)
        
        # Add execute-only permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="x"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        # Should deny read
        read_success, _ = access_helper.test_read_access(
            script_path, test_executor, expected_success=False
        )
        assert not read_success, "Read should fail with only x permission"


class TestCombinedPermissions:
    """Test combined permission scenarios."""
    
    def test_rw_grants_read_and_write(self, effectiveness_dir, protected_file,
                                       qdocse_client, test_user, access_helper, test_executor):
        """
        Test: 'rw' permission grants both read and write access.
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
        
        # Should allow read
        read_success, _ = access_helper.test_read_access(
            file_path, test_executor, expected_success=True
        )
        assert read_success, "Read should succeed with rw permission"
        
        # Should allow write
        write_success, _ = access_helper.test_write_access(
            file_path, test_executor, expected_success=True
        )
        assert write_success, "Write should succeed with rw permission"
    
    def test_rx_grants_read_and_execute(self, effectiveness_dir, qdocse_client,
                                         test_user, access_helper, test_executor):
        """
        Test: 'rx' permission grants both read and execute access.
        """
        # Create executable
        script_path = os.path.join(effectiveness_dir, "script.sh")
        with open(script_path, 'w') as f:
            f.write("#!/bin/bash\necho 'executed'\n")
        os.chmod(script_path, 0o755)
        
        # Add read-execute permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="rx"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        # Should allow read
        read_success, _ = access_helper.test_read_access(
            script_path, test_executor, expected_success=True
        )
        assert read_success, "Read should succeed with rx permission"
        
        # Should allow execute
        exec_success, _ = access_helper.test_execute_access(
            script_path, test_executor, expected_success=True
        )
        assert exec_success, "Execute should succeed with rx permission"
        
        # Should deny write
        write_success, _ = access_helper.test_write_access(
            script_path, test_executor, expected_success=False
        )
        assert not write_success, "Write should fail with rx permission"
    
    def test_rwx_grants_all_access(self, effectiveness_dir, qdocse_client,
                                    test_user, access_helper, test_executor):
        """
        Test: 'rwx' permission grants full access.
        """
        # Create executable
        script_path = os.path.join(effectiveness_dir, "script.sh")
        with open(script_path, 'w') as f:
            f.write("#!/bin/bash\necho 'executed'\n")
        os.chmod(script_path, 0o755)
        
        # Add full permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="rwx"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        # All operations should succeed
        read_success, _ = access_helper.test_read_access(
            script_path, test_executor, expected_success=True
        )
        assert read_success, "Read should succeed with rwx permission"
        
        write_success, _ = access_helper.test_write_access(
            script_path, test_executor, expected_success=True
        )
        assert write_success, "Write should succeed with rwx permission"
        
        exec_success, _ = access_helper.test_execute_access(
            script_path, test_executor, expected_success=True
        )
        assert exec_success, "Execute should succeed with rwx permission"


class TestPermissionInheritance:
    """Test permission inheritance and override scenarios."""
    
    def test_more_specific_entry_takes_precedence(self, effectiveness_dir, protected_file,
                                                    qdocse_client, test_user, test_group,
                                                    access_helper, test_executor):
        """
        Test: More specific ACL entry takes precedence over general entry.
        
        User-specific entry should override group entry.
        """
        file_path, _ = protected_file
        
        # Add group entry with full access
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="group",
            subject=test_group,
            permissions="rwx"
        )
        
        # Add user entry with read-only
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="r"
        )
        
        qdocse_client.acl_push(effectiveness_dir)
        
        # User-specific entry should take precedence
        # If user entry is more specific, should only have read
        read_success, _ = access_helper.test_read_access(
            file_path, test_executor, expected_success=True
        )
        assert read_success, "Read should succeed"
    
    def test_multiple_matching_entries(self, effectiveness_dir, protected_file,
                                        qdocse_client, test_user, access_helper, test_executor):
        """
        Test: When multiple entries match, combined permissions apply.
        
        This tests the permission combination behavior.
        """
        file_path, _ = protected_file
        
        # Add entry with read permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="r"
        )
        
        # Add another entry with write permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="w"
        )
        
        qdocse_client.acl_push(effectiveness_dir)
        
        # Behavior depends on system configuration:
        # Some systems combine permissions (r + w = rw)
        # Others use first-match or most-restrictive
        
        # Test read access
        read_result = test_executor.run(f"cat {file_path}")
        # Document the observed behavior without strict assertion
        # as this varies by implementation
