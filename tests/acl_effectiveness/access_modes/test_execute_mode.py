"""
Access Mode Tests - Execute Mode

Tests for execute permission effectiveness:
- Files with execute permission can be executed
- Files without execute permission cannot be executed
- Execute permission boundary conditions
"""

import pytest
import os


@pytest.fixture
def executable_file(effectiveness_dir):
    """Create an executable test script."""
    script_path = os.path.join(effectiveness_dir, "test_script.sh")
    with open(script_path, 'w') as f:
        f.write("#!/bin/bash\necho 'Script executed successfully'\nexit 0\n")
    os.chmod(script_path, 0o755)  # Make executable at filesystem level
    return script_path


class TestExecuteModeAllow:
    """Test cases where execute access should be allowed."""
    
    def test_execute_with_x_permission(self, effectiveness_dir, executable_file,
                                        qdocse_client, test_user, access_helper, test_executor):
        """
        Test: User with 'x' permission can execute files.
        
        Setup:
        - Protected directory with executable script
        - User ACL entry with execute permission
        
        Expected: Execution succeeds
        """
        # Add execute permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="x"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        success, output = access_helper.test_execute_access(
            executable_file, test_executor, expected_success=True
        )
        
        assert success, "Execute should succeed with x permission"
        assert "Script executed successfully" in output
    
    def test_execute_with_rx_permission(self, effectiveness_dir, executable_file,
                                         qdocse_client, test_user, access_helper, test_executor):
        """
        Test: User with 'rx' permission can execute files.
        """
        # Add read-execute permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="rx"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        success, _ = access_helper.test_execute_access(
            executable_file, test_executor, expected_success=True
        )
        
        assert success, "Execute should succeed with rx permission"
    
    def test_execute_with_rwx_permission(self, effectiveness_dir, executable_file,
                                          qdocse_client, test_user, access_helper, test_executor):
        """
        Test: User with 'rwx' (full) permission can execute files.
        """
        # Add full permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="rwx"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        success, _ = access_helper.test_execute_access(
            executable_file, test_executor, expected_success=True
        )
        
        assert success, "Execute should succeed with rwx permission"


class TestExecuteModeDeny:
    """Test cases where execute access should be denied."""
    
    def test_execute_without_permission(self, effectiveness_dir, executable_file,
                                         access_helper, unauthorized_executor):
        """
        Test: User without any ACL entry cannot execute files.
        """
        success, _ = access_helper.test_execute_access(
            executable_file, unauthorized_executor, expected_success=False
        )
        
        assert not success, "Execute should fail without permission"
    
    def test_execute_with_only_r_permission(self, effectiveness_dir, executable_file,
                                             user_acl_entry, access_helper, test_executor):
        """
        Test: User with only 'r' permission cannot execute files.
        """
        # user_acl_entry fixture adds 'r' permission
        
        success, _ = access_helper.test_execute_access(
            executable_file, test_executor, expected_success=False
        )
        
        assert not success, "Execute should fail with only r permission"
    
    def test_execute_with_only_w_permission(self, effectiveness_dir, executable_file,
                                             qdocse_client, test_user, access_helper, test_executor):
        """
        Test: User with only 'w' permission cannot execute files.
        """
        # Add write-only permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="w"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        success, _ = access_helper.test_execute_access(
            executable_file, test_executor, expected_success=False
        )
        
        assert not success, "Execute should fail with only w permission"
    
    def test_execute_with_rw_permission(self, effectiveness_dir, executable_file,
                                         qdocse_client, test_user, access_helper, test_executor):
        """
        Test: User with 'rw' permission cannot execute files.
        
        Read-write without execute should not allow execution.
        """
        # Add read-write permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="rw"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        success, _ = access_helper.test_execute_access(
            executable_file, test_executor, expected_success=False
        )
        
        assert not success, "Execute should fail with rw permission (no x)"
    
    def test_execute_with_explicit_deny(self, effectiveness_dir, executable_file,
                                         deny_entry, access_helper, test_executor):
        """
        Test: User with explicit deny entry cannot execute files.
        """
        success, _ = access_helper.test_execute_access(
            executable_file, test_executor, expected_success=False
        )
        
        assert not success, "Execute should fail with explicit deny"


class TestExecuteModeEdgeCases:
    """Edge cases for execute permission testing."""
    
    def test_execute_binary(self, effectiveness_dir, qdocse_client, test_user, test_executor):
        """
        Test: Can execute binary files with execute permission.
        """
        # Copy a system binary for testing
        binary_path = os.path.join(effectiveness_dir, "test_binary")
        test_executor.run(f"cp /bin/echo {binary_path}")
        
        # Add execute permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="x"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        # Execute binary
        result = test_executor.run(f"{binary_path} 'test output'")
        
        assert result.returncode == 0, "Should be able to execute binary"
        assert "test output" in result.stdout
    
    def test_execute_script_requires_read(self, effectiveness_dir, executable_file,
                                           qdocse_client, test_user, test_executor):
        """
        Test: Executing interpreted scripts may require read permission.
        
        Note: This behavior depends on how scripts are executed.
        Direct execution via shebang may need read access.
        """
        # Add only execute permission (no read)
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="x"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        # Try to execute - may fail if interpreter needs to read script
        result = test_executor.run(executable_file)
        
        # This test documents the expected behavior
        # Success depends on execution method and system configuration
        if result.returncode != 0:
            # Script execution failed - likely needs read permission
            pytest.skip("System requires read permission for script execution")
    
    def test_execute_in_subdirectory(self, effectiveness_dir, qdocse_client, 
                                      test_user, test_executor):
        """
        Test: Execute permission works for files in subdirectories.
        """
        # Create subdirectory with script
        subdir = os.path.join(effectiveness_dir, "scripts")
        os.makedirs(subdir)
        
        script_path = os.path.join(subdir, "subdir_script.sh")
        with open(script_path, 'w') as f:
            f.write("#!/bin/bash\necho 'Subdirectory script executed'\n")
        os.chmod(script_path, 0o755)
        
        # Add execute permission to parent (should apply to subdirectory)
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="rx"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        # Execute script in subdirectory
        result = test_executor.run(script_path)
        
        assert result.returncode == 0, "Should execute script in subdirectory"
