"""
File Lifecycle Tests - Create Operations

Tests for file creation in protected directories:
- Creating new files with write permission
- Creating files without permission (should fail)
- File creation inheritance
"""

import pytest
import os


class TestFileCreationAllowed:
    """Test cases where file creation should succeed."""
    
    def test_create_file_with_w_permission(self, effectiveness_dir, qdocse_client,
                                            test_user, test_executor):
        """
        Test: User with 'w' permission can create new files.
        
        Write permission should allow creation of new files in the directory.
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
        new_file = os.path.join(effectiveness_dir, "created_file.txt")
        result = test_executor.run(f"echo 'new content' > {new_file}")
        
        assert result.returncode == 0, "File creation should succeed"
        assert os.path.exists(new_file), "Created file should exist"
    
    def test_create_file_with_rw_permission(self, effectiveness_dir, qdocse_client,
                                             test_user, test_executor):
        """
        Test: User with 'rw' permission can create new files.
        """
        # Add read-write permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="rw"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        # Create new file
        new_file = os.path.join(effectiveness_dir, "created_rw.txt")
        result = test_executor.run(f"touch {new_file}")
        
        assert result.returncode == 0, "File creation should succeed with rw"
        assert os.path.exists(new_file), "Created file should exist"
    
    def test_create_multiple_files(self, effectiveness_dir, qdocse_client,
                                    test_user, test_executor):
        """
        Test: Can create multiple files in protected directory.
        """
        # Add write permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="w"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        # Create multiple files
        for i in range(5):
            file_path = os.path.join(effectiveness_dir, f"file_{i}.txt")
            result = test_executor.run(f"echo 'content {i}' > {file_path}")
            assert result.returncode == 0, f"Creating file_{i} should succeed"
        
        # Verify all files exist
        files = os.listdir(effectiveness_dir)
        assert len([f for f in files if f.startswith("file_")]) == 5


class TestFileCreationDenied:
    """Test cases where file creation should fail."""
    
    def test_create_file_without_permission(self, effectiveness_dir, 
                                             unauthorized_executor):
        """
        Test: User without permission cannot create files.
        """
        new_file = os.path.join(effectiveness_dir, "unauthorized.txt")
        result = unauthorized_executor.run(f"touch {new_file}")
        
        assert result.returncode != 0, "File creation should fail without permission"
        assert not os.path.exists(new_file), "File should not be created"
    
    def test_create_file_with_only_r_permission(self, effectiveness_dir, 
                                                 user_acl_entry, test_executor):
        """
        Test: User with only 'r' permission cannot create files.
        """
        # user_acl_entry provides 'r' permission
        
        new_file = os.path.join(effectiveness_dir, "readonly_create.txt")
        result = test_executor.run(f"touch {new_file}")
        
        assert result.returncode != 0, "File creation should fail with only r"
    
    def test_create_file_with_only_x_permission(self, effectiveness_dir, qdocse_client,
                                                 test_user, test_executor):
        """
        Test: User with only 'x' permission cannot create files.
        """
        # Add execute-only permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="x"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        new_file = os.path.join(effectiveness_dir, "execonly_create.txt")
        result = test_executor.run(f"touch {new_file}")
        
        assert result.returncode != 0, "File creation should fail with only x"


class TestFileCreationInheritance:
    """Test ACL inheritance for newly created files."""
    
    def test_new_file_inherits_directory_acl(self, effectiveness_dir, qdocse_client,
                                              test_user, test_executor, access_helper):
        """
        Test: Newly created files inherit directory ACL.
        
        Files created in protected directory should be automatically protected.
        """
        # Add full permission
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="rwx"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        # Create new file
        new_file = os.path.join(effectiveness_dir, "inherited.txt")
        test_executor.run(f"echo 'content' > {new_file}")
        
        # Verify file inherits protection
        # User should be able to read the file they created
        success, _ = access_helper.test_read_access(
            new_file, test_executor, expected_success=True
        )
        assert success, "Created file should be accessible per inherited ACL"
    
    def test_new_file_in_subdirectory_inherits_acl(self, effectiveness_dir, qdocse_client,
                                                    test_user, test_executor):
        """
        Test: Files created in subdirectories inherit ACL.
        
        Subdirectory files should be controlled by parent directory ACL.
        """
        # Create subdirectory
        subdir = os.path.join(effectiveness_dir, "subdir")
        os.makedirs(subdir)
        
        # Add permission to parent
        qdocse_client.acl_add(
            path=effectiveness_dir,
            subject_type="user",
            subject=test_user,
            permissions="rw"
        )
        qdocse_client.acl_push(effectiveness_dir)
        
        # Create file in subdirectory
        sub_file = os.path.join(subdir, "subfile.txt")
        result = test_executor.run(f"echo 'subdir content' > {sub_file}")
        
        assert result.returncode == 0, "Should create file in subdirectory"
        assert os.path.exists(sub_file), "Subdirectory file should exist"
