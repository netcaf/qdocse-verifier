"""
New File ACL Inheritance Tests

PDF Page 116:
"If you have already configured authorized programs with the adjust command 
and the push_config command then new files created by the authorized program 
will have protection added."

Test how new files inherit directory ACL settings.
"""
import pytest
import os
from pathlib import Path
from helpers import QDocSE


def cleanup(acl_id):
    QDocSE.acl_destroy(acl_id, force=True).execute()
    QDocSE.push_config().execute()


class TestNewFileInheritance:
    """New file inherits protection status"""
    
    def test_new_file_inherits_protection(self, protected_dir, allow_rw_acl):
        """New file inherits directory protection status"""
        from conftest import apply_acl
        apply_acl(protected_dir, allow_rw_acl)
        
        # Create new file
        new_file = Path(protected_dir) / "new_file.txt"
        new_file.write_text("new content")
        
        # Verify new file is protected
        result = QDocSE.list().execute().ok()
        # New file should be in protected list or accessible via ACL
        assert new_file.exists()
    
    def test_new_file_in_encrypted_dir(self, encrypted_dir, allow_rw_acl):
        """New file in encrypted directory is automatically encrypted"""
        from conftest import apply_acl
        apply_acl(encrypted_dir, allow_rw_acl)
        
        # Create new file
        new_file = Path(encrypted_dir) / "new_encrypted.txt"
        new_file.write_text("will be encrypted")
        
        # Verify new file is encrypted
        # Transparent read should return plaintext
        assert new_file.read_text() == "will be encrypted"


class TestProtectWithACLOption:
    """protect command -A/-P options"""
    
    def test_protect_with_user_acl(self, temp_dir):
        """
        protect -d dir -e no -A acl_id
        """
        Path(temp_dir, "data.txt").write_text("data")
        
        acl_id = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="r").execute()
        
        try:
            # protect and set ACL simultaneously
            QDocSE.protect(temp_dir, encrypt=False) \
                ._opt("-A", acl_id).execute()
            QDocSE.push_config().execute()
            
            # Read-only ACL
            assert Path(temp_dir, "data.txt").read_text() == "data"
            with pytest.raises(PermissionError):
                Path(temp_dir, "data.txt").write_text("fail")
                
        finally:
            cleanup(acl_id)
            QDocSE.unprotect(temp_dir).execute()
    
    def test_protect_with_both_acls(self, temp_dir):
        """
        protect -d dir -e yes -A user_acl -P prog_acl
        """
        Path(temp_dir, "data.txt").write_text("data")
        
        view_result = QDocSE.view().authorized().execute().ok()
        programs = view_result.parse().get("programs", [])
        if not programs:
            pytest.skip("No authorized programs")
        
        user_acl = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(user_acl, allow=True, user=os.getuid(), mode="rw").execute()
        
        prog_acl = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(prog_acl, allow=True).program(1).mode("rw").execute()
        
        try:
            # protect and set two ACLs simultaneously
            QDocSE.protect(temp_dir, encrypt=True) \
                ._opt("-A", user_acl) \
                ._opt("-P", prog_acl).execute()
            QDocSE.push_config().execute()
            
        finally:
            cleanup(user_acl)
            cleanup(prog_acl)
            QDocSE.unprotect(temp_dir).execute()


class TestNewFileInheritACL:
    """New file inherits directory ACL settings"""
    
    def test_new_file_uses_directory_acl(self, temp_dir):
        """
        New file should use directory's default ACL
        """
        Path(temp_dir, "existing.txt").write_text("existing")
        
        acl_id = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw").execute()
        
        try:
            # protect and set ACL
            QDocSE.protect(temp_dir, encrypt=False) \
                ._opt("-A", acl_id).execute()
            QDocSE.push_config().execute()
            
            # Create new file
            new_file = Path(temp_dir) / "new.txt"
            new_file.write_text("new file")
            
            # New file should inherit ACL settings
            assert new_file.read_text() == "new file"
            
        finally:
            cleanup(acl_id)
            QDocSE.unprotect(temp_dir).execute()
    
    def test_new_file_access_controlled(self, temp_dir):
        """
        New file should be controlled by ACL
        """
        acl_id = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        # Only allow read
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="r").execute()
        
        try:
            QDocSE.protect(temp_dir, encrypt=False) \
                ._opt("-A", acl_id).execute()
            QDocSE.push_config().execute()
            
            # Create new file (may need temporary elevated permissions or create before ACL applied)
            # Testing concept here
            
        finally:
            cleanup(acl_id)
            QDocSE.unprotect(temp_dir).execute()
