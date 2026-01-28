"""ACL Control for Encrypted Files"""
import pytest
from pathlib import Path
from conftest import apply_acl


class TestEncryptedFile:
    """Encrypted file access control"""
    
    def test_allowed_reads_plaintext(self, encrypted_dir, allow_rw_acl):
        """Allowed user reads plaintext"""
        apply_acl(encrypted_dir, allow_rw_acl)
        
        content = Path(encrypted_dir, "secret.txt").read_text()
        assert content == "secret content"
    
    def test_allowed_writes_encrypted(self, encrypted_dir, allow_rw_acl):
        """Allowed user writes (transparent encryption)"""
        apply_acl(encrypted_dir, allow_rw_acl)
        
        test_file = Path(encrypted_dir) / "new_secret.txt"
        test_file.write_text("new secret")
        
        assert test_file.read_text() == "new secret"
    
    def test_denied_cannot_read(self, encrypted_dir, deny_acl):
        """Denied user cannot read"""
        apply_acl(encrypted_dir, deny_acl)
        
        with pytest.raises(PermissionError):
            Path(encrypted_dir, "secret.txt").read_text()


class TestUnencryptedFile:
    """Unencrypted protected file"""
    
    def test_allowed_reads_content(self, protected_dir, allow_r_acl):
        """Allowed user reads"""
        apply_acl(protected_dir, allow_r_acl)
        
        content = Path(protected_dir, "test.txt").read_text()
        assert content == "test content"
    
    def test_denied_cannot_read(self, protected_dir, deny_acl):
        """Denied user cannot read"""
        apply_acl(protected_dir, deny_acl)
        
        with pytest.raises(PermissionError):
            Path(protected_dir, "test.txt").read_text()
