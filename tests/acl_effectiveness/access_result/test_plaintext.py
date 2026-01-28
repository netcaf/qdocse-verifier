"""Return plaintext content when access is allowed"""
import pytest
from pathlib import Path
from conftest import apply_acl


class TestPlaintextAccess:
    """Allowed user reading encrypted file should get plaintext"""
    
    def test_read_encrypted_returns_plaintext(self, encrypted_dir, allow_rw_acl):
        """Encrypted file transparent decryption"""
        apply_acl(encrypted_dir, allow_rw_acl)
        
        test_file = Path(encrypted_dir) / "secret.txt"
        content = test_file.read_text()
        
        assert content == "secret content"
    
    def test_write_then_read_plaintext(self, encrypted_dir, allow_rw_acl):
        """Write then read still returns plaintext"""
        apply_acl(encrypted_dir, allow_rw_acl)
        
        test_file = Path(encrypted_dir) / "new.txt"
        test_file.write_text("new content")
        
        assert test_file.read_text() == "new content"
    
    def test_read_protected_unencrypted(self, protected_dir, allow_r_acl):
        """Unencrypted protected file normal read"""
        apply_acl(protected_dir, allow_r_acl)
        
        test_file = Path(protected_dir) / "test.txt"
        content = test_file.read_text()
        
        assert content == "test content"
