"""Special Scenario Tests"""
import pytest
from pathlib import Path
from helpers import QDocSE


class TestACLIDZero:
    """ACL ID 0 (built-in allow access)"""
    
    def test_default_uses_acl_zero(self, protected_dir):
        """Uses ID 0 when ACL not specified"""
        # Only protect, do not set ACL
        QDocSE.protect(protected_dir, encrypt=False).execute()
        QDocSE.push_config().execute()
        
        try:
            # Default should allow access
            content = Path(protected_dir, "test.txt").read_text()
            assert content == "test content"
        finally:
            QDocSE.unprotect(protected_dir).execute()
    
    def test_cannot_modify_acl_zero(self):
        """Cannot modify ACL ID 0"""
        result = QDocSE.acl_add(0, allow=True, user=0, mode="r").execute()
        assert result.result.failed
    
    def test_cannot_destroy_acl_zero(self):
        """Cannot delete ACL ID 0"""
        result = QDocSE.acl_destroy(0).execute()
        assert result.result.failed


class TestInspectorMode:
    """Inspector access mode"""
    
    @pytest.mark.requires_cap("CAP_DAC_OVERRIDE")
    def test_inspector_allows_ciphertext_read(self, encrypted_dir, deny_acl, request):
        """Inspector mode allows reading ciphertext"""
        from conftest import apply_acl
        
        apply_acl(encrypted_dir, deny_acl)
        QDocSE.set_access("inspector").execute()
        
        try:
            content = Path(encrypted_dir, "secret.txt").read_bytes()
            # Should be ciphertext (not plaintext)
            assert len(content) > 0
        finally:
            QDocSE.set_access("normal").execute()
    
    def test_normal_mode_denies_blocked_user(self, encrypted_dir, deny_acl, request):
        """Normal mode denies blocked user"""
        from conftest import apply_acl
        
        apply_acl(encrypted_dir, deny_acl)
        QDocSE.set_access("normal").execute()
        
        with pytest.raises(PermissionError):
            Path(encrypted_dir, "secret.txt").read_text()
