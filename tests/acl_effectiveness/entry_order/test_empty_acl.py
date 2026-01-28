"""Empty ACL and Default Behavior Tests"""
import pytest
from pathlib import Path
from helpers import QDocSE
from conftest import apply_acl


class TestEmptyACL:
    """Empty ACL denies all by default"""
    
    def test_empty_denies_read(self, protected_dir, empty_acl):
        """Empty ACL denies read"""
        apply_acl(protected_dir, empty_acl)
        
        with pytest.raises(PermissionError):
            Path(protected_dir, "test.txt").read_text()
    
    def test_empty_denies_write(self, protected_dir, empty_acl):
        """Empty ACL denies write"""
        apply_acl(protected_dir, empty_acl)
        
        with pytest.raises(PermissionError):
            Path(protected_dir, "new.txt").write_text("fail")


class TestNoMatchFallthrough:
    """Behavior when no matching entry"""
    
    def test_no_match_denies(self, protected_dir, request):
        """Deny when no entry matches"""
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        # Only allow nobody
        QDocSE.acl_add(acl_id, allow=True, user=65534, mode="rw").execute()
        
        try:
            apply_acl(protected_dir, acl_id)
            with pytest.raises(PermissionError):
                Path(protected_dir, "test.txt").read_text()
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()


class TestACLIDZero:
    """ACL ID 0 (built-in allow)"""
    
    def test_default_allows(self, protected_dir):
        """Uses default (ID 0) allow access when ACL not specified"""
        # Only protect, do not set ACL
        QDocSE.protect(protected_dir, encrypt=False).execute()
        QDocSE.push_config().execute()
        
        content = Path(protected_dir, "test.txt").read_text()
        assert content == "test content"
