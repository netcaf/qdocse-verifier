"""ACL Control for File Delete"""
import pytest
from pathlib import Path
from conftest import apply_acl


class TestFileDelete:
    """File delete permission control"""
    
    def test_delete_with_w_mode(self, protected_dir, allow_rw_acl):
        """Can delete with write permission"""
        apply_acl(protected_dir, allow_rw_acl)
        
        test_file = Path(protected_dir) / "to_delete.txt"
        test_file.write_text("delete me")
        test_file.unlink()
        
        assert not test_file.exists()
    
    def test_delete_denied_without_w(self, protected_dir, allow_r_acl):
        """Cannot delete without write permission"""
        apply_acl(protected_dir, allow_r_acl)
        
        with pytest.raises(PermissionError):
            Path(protected_dir, "test.txt").unlink()
    
    def test_delete_denied_by_acl(self, protected_dir, deny_acl):
        """Cannot delete when ACL denies"""
        apply_acl(protected_dir, deny_acl)
        
        with pytest.raises(PermissionError):
            Path(protected_dir, "test.txt").unlink()
