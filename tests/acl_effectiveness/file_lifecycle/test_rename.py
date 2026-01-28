"""ACL Control for File Rename/Move"""
import pytest
from pathlib import Path
from conftest import apply_acl


class TestFileRename:
    """File Rename"""
    
    def test_rename_with_w_mode(self, protected_dir, allow_rw_acl):
        """Can rename with write permission"""
        apply_acl(protected_dir, allow_rw_acl)
        
        old = Path(protected_dir) / "test.txt"
        new = Path(protected_dir) / "renamed.txt"
        old.rename(new)
        
        assert not old.exists()
        assert new.exists()
    
    def test_rename_denied_without_w(self, protected_dir, allow_r_acl):
        """Cannot rename without write permission"""
        apply_acl(protected_dir, allow_r_acl)
        
        with pytest.raises(PermissionError):
            old = Path(protected_dir) / "test.txt"
            new = Path(protected_dir) / "fail.txt"
            old.rename(new)


class TestFileMove:
    """File Move"""
    
    def test_move_within_protected_dir(self, protected_dir, allow_rw_acl):
        """Move within protected directory"""
        subdir = Path(protected_dir) / "subdir"
        subdir.mkdir()
        
        apply_acl(protected_dir, allow_rw_acl)
        
        src = Path(protected_dir) / "test.txt"
        dst = subdir / "moved.txt"
        src.rename(dst)
        
        assert dst.exists()
        assert dst.read_text() == "test content"
