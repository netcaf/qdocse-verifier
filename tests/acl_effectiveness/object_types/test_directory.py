"""ACL Control for Directory Objects"""
import pytest
from pathlib import Path
from conftest import apply_acl


class TestDirectory:
    """Directory-level ACL control"""
    
    def test_create_subdir(self, protected_dir, allow_rw_acl):
        """Create subdirectory"""
        apply_acl(protected_dir, allow_rw_acl)
        
        subdir = Path(protected_dir) / "subdir"
        subdir.mkdir()
        assert subdir.is_dir()
    
    def test_remove_empty_subdir(self, protected_dir, allow_rw_acl):
        """Remove empty subdirectory"""
        subdir = Path(protected_dir) / "empty_subdir"
        subdir.mkdir()
        
        apply_acl(protected_dir, allow_rw_acl)
        subdir.rmdir()
        assert not subdir.exists()
    
    def test_list_dir_contents(self, protected_dir, allow_r_acl):
        """List directory contents"""
        apply_acl(protected_dir, allow_r_acl)
        
        entries = list(Path(protected_dir).iterdir())
        assert any("test.txt" in str(e) for e in entries)


class TestRecursive:
    """Recursive directory ACL"""
    
    def test_acl_applies_to_subdirs(self, protected_dir, allow_rw_acl):
        """ACL applies recursively to subdirectories"""
        subdir = Path(protected_dir) / "sub"
        subdir.mkdir()
        subfile = subdir / "file.txt"
        subfile.write_text("sub content")
        
        apply_acl(protected_dir, allow_rw_acl)
        
        # Subdirectory files should be controlled by ACL
        content = subfile.read_text()
        assert content == "sub content"
