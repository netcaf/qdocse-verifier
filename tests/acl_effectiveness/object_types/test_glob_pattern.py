"""
Glob Pattern Matching Effect on ACL Application

PDF Page 77-78, 117:
- -dp match pattern
- -excl exclude pattern
- "This option works with local drives only; it has no effect with remote drives"
"""
import pytest
import os
from pathlib import Path
from helpers import QDocSE


def cleanup(acl_id):
    QDocSE.acl_destroy(acl_id, force=True).execute()
    QDocSE.push_config().execute()


class TestDpPattern:
    """-dp matching pattern tests"""
    
    def test_dp_applies_only_to_matching(self, temp_dir):
        """
        -dp only applies ACL to matching files
        """
        # Create files of different types
        Path(temp_dir, "doc1.txt").write_text("txt1")
        Path(temp_dir, "doc2.txt").write_text("txt2")
        Path(temp_dir, "data.csv").write_text("csv")
        Path(temp_dir, "config.cfg").write_text("cfg")
        
        # Protect directory
        QDocSE.protect(temp_dir, encrypt=False).execute()
        
        # Create ACL
        acl_id = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=False, user=os.getuid(), mode="rw").execute()
        
        try:
            # Apply ACL only to *.txt files
            QDocSE.acl_file().dir(temp_dir).pattern("*.txt") \
                .user_acl(acl_id).execute()
            QDocSE.push_config().execute()
            
            # txt files should be denied
            with pytest.raises(PermissionError):
                Path(temp_dir, "doc1.txt").read_text()
            
            # csv files unaffected (use default ACL)
            content = Path(temp_dir, "data.csv").read_text()
            assert content == "csv"
            
        finally:
            cleanup(acl_id)
            QDocSE.unprotect(temp_dir).execute()
    
    def test_dp_recursive_matching(self, temp_dir):
        """
        -dp also applies to subdirectories
        """
        # Create subdirectory structure
        subdir = Path(temp_dir) / "subdir"
        subdir.mkdir()
        Path(temp_dir, "root.txt").write_text("root")
        Path(subdir, "sub.txt").write_text("sub")
        
        QDocSE.protect(temp_dir, encrypt=False).execute()
        
        acl_id = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="r").execute()
        
        try:
            QDocSE.acl_file().dir(temp_dir).pattern("*.txt") \
                .user_acl(acl_id).execute()
            QDocSE.push_config().execute()
            
            # txt in root and subdirectories should be controlled by ACL
            assert Path(temp_dir, "root.txt").read_text() == "root"
            assert Path(subdir, "sub.txt").read_text() == "sub"
            
        finally:
            cleanup(acl_id)
            QDocSE.unprotect(temp_dir).execute()


class TestExclPattern:
    """-excl exclusion pattern tests"""
    
    def test_excl_excludes_matching(self, temp_dir):
        """
        -excl excludes matching files
        """
        Path(temp_dir, "include1.txt").write_text("inc1")
        Path(temp_dir, "include2.txt").write_text("inc2")
        Path(temp_dir, "exclude.txt").write_text("excl")
        
        QDocSE.protect(temp_dir, encrypt=False).execute()
        
        acl_id = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=False, user=os.getuid(), mode="rw").execute()
        
        try:
            # All files, but exclude exclude.txt
            QDocSE.acl_file().dir(temp_dir) \
                .pattern("*.txt").exclude("exclude*") \
                .user_acl(acl_id).execute()
            QDocSE.push_config().execute()
            
            # include*.txt should be denied
            with pytest.raises(PermissionError):
                Path(temp_dir, "include1.txt").read_text()
            
            # exclude.txt unaffected
            content = Path(temp_dir, "exclude.txt").read_text()
            assert content == "excl"
            
        finally:
            cleanup(acl_id)
            QDocSE.unprotect(temp_dir).execute()
    
    def test_dp_then_excl_order(self, temp_dir):
        """
        -dp adds first, -excl removes after
        """
        Path(temp_dir, "data.doc").write_text("doc")
        Path(temp_dir, "data.txt").write_text("txt")
        Path(temp_dir, "temp.txt").write_text("temp")
        
        QDocSE.protect(temp_dir, encrypt=False).execute()
        
        acl_id = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=False, user=os.getuid(), mode="rw").execute()
        
        try:
            # Match all .txt, but exclude temp*
            QDocSE.acl_file().dir(temp_dir) \
                .pattern("*.txt").exclude("temp*") \
                .user_acl(acl_id).execute()
            QDocSE.push_config().execute()
            
            # data.txt should be denied
            with pytest.raises(PermissionError):
                Path(temp_dir, "data.txt").read_text()
            
            # temp.txt unaffected
            assert Path(temp_dir, "temp.txt").read_text() == "temp"
            
            # doc unaffected
            assert Path(temp_dir, "data.doc").read_text() == "doc"
            
        finally:
            cleanup(acl_id)
            QDocSE.unprotect(temp_dir).execute()


class TestNonMatchingUnchanged:
    """Non-matching files keep original ACL"""
    
    def test_non_matching_keeps_original_acl(self, temp_dir):
        """
        Files not matching -dp keep their original ACL settings
        """
        Path(temp_dir, "file.txt").write_text("txt")
        Path(temp_dir, "file.csv").write_text("csv")
        
        QDocSE.protect(temp_dir, encrypt=False).execute()
        
        # First ACL (for txt)
        acl1 = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(acl1, allow=True, user=os.getuid(), mode="r").execute()
        
        # Second ACL (for csv)
        acl2 = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(acl2, allow=True, user=os.getuid(), mode="rw").execute()
        
        try:
            # Set ACL for csv first
            QDocSE.acl_file().dir(temp_dir).pattern("*.csv") \
                .user_acl(acl2).execute()
            QDocSE.push_config().execute()
            
            # Set ACL for txt, csv should be unaffected
            QDocSE.acl_file().dir(temp_dir).pattern("*.txt") \
                .user_acl(acl1).execute()
            QDocSE.push_config().execute()
            
            # txt read-only
            assert Path(temp_dir, "file.txt").read_text() == "txt"
            with pytest.raises(PermissionError):
                Path(temp_dir, "file.txt").write_text("fail")
            
            # csv read-write
            assert Path(temp_dir, "file.csv").read_text() == "csv"
            Path(temp_dir, "file.csv").write_text("updated")
            
        finally:
            cleanup(acl1)
            cleanup(acl2)
            QDocSE.unprotect(temp_dir).execute()
