"""Group ACL Tests"""
import pytest
import os
import grp
from pathlib import Path
from helpers import QDocSE
from conftest import apply_acl


class TestGroupByGID:
    """Specify group by GID"""
    
    def test_allow_by_gid(self, protected_dir, request):
        """Allow using GID"""
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, group=os.getgid(), mode="rw").execute()
        
        try:
            apply_acl(protected_dir, acl_id)
            content = Path(protected_dir, "test.txt").read_text()
            assert content == "test content"
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()


class TestGroupByName:
    """Specify group by name"""
    
    def test_allow_by_name(self, protected_dir, request):
        """Allow using group name"""
        groupname = grp.getgrgid(os.getgid()).gr_name
        
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, group=groupname, mode="rw").execute()
        
        try:
            apply_acl(protected_dir, acl_id)
            content = Path(protected_dir, "test.txt").read_text()
            assert content == "test content"
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()


class TestSupplementaryGroup:
    """User's supplementary group"""
    
    def test_allow_supplementary_group(self, protected_dir, request):
        """User is in allowed supplementary group"""
        groups = os.getgroups()
        if not groups:
            pytest.skip("No supplementary groups")
        
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, group=groups[0], mode="rw").execute()
        
        try:
            apply_acl(protected_dir, acl_id)
            content = Path(protected_dir, "test.txt").read_text()
            assert content == "test content"
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
