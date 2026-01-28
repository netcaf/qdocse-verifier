"""User ACL Tests"""
import pytest
import os
import pwd
from pathlib import Path
from helpers import QDocSE
from conftest import apply_acl


class TestUserByUID:
    """Specify user by UID"""
    
    def test_allow_by_uid(self, protected_dir, request):
        """Allow using UID"""
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw").execute()
        
        try:
            apply_acl(protected_dir, acl_id)
            content = Path(protected_dir, "test.txt").read_text()
            assert content == "test content"
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
    
    def test_deny_other_uid(self, protected_dir, request):
        """Other UID denied"""
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


class TestUserByName:
    """Specify user by name"""
    
    def test_allow_by_name(self, protected_dir, request):
        """Allow using username"""
        username = pwd.getpwuid(os.getuid()).pw_name
        
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=username, mode="rw").execute()
        
        try:
            apply_acl(protected_dir, acl_id)
            content = Path(protected_dir, "test.txt").read_text()
            assert content == "test content"
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
