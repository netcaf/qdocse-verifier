"""Config Persistence Tests - push_config"""
import pytest
import os
from pathlib import Path
from helpers import QDocSE


class TestPushConfigRequired:
    """Behavior difference before and after push_config"""
    
    def test_not_effective_without_push(self, protected_dir, request):
        """ACL not effective without push_config"""
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=False, user=os.getuid(), mode="rw").execute()
        
        try:
            # Set ACL but don't push
            QDocSE.acl_file(protected_dir, user_acl=acl_id).execute()
            # Don't call push_config
            
            # Should still be accessible (old config)
            content = Path(protected_dir, "test.txt").read_text()
            assert content == "test content"
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
    
    def test_effective_after_push(self, protected_dir, request):
        """ACL effective after push_config"""
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=False, user=os.getuid(), mode="rw").execute()
        
        try:
            QDocSE.acl_file(protected_dir, user_acl=acl_id).execute()
            QDocSE.push_config().execute()  # Push config
            
            # Now should be denied
            with pytest.raises(PermissionError):
                Path(protected_dir, "test.txt").read_text()
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()


class TestPendingState:
    """Pending state check"""
    
    def test_shows_pending_before_push(self, protected_dir, request):
        """Shows Pending state after modification"""
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw").execute()
        
        try:
            QDocSE.acl_file(protected_dir, user_acl=acl_id).execute()
            
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            assert "Pending" in list_result.result.stdout
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
    
    def test_no_pending_after_push(self, protected_dir, request):
        """No Pending state after push"""
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw").execute()
        
        try:
            QDocSE.acl_file(protected_dir, user_acl=acl_id).execute()
            QDocSE.push_config().execute()
            
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            assert "Pending" not in list_result.result.stdout
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
