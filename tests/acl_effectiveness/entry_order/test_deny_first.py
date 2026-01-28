"""Behavior when Deny Entry is First"""
import pytest
import os
from pathlib import Path
from helpers import QDocSE
from conftest import apply_acl


class TestDenyFirst:
    """Deny before Allow, matches Deny then denies"""
    
    def test_deny_then_allow_denies(self, protected_dir, request):
        """Order: Deny -> Allow = Deny"""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        # Deny first, then Allow
        QDocSE.acl_add(acl_id, allow=False, user=uid, mode="rw").execute()
        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rw").execute()
        
        try:
            apply_acl(protected_dir, acl_id)
            with pytest.raises(PermissionError):
                Path(protected_dir, "test.txt").read_text()
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()


class TestOrderChange:
    """Change order using acl_edit"""
    
    def test_edit_order_changes_result(self, protected_dir, request):
        """Changing order changes access result"""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        # Initial: Deny -> Allow (denied)
        QDocSE.acl_add(acl_id, allow=False, user=uid, mode="rw").execute()
        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rw").execute()
        
        try:
            apply_acl(protected_dir, acl_id)
            
            # Initially should deny
            with pytest.raises(PermissionError):
                Path(protected_dir, "test.txt").read_text()
            
            # Adjust order: move entry 2 to top
            QDocSE.acl_edit(acl_id, entry=2, position="top").execute()
            QDocSE.push_config().execute()
            
            # Now should allow
            content = Path(protected_dir, "test.txt").read_text()
            assert content == "test content"
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
