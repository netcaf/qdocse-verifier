"""Behavior when Allow Entry is First"""
import pytest
import os
from pathlib import Path
from helpers import QDocSE
from conftest import apply_acl


class TestAllowFirst:
    """Allow before Deny, matches Allow then allows"""
    
    def test_allow_then_deny_grants(self, protected_dir, request):
        """Order: Allow -> Deny = Allow"""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        # Allow first, then Deny
        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rw").execute()
        QDocSE.acl_add(acl_id, allow=False, user=uid, mode="rw").execute()
        
        try:
            apply_acl(protected_dir, acl_id)
            content = Path(protected_dir, "test.txt").read_text()
            assert content == "test content"
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
    
    def test_allow_specific_deny_general(self, protected_dir, request):
        """Allow specific user, Deny all = Allow that user"""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        # Allow current user
        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rw").execute()
        # Deny other user
        QDocSE.acl_add(acl_id, allow=False, user=65534, mode="rw").execute()
        
        try:
            apply_acl(protected_dir, acl_id)
            content = Path(protected_dir, "test.txt").read_text()
            assert content == "test content"
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
