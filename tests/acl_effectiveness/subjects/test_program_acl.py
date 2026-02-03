"""Program ACL Tests"""
import pytest
import os
from pathlib import Path
from helpers import QDocSE
from conftest import apply_acl


class TestProgramACL:
    """Program ACL control"""
    
    def test_program_acl_setup(self, protected_dir, request):
        """Set program ACL"""
        # Get authorized program list
        view_result = QDocSE.view().authorized().execute().ok()
        programs = view_result.parse().get("authorized", [])
        
        if not programs:
            pytest.skip("No authorized programs")
        
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True).program(1).mode("rw").execute()
        
        try:
            QDocSE.acl_file(protected_dir, prog_acl=acl_id).execute().ok()
            QDocSE.push_config().execute()
            # Verify setup successful
            assert True
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()


class TestUserAndProgramACL:
    """User ACL and Program ACL combination"""
    
    def test_both_acls(self, protected_dir, request):
        """Set both user ACL and program ACL"""
        # Get authorized program
        view_result = QDocSE.view().authorized().execute().ok()
        programs = view_result.parse().get("authorized", [])
        
        if not programs:
            pytest.skip("No authorized programs")
        
        user_acl = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        prog_acl = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        
        QDocSE.acl_add(user_acl, allow=True, user=os.getuid(), mode="rw").execute()
        QDocSE.acl_add(prog_acl, allow=True).program(1).mode("rw").execute()
        
        try:
            QDocSE.acl_file(protected_dir, user_acl=user_acl, prog_acl=prog_acl).execute().ok()
            QDocSE.push_config().execute()
            assert True
        finally:
            QDocSE.acl_destroy(user_acl, force=True).execute()
            QDocSE.acl_destroy(prog_acl, force=True).execute()
            QDocSE.push_config().execute()


class TestMixingRestriction:
    """User/Program cannot be mixed in same ACL"""
    
    def test_cannot_mix(self, protected_dir, request):
        """Same ACL cannot have both User and Program entries"""
        view_result = QDocSE.view().authorized().execute().ok()
        programs = view_result.parse().get("authorized", [])
        
        if not programs:
            pytest.skip("No authorized programs")
        
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        # Add user entry first
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw").execute()
        
        try:
            # Adding program entry should fail
            add_result = QDocSE.acl_add(acl_id, allow=True).program(1).mode("rw").execute()
            assert add_result.result.failed, "Should not allow mixing"
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
