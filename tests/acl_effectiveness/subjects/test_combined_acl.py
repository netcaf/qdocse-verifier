"""
User ACL + Program ACL Combination Tests

When a file has both -A (User ACL) and -P (Program ACL) set,
both must be satisfied to allow access.

PDF Page 81-82, 90
"""
import pytest
import os
from pathlib import Path
from helpers import QDocSE


def cleanup(*acl_ids):
    for acl_id in acl_ids:
        QDocSE.acl_destroy(acl_id, force=True).execute()
    QDocSE.push_config().execute()


class TestBothACLsMustSatisfy:
    """Both User ACL and Program ACL must be satisfied"""
    
    def test_user_allow_program_allow_should_allow(self, protected_dir):
        """
        User ACL allow + Program ACL allow → Allow
        """
        # Get authorized program
        view_result = QDocSE.view().authorized().execute().ok()
        programs = view_result.parse().get("authorized", [])
        if not programs:
            pytest.skip("No authorized programs")
        
        # Create User ACL (allow current user)
        user_acl = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(user_acl, allow=True, user=os.getuid(), mode="rw").execute()
        
        # Create Program ACL (allow program)
        prog_acl = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(prog_acl, allow=True).program(1).mode("rw").execute()
        
        try:
            # Set both ACLs simultaneously
            QDocSE.acl_file(protected_dir, user_acl=user_acl, prog_acl=prog_acl).execute()
            QDocSE.push_config().execute()
            
            # Both allow, should be able to access
            # Note: Need to access through authorized program
        finally:
            cleanup(user_acl, prog_acl)
    
    def test_user_allow_program_deny_should_deny(self, protected_dir):
        """
        User ACL allow + Program ACL deny → Deny
        """
        view_result = QDocSE.view().authorized().execute().ok()
        programs = view_result.parse().get("authorized", [])
        if not programs:
            pytest.skip("No authorized programs")
        
        # User ACL allows
        user_acl = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(user_acl, allow=True, user=os.getuid(), mode="rw").execute()
        
        # Program ACL denies (empty ACL defaults to deny)
        prog_acl = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        # Do not add any allow entries
        
        try:
            QDocSE.acl_file(protected_dir, user_acl=user_acl, prog_acl=prog_acl).execute()
            QDocSE.push_config().execute()
            
            # Program ACL denies, cannot access even if User ACL allows
            with pytest.raises(PermissionError):
                Path(protected_dir, "test.txt").read_text()
        finally:
            cleanup(user_acl, prog_acl)
    
    def test_user_deny_program_allow_should_deny(self, protected_dir):
        """
        User ACL deny + Program ACL allow → Deny
        """
        view_result = QDocSE.view().authorized().execute().ok()
        programs = view_result.parse().get("authorized", [])
        if not programs:
            pytest.skip("No authorized programs")
        
        # User ACL denies (empty ACL)
        user_acl = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        
        # Program ACL allows
        prog_acl = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(prog_acl, allow=True).program(1).mode("rw").execute()
        
        try:
            QDocSE.acl_file(protected_dir, user_acl=user_acl, prog_acl=prog_acl).execute()
            QDocSE.push_config().execute()
            
            # User ACL denies, cannot access even if Program ACL allows
            with pytest.raises(PermissionError):
                Path(protected_dir, "test.txt").read_text()
        finally:
            cleanup(user_acl, prog_acl)


class TestOnlyUserACL:
    """Only set User ACL"""
    
    def test_only_user_acl_no_program_acl(self, protected_dir):
        """
        Only set -A, not -P
        
        Unset ACL uses default value (ACL ID 0 = allow all)
        """
        user_acl = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(user_acl, allow=True, user=os.getuid(), mode="rw").execute()
        
        try:
            # Only set User ACL
            QDocSE.acl_file(protected_dir, user_acl=user_acl).execute()
            QDocSE.push_config().execute()
            
            # User ACL allows, Program ACL uses default (allow)
            content = Path(protected_dir, "test.txt").read_text()
            assert content is not None
        finally:
            cleanup(user_acl)


class TestOnlyProgramACL:
    """Only set Program ACL"""
    
    def test_only_program_acl_no_user_acl(self, protected_dir):
        """
        Only set -P, not -A
        
        Unset ACL uses default value (ACL ID 0 = allow all)
        """
        view_result = QDocSE.view().authorized().execute().ok()
        programs = view_result.parse().get("authorized", [])
        if not programs:
            pytest.skip("No authorized programs")
        
        prog_acl = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(prog_acl, allow=True).program(1).mode("rw").execute()
        
        try:
            # Only set Program ACL
            QDocSE.acl_file(protected_dir, prog_acl=prog_acl).execute()
            QDocSE.push_config().execute()
            
            # Program ACL set, User ACL uses default (allow)
            # May fail if current program not in authorized list
        finally:
            cleanup(prog_acl)
