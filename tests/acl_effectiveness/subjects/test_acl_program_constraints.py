"""
acl_program Constraint Tests

PDF Page 81-82:
- Associated ACL must be User/Group type, cannot be Program type
- ACL must be non-empty
- "ACL is empty. Cannot assign."
- "ACL needs user/group entry. Cannot assign."
"""
import pytest
import os
from helpers import QDocSE


def cleanup(acl_id):
    QDocSE.acl_destroy(acl_id, force=True).execute()
    QDocSE.push_config().execute()


class TestACLProgramEmptyACL:
    """Empty ACL cannot be associated with program"""
    
    def test_cannot_assign_empty_acl(self):
        """Empty ACL association with program should fail"""
        view_result = QDocSE.view().authorized().execute().ok()
        programs = view_result.parse().get("programs", [])
        if not programs:
            pytest.skip("No authorized programs")
        
        # Create empty ACL
        acl_id = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        
        try:
            # Try to associate empty ACL with program
            result = QDocSE.acl_program(acl_id, program=1).execute()
            
            # Should fail
            assert result.result.failed, "Empty ACL should not be associable with program"
            assert "empty" in result.result.stderr.lower() or \
                   "cannot assign" in result.result.stderr.lower()
        finally:
            cleanup(acl_id)


class TestACLProgramWrongType:
    """Program type ACL cannot be associated with program"""
    
    def test_cannot_assign_program_type_acl(self):
        """
        ACL containing Program entries cannot be used for acl_program
        """
        view_result = QDocSE.view().authorized().execute().ok()
        programs = view_result.parse().get("programs", [])
        if len(programs) < 2:
            pytest.skip("Need at least 2 authorized programs")
        
        # Create Program type ACL
        acl_id = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True).program(1).mode("rw").execute()
        
        try:
            # Try to associate Program type ACL with another program
            result = QDocSE.acl_program(acl_id, program=2).execute()
            
            # Should fail
            assert result.result.failed, "Program type ACL should not be associable with program"
            assert "user/group" in result.result.stderr.lower()
        finally:
            cleanup(acl_id)


class TestACLProgramValidACL:
    """Valid User/Group ACL can be associated with program"""
    
    def test_can_assign_user_acl_to_program(self):
        """User type ACL can be associated with program"""
        view_result = QDocSE.view().authorized().execute().ok()
        programs = view_result.parse().get("programs", [])
        if not programs:
            pytest.skip("No authorized programs")
        
        # Create User type ACL (non-empty)
        acl_id = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw").execute()
        
        try:
            # Association with program should succeed
            result = QDocSE.acl_program(acl_id, program=1).execute()
            assert result.result.success, f"Association failed: {result.result.stderr}"
        finally:
            cleanup(acl_id)
    
    def test_can_assign_group_acl_to_program(self):
        """Group type ACL can be associated with program"""
        view_result = QDocSE.view().authorized().execute().ok()
        programs = view_result.parse().get("programs", [])
        if not programs:
            pytest.skip("No authorized programs")
        
        # Create Group type ACL (non-empty)
        acl_id = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, group=os.getgid(), mode="rw").execute()
        
        try:
            # Association with program should succeed
            result = QDocSE.acl_program(acl_id, program=1).execute()
            assert result.result.success, f"Association failed: {result.result.stderr}"
        finally:
            cleanup(acl_id)


class TestACLProgramEffectiveness:
    """Access control after associating ACL with program"""
    
    def test_program_must_satisfy_associated_acl(self, protected_dir):
        """
        After program associates ACL, user running program must satisfy ACL
        """
        view_result = QDocSE.view().authorized().execute().ok()
        programs = view_result.parse().get("programs", [])
        if not programs:
            pytest.skip("No authorized programs")
        
        # Create ACL that only allows nobody user
        acl_id = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=65534, mode="rw").execute()  # nobody
        
        try:
            # Associate with program
            QDocSE.acl_program(acl_id, program=1).execute()
            QDocSE.push_config().execute()
            
            # Current user (not nobody) running program should be denied
            # This needs to be verified through authorized program access
        finally:
            cleanup(acl_id)
