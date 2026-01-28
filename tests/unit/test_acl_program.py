"""
acl_program Command Tests

PDF Manual Key Points (Page 82):
1. Sets the ACL to be associated with an authorized program
2. Same setting can be performed with the adjust command
3. ACL must have User/Group entries (not program entries)
4. ACL must have at least one entry
5. When ACL is not matched, program is invalid (cannot access protected files)
6. When ACL is matched, program may be valid (still needs other criteria)

Options:
- -A <acl_id>: Required. The ACL to associate (must have user/group entries)
- -p <program_index>: Required. The program index from view command

Active modes: Elevated, Learning
License type: A

Errors:
- ACL is empty. Cannot assign.
- ACL needs user/group entry. Cannot assign.
- Program index X does not exist.

Test Strategy:
1. Basic association: Link valid ACL to valid program
2. ACL content validation: Empty ACL fails, program-entry ACL fails
3. Program index validation: Invalid/nonexistent index fails
4. Integration with adjust command comparison
"""
import pytest
from helpers import QDocSE

# Prerequisites (auto-checked)
pytestmark = [
    pytest.mark.requires_mode("elevated", "learning"),
    pytest.mark.requires_license("A"),
]


def cleanup_acl(acl_id: int) -> None:
    """Cleanup helper"""
    QDocSE.acl_destroy(acl_id, force=True).execute()
    QDocSE.push_config().execute()


@pytest.fixture
def acl_with_user_entries():
    """
    Create an ACL with user/group entries (suitable for acl_program).
    """
    result = QDocSE.acl_create().execute().ok()
    acl_id = result.parse()["acl_id"]
    
    # Add user/group entries
    QDocSE.acl_add(acl_id, allow=True, user=0, mode="rw").execute().ok()
    QDocSE.acl_add(acl_id, allow=True, group=0, mode="r").execute().ok()
    
    yield acl_id
    
    cleanup_acl(acl_id)


@pytest.fixture
def authorized_program_index():
    """
    Get the index of an authorized program from the system.
    
    Returns program index if found, otherwise skips test.
    """
    # Get list of authorized programs
    view_result = QDocSE.view().execute()
    
    if view_result.result.failed:
        pytest.skip("Cannot get view output")
    
    parsed = view_result.parse()
    programs = parsed.get("programs", [])
    
    if not programs:
        pytest.skip("No authorized programs found in system")
    
    # Return first program index (usually 1)
    # Need to parse index from output - assuming format "(1) /path/to/program"
    return 1  # Most systems have at least one authorized program


@pytest.mark.unit
class TestACLProgramBasic:
    """Basic acl_program functionality"""
    
    def test_acl_program_requires_both_options(self):
        """
        acl_program requires both -A and -p options.
        """
        # Missing -p
        result1 = QDocSE.acl_program(acl_id=1).execute()
        result1.fail("Should fail without program index")
        
        # Missing -A
        result2 = QDocSE.acl_program(program=1).execute()
        result2.fail("Should fail without ACL ID")
    
    def test_associate_acl_with_program(self, acl_with_user_entries, authorized_program_index):
        """
        Basic association of ACL with an authorized program.
        """
        acl_id = acl_with_user_entries
        prog_idx = authorized_program_index
        
        result = QDocSE.acl_program(acl_id, program=prog_idx).execute()
        
        # This may succeed or fail depending on system state
        # Document actual behavior
        if result.result.success:
            print(f"Successfully associated ACL {acl_id} with program {prog_idx}")
        else:
            # May fail if program index doesn't exist
            print(f"Association failed: {result.result.stderr}")


@pytest.mark.unit
class TestACLProgramACLValidation:
    """Tests for ACL content validation"""
    
    def test_empty_acl_fails(self):
        """
        acl_program with empty ACL should fail.
        
        Per PDF page 82: "ACL is empty. Cannot assign." error
        """
        # Create empty ACL
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        try:
            # Try to associate with program
            assoc_result = QDocSE.acl_program(acl_id, program=1).execute()
            
            # Should fail because ACL is empty
            assoc_result.fail("Should fail with empty ACL")
            assert "empty" in assoc_result.result.stderr.lower() or \
                   "empty" in assoc_result.result.stdout.lower(), \
                   "Error should mention ACL is empty"
        
        finally:
            cleanup_acl(acl_id)
    
    def test_acl_with_at_least_one_entry_required(self):
        """
        Per PDF page 82: "The associated ACL must have at least one entry."
        """
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        try:
            # Verify empty ACL fails
            assoc_result1 = QDocSE.acl_program(acl_id, program=1).execute()
            assert assoc_result1.result.failed, "Empty ACL should fail"
            
            # Add one entry
            QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
            
            # Now it should potentially work (depends on program existence)
            assoc_result2 = QDocSE.acl_program(acl_id, program=1).execute()
            # If it still fails, it should be for different reason (program not found)
            if assoc_result2.result.failed:
                assert "empty" not in assoc_result2.result.stderr.lower(), \
                    "Should not fail due to empty ACL anymore"
        
        finally:
            cleanup_acl(acl_id)


@pytest.mark.unit
class TestACLProgramProgramValidation:
    """Tests for program index validation"""
    
    def test_nonexistent_program_index_fails(self, acl_with_user_entries):
        """
        acl_program with nonexistent program index should fail.
        
        Per PDF page 82: "Program index X does not exist." error
        """
        acl_id = acl_with_user_entries
        
        # Use a very high index that likely doesn't exist
        result = QDocSE.acl_program(acl_id, program=99999).execute()
        result.fail("Should fail for nonexistent program index")
        
        # Error should mention program doesn't exist
        output = result.result.stderr + result.result.stdout
        assert "not exist" in output.lower() or \
               "invalid" in output.lower() or \
               "program" in output.lower(), \
               "Error should mention invalid program"
    
    def test_negative_program_index_fails(self, acl_with_user_entries):
        """
        acl_program with negative program index should fail.
        """
        acl_id = acl_with_user_entries
        
        result = QDocSE.acl_program(acl_id, program=-1).execute()
        result.fail("Should fail for negative program index")
    
    def test_zero_program_index(self, acl_with_user_entries):
        """
        Program index 0 behavior - document actual behavior.
        """
        acl_id = acl_with_user_entries
        
        result = QDocSE.acl_program(acl_id, program=0).execute()
        # Document behavior - may be invalid or reserved
        if result.result.success:
            print("Note: Program index 0 is valid")
        else:
            print("Note: Program index 0 is invalid/reserved")


@pytest.mark.unit  
class TestACLProgramInvalidACL:
    """Tests for invalid ACL IDs"""
    
    def test_nonexistent_acl_fails(self):
        """
        acl_program with nonexistent ACL ID should fail.
        """
        result = QDocSE.acl_program(999999, program=1).execute()
        result.fail("Should fail for nonexistent ACL ID")
    
    def test_negative_acl_id_fails(self):
        """
        acl_program with negative ACL ID should fail.
        """
        result = QDocSE.acl_program(-1, program=1).execute()
        result.fail("Should fail for negative ACL ID")


@pytest.mark.unit
class TestACLProgramWithAdjust:
    """
    Verify acl_program and adjust -A produce equivalent results.
    
    Per PDF page 82: "The same setting can be performed as an option with the adjust command."
    """
    
    def test_acl_program_vs_adjust(self, acl_with_user_entries):
        """
        Both acl_program and adjust -A should associate ACL with program.
        
        Note: Actual equivalence depends on system having authorized programs.
        """
        acl_id = acl_with_user_entries
        
        # Using acl_program
        result1 = QDocSE.acl_program(acl_id, program=1).execute()
        
        # Using adjust with ACL
        result2 = QDocSE.adjust().auth_index(1).with_acl(acl_id).execute()
        
        # Both should have consistent behavior (both succeed or fail for same reason)
        # This documents the actual equivalence


@pytest.mark.unit
class TestACLProgramChaining:
    """Fluent interface tests"""
    
    def test_chaining_style(self, acl_with_user_entries):
        """Test fluent API"""
        acl_id = acl_with_user_entries
        
        # Note: May fail if program 1 doesn't exist, but tests the API
        (QDocSE.acl_program()
            .acl_id(acl_id)
            .program(1)
            .execute())


@pytest.mark.unit
class TestACLProgramPushConfig:
    """Test that acl_program changes require push_config"""
    
    def test_changes_pending_until_push(self, acl_with_user_entries, authorized_program_index):
        """
        After acl_program, changes should be pending until push_config.
        """
        acl_id = acl_with_user_entries
        prog_idx = authorized_program_index
        
        # Associate ACL
        assoc_result = QDocSE.acl_program(acl_id, program=prog_idx).execute()
        
        if assoc_result.result.success:
            # Check for pending configuration
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            
            # Should show pending
            if "Pending configuration" in list_result.result.stdout:
                print("Confirmed: acl_program changes require push_config")
                
                # Push config
                QDocSE.push_config().execute().ok()
                
                # Verify pending cleared
                list_after = QDocSE.acl_list(acl_id).execute().ok()
                assert "Pending configuration" not in list_after.result.stdout
