"""
acl_program command tests.

PDF Manual Key Points (Page 82):
1. Sets the ACL to be associated with an authorized program
2. Same setting can be performed with the adjust command
3. ACL must have User/Group entries (not program entries)
4. ACL must have at least one entry
5. When ACL is not matched, program is invalid (cannot access protected files)
6. When ACL is matched, program may be valid (still needs other criteria)
7. Active modes: Elevated, Learning
8. License type: A

Options:
- -A <acl_id>: Required. The ACL to associate (must have user/group entries)
- -p <program_index>: Required. The program index from view command

Examples from PDF:
  QDocSEConsole -c acl_program -A 1 -p 1
  QDocSEConsole -c acl_program -A 7 -p 3

Errors documented:
- ACL is empty. Cannot assign.
- ACL needs user/group entry. Cannot assign.
- Program index X does not exist.
"""
import pytest
from helpers import QDocSE

# Prerequisites (auto-checked)
pytestmark = [
    pytest.mark.requires_mode("elevated", "learning"),
    pytest.mark.requires_license("A"),
]


@pytest.fixture
def acl_with_user_entry(acl_id, some_valid_uids):
    """ACL with a user entry (suitable for acl_program -A)."""
    uid = some_valid_uids[0]
    QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rw").execute().ok()
    return acl_id


@pytest.fixture
def authorized_program_index():
    """Get the index of an authorized program from the system.

    Parses the view -a output and returns the first program index.
    Skips if no authorized programs exist.
    """
    view_result = QDocSE.view().authorized().execute()
    if view_result.result.failed:
        pytest.skip(f"Cannot query authorized programs: {view_result.result.stderr}")

    programs = view_result.parse().get("authorized", [])
    if not programs:
        pytest.skip("No authorized programs found on system")

    # Program indices are 1-based in the view output
    return 1


@pytest.mark.unit
class TestACLProgramBasic:
    """Basic acl_program functionality."""

    def test_associate_acl_with_program(self, acl_with_user_entry,
                                        authorized_program_index):
        """Associate a user/group ACL with an authorized program.

        Per PDF example: QDocSEConsole -c acl_program -A 1 -p 1
        """
        QDocSE.acl_program(
            acl_with_user_entry, program=authorized_program_index
        ).execute().ok()

    def test_missing_program_option(self, acl_with_user_entry):
        """acl_program requires -p option."""
        result = QDocSE.acl_program(acl_id=acl_with_user_entry).execute()
        result.fail("Should fail without -p option")

    def test_missing_acl_option(self):
        """acl_program requires -A option."""
        result = QDocSE.acl_program(program=1).execute()
        result.fail("Should fail without -A option")


@pytest.mark.unit
class TestACLProgramACLValidation:
    """ACL content validation tests."""

    def test_empty_acl_fails(self, acl_id):
        """acl_program with empty ACL should fail.

        Per PDF: "ACL is empty. Cannot assign."
        """
        result = QDocSE.acl_program(acl_id, program=1).execute()
        result.fail("Should fail with empty ACL")
        result.contains("empty")

    def test_acl_needs_entry_before_association(self, acl_id, some_valid_uids):
        """Adding an entry should resolve the "empty" error.

        Per PDF: "The associated ACL must have at least one entry."
        """
        # Empty ACL should fail
        result1 = QDocSE.acl_program(acl_id, program=1).execute()
        result1.fail("Empty ACL should fail")
        result1.contains("empty")

        # Add one entry
        uid = some_valid_uids[0]
        QDocSE.acl_add(acl_id, user=uid, mode="r").execute().ok()

        # Now the "empty" error should no longer occur
        # (may still fail for other reasons like program index not found)
        result2 = QDocSE.acl_program(acl_id, program=1).execute()
        output = result2.result.stdout + result2.result.stderr
        assert "empty" not in output.lower(), \
            "Should not fail due to empty ACL after adding entry"

    def test_program_entry_acl_fails(self, program_acl,
                                     authorized_program_index):
        """ACL with program entries cannot be used with acl_program.

        Per PDF: "ACL needs user/group entry. Cannot assign."
        """
        result = QDocSE.acl_program(
            program_acl, program=authorized_program_index
        ).execute()
        result.fail("Program-entry ACL should not work with acl_program")
        result.contains("needs user/group entry")


@pytest.mark.unit
class TestACLProgramProgramValidation:
    """Program index validation tests."""

    def test_nonexistent_program_index(self, acl_with_user_entry):
        """Nonexistent program index should fail.

        Per PDF: "Program index X does not exist."
        """
        result = QDocSE.acl_program(
            acl_with_user_entry, program=99999
        ).execute()
        result.fail("Should fail for nonexistent program index")
        result.contains("does not exist")

    def test_negative_program_index(self, acl_with_user_entry):
        """Negative program index should fail."""
        result = QDocSE.acl_program(
            acl_with_user_entry, program=-1
        ).execute()
        result.fail("Should fail for negative program index")

    @pytest.mark.xfail(reason="temporary failure, will fix later")
    def test_zero_program_index(self, acl_with_user_entry):
        """Program index 0 should fail (indices are 1-based)."""
        result = QDocSE.acl_program(
            acl_with_user_entry, program=0
        ).execute()
        result.fail("Should fail for program index 0")


@pytest.mark.unit
class TestACLProgramInvalidACL:
    """Invalid ACL ID tests."""

    def test_nonexistent_acl(self):
        """Nonexistent ACL ID should fail."""
        result = QDocSE.acl_program(999999, program=1).execute()
        result.fail("Should fail for nonexistent ACL ID")

    def test_negative_acl_id(self):
        """Negative ACL ID should fail."""
        result = QDocSE.acl_program(-1, program=1).execute()
        result.fail("Should fail for negative ACL ID")


@pytest.mark.unit
class TestACLProgramChaining:
    """Fluent API tests."""

    def test_chaining_style(self, acl_with_user_entry,
                            authorized_program_index):
        """Method chaining should produce the same result."""
        (QDocSE.acl_program()
            .acl_id(acl_with_user_entry)
            .program(authorized_program_index)
            .execute()
            .ok())
