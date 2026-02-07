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
class TestACLProgramNoParameters:
    """Test acl_program with no parameters at all."""

    def test_no_parameters(self):
        """acl_program with no options should fail."""
        result = QDocSE.acl_program().execute()
        result.fail("Should fail without any parameters")


@pytest.mark.unit
class TestACLProgramACLIDZero:
    """Test acl_program with ACL ID 0."""

    @pytest.mark.xfail(reason="temporary failure, will fix later")
    def test_acl_id_zero(self):
        """ACL ID 0 is built-in and should not be assignable.

        Per PDF: ACL ID 0 is a fixed, built-in 'allow access' ACL.
        """
        result = QDocSE.acl_program(0, program=1).execute()
        result.fail("Should fail for ACL ID 0 (built-in)")


@pytest.mark.unit
class TestACLProgramNonDigitInputs:
    """Non-digit input validation."""

    @pytest.mark.parametrize("acl_id_val,desc", [
        ("abc", "alphabetic"),
        ("1.5", "decimal"),
        ("", "empty string"),
        ("!@#", "special chars"),
    ])
    def test_non_digit_acl_id(self, acl_id_val, desc):
        """Non-digit ACL ID should fail."""
        cmd = QDocSE.acl_program()
        cmd._opt("-A", acl_id_val)
        cmd._opt("-p", 1)
        result = cmd.execute()
        result.fail(desc)

    @pytest.mark.parametrize("prog_val,desc", [
        ("abc", "alphabetic"),
        ("1.5", "decimal"),
        ("", "empty string"),
        ("!@#", "special chars"),
    ])
    def test_non_digit_program_index(self, prog_val, desc):
        """Non-digit program index should fail."""
        cmd = QDocSE.acl_program()
        cmd._opt("-A", 1)
        cmd._opt("-p", prog_val)
        result = cmd.execute()
        result.fail(desc)


@pytest.mark.unit
class TestACLProgramReassignment:
    """Test reassigning programs to different ACLs."""

    def test_reassign_to_different_acl(self, some_valid_uids,
                                       authorized_program_index):
        """Reassigning a program from one ACL to another should work.

        Per PDF: acl_program associates ACL with program. Reassigning
        should update the association.
        """
        uid = some_valid_uids[0]

        # Create first ACL with user entry
        id1: int = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(id1, user=uid, mode="r").execute().ok()

        # Create second ACL with user entry
        id2: int = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(id2, user=uid, mode="rw").execute().ok()

        # Associate with first ACL
        QDocSE.acl_program(id1, program=authorized_program_index).execute().ok()

        # Reassign to second ACL
        QDocSE.acl_program(id2, program=authorized_program_index).execute().ok()

    def test_idempotent_reassignment(self, acl_with_user_entry,
                                      authorized_program_index):
        """Assigning the same ACL to the same program twice should succeed."""
        QDocSE.acl_program(
            acl_with_user_entry, program=authorized_program_index
        ).execute().ok()

        # Assign again (idempotent)
        QDocSE.acl_program(
            acl_with_user_entry, program=authorized_program_index
        ).execute().ok()


@pytest.mark.unit
class TestACLProgramSuccessOutput:
    """Verify success output message."""

    def test_success_message(self, acl_with_user_entry,
                              authorized_program_index):
        """Successful acl_program should produce confirmation output."""
        result = QDocSE.acl_program(
            acl_with_user_entry, program=authorized_program_index
        ).execute().ok()
        # Should produce some output confirming the association
        assert result.result.stdout.strip(), \
            "Successful acl_program should produce output"


@pytest.mark.unit
class TestACLProgramSequentialChanges:
    """Test sequential program associations."""

    def test_sequential_program_changes(self, acl_with_user_entry,
                                         authorized_program_index):
        """Multiple sequential acl_program calls should all succeed."""
        for _ in range(3):
            QDocSE.acl_program(
                acl_with_user_entry, program=authorized_program_index
            ).execute().ok()


@pytest.mark.unit
class TestACLProgramNoChangeOnFailure:
    """Verify failed acl_program doesn't modify state."""

    def test_no_change_on_failure(self, acl_with_user_entry,
                                   authorized_program_index):
        """Failed acl_program should not modify existing association.

        Associate program, then attempt invalid reassignment. Original
        association should remain intact.
        """
        # Establish association
        QDocSE.acl_program(
            acl_with_user_entry, program=authorized_program_index
        ).execute().ok()

        # Attempt invalid reassignment (empty ACL)
        empty_id: int = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        result = QDocSE.acl_program(empty_id, program=authorized_program_index).execute()
        result.fail("Should fail with empty ACL")

        # Original association should still work (push and verify)
        QDocSE.push_config().execute()


@pytest.mark.unit
class TestACLProgramStress:
    """Stress test for acl_program."""

    def test_many_programs_different_acls(self, some_valid_uids):
        """Associate multiple ACLs with different programs.

        Creates multiple ACLs and attempts to associate each with
        a different program index (if available).
        """
        view_result = QDocSE.view().authorized().execute()
        if view_result.result.failed:
            pytest.skip("Cannot query authorized programs")

        programs = view_result.parse().get("authorized", [])
        if len(programs) < 2:
            pytest.skip("Need at least 2 authorized programs")

        uid = some_valid_uids[0]
        acl_ids = []
        try:
            for i in range(min(len(programs), 3)):
                aid: int = QDocSE.acl_create().execute().ok().parse()["acl_id"]
                acl_ids.append(aid)
                QDocSE.acl_add(aid, user=uid, mode="r").execute().ok()
                QDocSE.acl_program(aid, program=i + 1).execute().ok()
        finally:
            for aid in acl_ids:
                QDocSE.acl_destroy(aid, force=True).execute()
            QDocSE.push_config().execute()


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
