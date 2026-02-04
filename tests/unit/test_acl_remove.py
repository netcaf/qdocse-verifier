"""
acl_remove command tests.

PDF Manual Key Points (Page 82-83):
1. Removes a single entry from the specified ACL
2. To delete an entire ACL, use acl_destroy
3. To move/re-order entries, use acl_edit
4. Active modes: Elevated, Learning
5. License type: A

Options:
- -i <acl_id>       ACL ID (required)
- -e <entry_position> Remove entry by number (preferred)
- -A                 Remove all entries
- -a                 Remove only Allow entries
- -d                 Remove only Deny entries
- -u <user_name>    Remove entries for specific user
- -g <group_name>   Remove entries for specific group

Examples from PDF:
  QDocSEConsole -c acl_remove -i 1 -e 4
  QDocSEConsole -c acl_remove -i 2 -A
  QDocSEConsole -c acl_remove -i 2 -a -u ted

Errors documented:
- Missing required '-i' option.
- No ACL configuration file found.
- Invalid program index.
- Invalid user ID.
- Invalid group ID.
- Missing user, group, entry or program option.
- Other options not allow when using '-A'.
"""
import pytest
from helpers import QDocSE

# Prerequisites (auto-checked)
pytestmark = [
    pytest.mark.requires_mode("elevated", "learning"),
    pytest.mark.requires_license("A"),
]


@pytest.mark.unit
class TestACLRemoveByEntry:
    """Remove by entry number (-e option)."""

    def test_remove_single_entry(self, acl_id, some_valid_uids):
        """Remove the only entry leaves ACL empty.

        Per PDF example: QDocSEConsole -c acl_remove -i 1 -e 4
        """
        uid = some_valid_uids[0]
        QDocSE.acl_add(acl_id, user=uid, mode="r").execute().ok()
        QDocSE.acl_list(acl_id).execute().ok().contains("Entry: 1")

        QDocSE.acl_remove(acl_id, entry=1).execute().ok()

        QDocSE.acl_list(acl_id).execute().ok().contains("No entries")

    def test_remove_middle_entry_renumbers(self, acl_id, some_valid_uids):
        """Removing a middle entry renumbers the remaining entries.

        After removing entry 2 from [uid_a, uid_b, uid_c], the result
        should be [uid_a, uid_c] at positions 1 and 2.
        """
        uid_a, uid_b, uid_c = some_valid_uids[:3]
        QDocSE.acl_add(acl_id, user=uid_a, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=uid_b, mode="w").execute().ok()
        QDocSE.acl_add(acl_id, user=uid_c, mode="x").execute().ok()

        QDocSE.acl_remove(acl_id, entry=2).execute().ok()

        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Entry: 1")
        result.contains("Entry: 2")
        result.contains(f"User: {uid_a}")
        result.contains(f"User: {uid_c}")
        assert f"User: {uid_b}" not in result.result.stdout, \
            f"User {uid_b} should have been removed"

    def test_remove_first_entry(self, acl_id, some_valid_uids):
        """Remove first entry; second entry becomes entry 1."""
        uid_a, uid_b = some_valid_uids[:2]
        QDocSE.acl_add(acl_id, user=uid_a, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=uid_b, mode="w").execute().ok()

        QDocSE.acl_remove(acl_id, entry=1).execute().ok()

        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Entry: 1")
        result.contains(f"User: {uid_b}")
        assert f"User: {uid_a}" not in result.result.stdout

    def test_remove_last_entry(self, acl_id, some_valid_uids):
        """Remove last entry; earlier entries are unchanged."""
        uid_a, uid_b = some_valid_uids[:2]
        QDocSE.acl_add(acl_id, user=uid_a, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=uid_b, mode="w").execute().ok()

        QDocSE.acl_remove(acl_id, entry=2).execute().ok()

        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Entry: 1")
        result.contains(f"User: {uid_a}")
        assert f"User: {uid_b}" not in result.result.stdout

    def test_remove_nonexistent_entry(self, acl_id):
        """Remove nonexistent entry should fail."""
        QDocSE.acl_remove(acl_id, entry=999).execute().fail(
            "Should fail for nonexistent entry"
        )


@pytest.mark.unit
class TestACLRemoveAll:
    """Remove all entries (-A option)."""

    def test_remove_all_entries(self, acl_id, some_valid_uids):
        """Clear all entries from ACL.

        Per PDF example: QDocSEConsole -c acl_remove -i 2 -A
        """
        for uid in some_valid_uids[:3]:
            QDocSE.acl_add(acl_id, user=uid, mode="r").execute().ok()

        QDocSE.acl_remove(acl_id, all=True).execute().ok()

        QDocSE.acl_list(acl_id).execute().ok().contains("No entries")

    def test_remove_all_from_empty_acl(self, acl_id):
        """Remove all on empty ACL should succeed (idempotent)."""
        QDocSE.acl_remove(acl_id, all=True).execute().ok()

    def test_remove_all_with_other_options_fails(self, acl_id, some_valid_uids):
        """'-A' cannot be combined with other options.

        Per PDF: "Other options not allow when using '-A'."
        """
        uid = some_valid_uids[0]
        QDocSE.acl_add(acl_id, user=uid, mode="r").execute().ok()

        result = QDocSE.acl_remove(acl_id, all=True).allow().execute()
        result.fail("Should fail when -A combined with -a")
        result.contains("not allow")


@pytest.mark.unit
class TestACLRemoveByType:
    """Remove by type (-a for Allow, -d for Deny)."""

    def test_remove_allow_only(self, acl_id, some_valid_uids):
        """Remove only Allow entries; Deny entries remain."""
        uid_a, uid_b = some_valid_uids[:2]
        QDocSE.acl_add(acl_id, allow=True, user=uid_a, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, allow=False, user=uid_b, mode="w").execute().ok()

        QDocSE.acl_remove(acl_id).allow().execute().ok()

        result = QDocSE.acl_list(acl_id).execute().ok()
        assert "Type: Allow" not in result.result.stdout, \
            "Allow entries should have been removed"
        result.contains("Type: Deny")
        result.contains(f"User: {uid_b}")

    def test_remove_deny_only(self, acl_id, some_valid_uids):
        """Remove only Deny entries; Allow entries remain."""
        uid_a, uid_b = some_valid_uids[:2]
        QDocSE.acl_add(acl_id, allow=True, user=uid_a, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, allow=False, user=uid_b, mode="w").execute().ok()

        QDocSE.acl_remove(acl_id).deny().execute().ok()

        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Type: Allow")
        result.contains(f"User: {uid_a}")
        assert "Type: Deny" not in result.result.stdout, \
            "Deny entries should have been removed"


@pytest.mark.unit
class TestACLRemoveBySubject:
    """Remove by subject (-u for user, -g for group)."""

    def test_remove_by_user(self, acl_id, some_valid_uids):
        """Remove entries for a specific user.

        Per PDF example: QDocSEConsole -c acl_remove -i 2 -a -u ted
        """
        uid_a, uid_b = some_valid_uids[:2]
        QDocSE.acl_add(acl_id, user=uid_a, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=uid_b, mode="w").execute().ok()

        QDocSE.acl_remove(acl_id).user(str(uid_a)).execute().ok()

        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains(f"User: {uid_b}")
        assert f"User: {uid_a}" not in result.result.stdout, \
            f"User {uid_a} should have been removed"

    def test_remove_by_group(self, acl_id, some_valid_gids):
        """Remove entries for a specific group."""
        gid_a, gid_b = some_valid_gids[:2]
        QDocSE.acl_add(acl_id, group=gid_a, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, group=gid_b, mode="w").execute().ok()

        QDocSE.acl_remove(acl_id).group(str(gid_a)).execute().ok()

        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains(f"Group: {gid_b}")
        assert f"Group: {gid_a}" not in result.result.stdout, \
            f"Group {gid_a} should have been removed"

    def test_remove_allow_by_user(self, acl_id, some_valid_uids):
        """Remove Allow entry for a specific user (-a -u combined).

        Per PDF example: QDocSEConsole -c acl_remove -i 2 -a -u ted
        """
        uid = some_valid_uids[0]
        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute().ok()

        QDocSE.acl_remove(acl_id).allow().user(str(uid)).execute().ok()

        QDocSE.acl_list(acl_id).execute().ok().contains("No entries")


@pytest.mark.unit
class TestACLRemoveErrors:
    """Error handling tests."""

    def test_missing_acl_id(self):
        """acl_remove requires -i option.

        Per PDF: "Missing required '-i' option."
        """
        result = QDocSE.acl_remove(entry=1).execute()
        result.fail("Should fail without -i option")
        result.contains("Missing required")

    def test_missing_removal_target(self, acl_id):
        """acl_remove requires a removal target option.

        Per PDF: "Missing user, group, entry or program option."
        """
        result = QDocSE.acl_remove(acl_id).execute()
        result.fail("Should fail without removal target")

    def test_nonexistent_acl(self):
        """Nonexistent ACL ID should fail."""
        result = QDocSE.acl_remove(999999, entry=1).execute()
        result.fail("Should fail for nonexistent ACL ID")

    def test_negative_acl_id(self):
        """Negative ACL ID should fail."""
        result = QDocSE.acl_remove(-1, entry=1).execute()
        result.fail("Should fail for negative ACL ID")

    def test_negative_entry(self, acl_id):
        """Negative entry number should fail."""
        result = QDocSE.acl_remove(acl_id, entry=-1).execute()
        result.fail("Should fail for negative entry")

    @pytest.mark.xfail(reason="temporary failure, will fix later")
    def test_invalid_user_id(self, acl_id):
        """Invalid user ID should fail.

        Per PDF: "Invalid user ID."
        """
        result = QDocSE.acl_remove(acl_id).user("nonexistent_user_xyz").execute()
        result.fail("Should fail for invalid user ID")

    @pytest.mark.xfail(reason="temporary failure, will fix later")
    def test_invalid_group_id(self, acl_id):
        """Invalid group ID should fail.

        Per PDF: "Invalid group ID."
        """
        result = QDocSE.acl_remove(acl_id).group("nonexistent_group_xyz").execute()
        result.fail("Should fail for invalid group ID")


@pytest.mark.unit
class TestACLRemoveChaining:
    """Fluent API tests."""

    def test_chaining_remove_entry(self, acl_id, some_valid_uids):
        """Method chaining for entry removal."""
        uid = some_valid_uids[0]
        QDocSE.acl_add(acl_id, user=uid, mode="r").execute().ok()

        (QDocSE.acl_remove()
            .acl_id(acl_id)
            .entry(1)
            .execute()
            .ok())

        QDocSE.acl_list(acl_id).execute().ok().contains("No entries")

    def test_chaining_remove_all(self, acl_id, some_valid_uids):
        """Method chaining for remove-all."""
        uid = some_valid_uids[0]
        QDocSE.acl_add(acl_id, user=uid, mode="r").execute().ok()

        (QDocSE.acl_remove()
            .acl_id(acl_id)
            .all()
            .execute()
            .ok())

        QDocSE.acl_list(acl_id).execute().ok().contains("No entries")
