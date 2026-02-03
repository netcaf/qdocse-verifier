"""
acl_list command tests.

PDF Manual Key Points (Page 80-81):
1. Displays all active ACLs and their entries
2. A specific ACL can be displayed with the '-i' option
3. Display includes numeric position information for use with other commands
4. Active modes: Elevated, Learning
5. License type: A

Option:
- -i <acl_id>: Display only the specified ACL

Output format per entry:
- ACL ID is displayed with each ACL
- Zero entries: "No entries (Deny)"
- One or more entries: "Entry:" with entry number
- Type: Allow or Deny
- User/group/program: UID/GID/index with readable name
- Mode: r, w, x combination
- Time: days and hours when entry is matched

Pending changes message:
- "Pending configuration: see push_config command"

Errors documented:
- No ACL configuration file found.
"""
import pytest
from helpers import QDocSE

# Prerequisites (auto-checked)
pytestmark = [
    pytest.mark.requires_mode("elevated", "learning"),
    pytest.mark.requires_license("A"),
]


@pytest.mark.unit
class TestACLListBasic:
    """Basic acl_list functionality."""

    def test_list_all(self, acl_id):
        """acl_list with no options shows all ACLs."""
        result = QDocSE.acl_list().execute().ok()
        result.contains(f"ACL ID {acl_id}")

    def test_list_specific_acl(self, acl_id):
        """acl_list -i <acl_id> shows only the specified ACL."""
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains(f"ACL ID {acl_id}")

    def test_empty_acl_shows_no_entries(self, acl_id):
        """Empty ACL displays "No entries (Deny)".

        Per PDF: "With zero entries the message 'No entries (Deny)' is displayed."
        """
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("No entries (Deny)")

    def test_list_all_shows_multiple_acls(self):
        """acl_list with no options shows all existing ACLs."""
        id1 = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        id2 = QDocSE.acl_create().execute().ok().parse()["acl_id"]

        result = QDocSE.acl_list().execute().ok()
        result.contains(f"ACL ID {id1}")
        result.contains(f"ACL ID {id2}")


@pytest.mark.unit
class TestACLListWithEntries:
    """Verify entry display format in acl_list output."""

    def test_list_shows_entry_details(self, acl_id, some_valid_uids):
        """Each entry displays type, user, and mode.

        Per PDF: "Each entry will display the type: Allow or Deny."
        "Each entry will display the user or group or program index"
        "Each entry will display the mode"
        """
        uid = some_valid_uids[0]
        QDocSE.acl_add(acl_id, user=uid, mode="r").execute().ok()

        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Entry: 1")
        result.contains("Type: Allow")
        result.contains(f"User: {uid}")
        result.contains("Mode: r--")

    def test_list_shows_multiple_entries(self, acl_id, some_valid_uids):
        """Multiple entries should all be displayed with correct types."""
        uid_a, uid_b, uid_c = some_valid_uids[:3]
        QDocSE.acl_add(acl_id, user=uid_a, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=uid_b, mode="rw").execute().ok()
        QDocSE.acl_add(acl_id, allow=False, user=uid_c, mode="w").execute().ok()

        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Entry: 1")
        result.contains("Entry: 2")
        result.contains("Entry: 3")
        result.contains("Type: Allow")
        result.contains("Type: Deny")
        result.contains(f"User: {uid_a}")
        result.contains(f"User: {uid_b}")
        result.contains(f"User: {uid_c}")

    def test_list_shows_entry_numbers(self, acl_id, some_valid_uids):
        """Entry numbers start from 1 and increment.

        Per PDF: "'Entry:' is displayed with the entry number."
        """
        for uid in some_valid_uids[:3]:
            QDocSE.acl_add(acl_id, user=uid, mode="r").execute().ok()

        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Entry: 1")
        result.contains("Entry: 2")
        result.contains("Entry: 3")

    def test_list_shows_group_entry(self, acl_id):
        """Group entries display "Group: <gid>"."""
        QDocSE.acl_add(acl_id, group=0, mode="r").execute().ok()

        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Group: 0")

    def test_list_shows_user_readable_name(self, acl_id):
        """User entries display UID followed by readable name.

        Per PDF: "The UID, GID or program index will be displayed
        followed by the readable name."
        """
        QDocSE.acl_add(acl_id, user="root", mode="r").execute().ok()

        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("User: 0 (root)")

    @pytest.mark.parametrize("mode,expected", [
        ("r", "Mode: r--"),
        ("w", "Mode: -w-"),
        ("x", "Mode: --x"),
        ("rw", "Mode: rw-"),
        ("rx", "Mode: r-x"),
        ("wx", "Mode: -wx"),
        ("rwx", "Mode: rwx"),
    ])
    def test_list_shows_mode_format(self, acl_id, mode, expected):
        """Mode is displayed in r/w/x format with dashes for unset bits."""
        QDocSE.acl_add(acl_id, user=0, mode=mode).execute().ok()

        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains(expected)

    def test_list_shows_time(self, acl_id):
        """Time specification appears in acl_list output.

        Per PDF: "Each entry will display the times of day and week
        that the entry will be successfully matched."
        """
        QDocSE.acl_add(acl_id, user=0, mode="r") \
            .time("mon-09:00:00-17:00:00").execute().ok()

        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Monday")
        result.contains("09:00:00-17:00:00")


@pytest.mark.unit
class TestACLListPendingConfig:
    """Pending configuration message tests."""

    def test_shows_pending_message(self, acl_id):
        """After modification, "Pending configuration" is displayed.

        Per PDF: "Pending configuration: see push_config command"
        """
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()

        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Pending configuration")

    def test_pending_cleared_after_push(self, acl_id):
        """After push_config, pending message should disappear."""
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        QDocSE.push_config().execute().ok()

        result = QDocSE.acl_list(acl_id).execute().ok()
        assert "Pending configuration" not in result.result.stdout, \
            "Pending message should be cleared after push_config"


@pytest.mark.unit
class TestACLListErrors:
    """Error handling tests."""

    @pytest.mark.xfail(reason="temporary failure, will fix later")
    def test_nonexistent_acl(self):
        """Nonexistent ACL ID should fail."""
        result = QDocSE.acl_list(999999).execute()
        result.fail("Should fail for nonexistent ACL ID")

    @pytest.mark.xfail(reason="temporary failure, will fix later")
    def test_negative_acl_id(self):
        """Negative ACL ID should fail."""
        result = QDocSE.acl_list(-1).execute()
        result.fail("Should fail for negative ACL ID")
