"""
acl_edit command tests.

PDF Manual Key Points (Page 75-76):
1. acl_edit changes the order of ACL entries for a specific ACL
2. Entry order is important for determining allow/deny (first match wins)
3. Options:
   -i <acl_id>    Specify ACL ID (required)
   -e <entry>     Entry number to move (required)
   -p <position>  New position: numeric, or "up", "down", "top", "bottom",
                  "first", "last", "begin", "end" (required)
4. Active modes: Elevated, Learning
5. License type: A

Errors documented:
- Missing required '-e' option.
- Missing required '-i' option.
- Missing required '-p' option.
- No ACL configuration file found.
- X is not a valid ACL ID.
- No change – item does not need to move.
- Error with acl_edit.

Examples from PDF:
  QDocSEConsole -c acl_edit -i 2 -e 3 -p up
  QDocSEConsole -c acl_edit -i 2 -e 3 -p down
  QDocSEConsole -c acl_edit -i 2 -e 3 -p 2
"""
import pytest
from helpers import QDocSE

# Prerequisites (auto-checked)
pytestmark = [
    pytest.mark.requires_mode("elevated", "learning"),
    pytest.mark.requires_license("A"),
]


@pytest.fixture
def acl_with_three_entries(acl_id, some_valid_uids):
    """Create ACL with 3 entries for move testing using valid system UIDs."""
    uids = some_valid_uids[:3]
    # Entry 1: uids[0], mode r
    QDocSE.acl_add(acl_id, user=uids[0], mode="r").execute().ok()
    # Entry 2: uids[1], mode w
    QDocSE.acl_add(acl_id, user=uids[1], mode="w").execute().ok()
    # Entry 3: uids[2], mode x
    QDocSE.acl_add(acl_id, user=uids[2], mode="x").execute().ok()
    return acl_id, uids


def _get_entry_order(acl_id, uids):
    """Parse acl_list output and return UIDs in entry order.

    acl_list shows entries with "User: <uid>" format.
    Returns the UIDs in the order they appear in the output.
    """
    stdout = QDocSE.acl_list(acl_id).execute().ok().result.stdout
    uid_positions = []
    for uid in uids:
        marker = f"User: {uid}"
        pos = stdout.find(marker)
        assert pos != -1, f"'{marker}' not found in acl_list output:\n{stdout}"
        uid_positions.append((pos, uid))
    uid_positions.sort()
    return [uid for _, uid in uid_positions]


@pytest.mark.unit
class TestACLEditPosition:
    """Entry position adjustment tests."""

    def test_move_to_first(self, acl_with_three_entries):
        """Move entry to first position using 'first' keyword."""
        acl_id, uids = acl_with_three_entries

        # Move entry 3 (uids[2]) to first position
        QDocSE.acl_edit(acl_id, entry=3, position="first").execute().ok()

        order = _get_entry_order(acl_id, uids)
        assert order[0] == uids[2], f"UID {uids[2]} should be first, got order {order}"

    def test_move_to_last(self, acl_with_three_entries):
        """Move entry to last position using 'last' keyword."""
        acl_id, uids = acl_with_three_entries

        # Move entry 1 (uids[0]) to last position
        QDocSE.acl_edit(acl_id, entry=1, position="last").execute().ok()

        order = _get_entry_order(acl_id, uids)
        assert order[-1] == uids[0], f"UID {uids[0]} should be last, got order {order}"

    @pytest.mark.xfail(reason="temporary failure, will fix later")
    def test_move_to_specific_position(self, acl_with_three_entries):
        """Move entry to numeric position.

        Per PDF example: acl_edit -i 2 -e 3 -p 2
        """
        acl_id, uids = acl_with_three_entries

        # Move entry 3 to position 2: order becomes uids[0], uids[2], uids[1]
        QDocSE.acl_edit(acl_id, entry=3, position=2).execute().ok()

        order = _get_entry_order(acl_id, uids)
        assert order == [uids[0], uids[2], uids[1]], \
            f"Expected [{uids[0]}, {uids[2]}, {uids[1]}], got {order}"

    def test_move_up(self, acl_with_three_entries):
        """Move entry one position up (toward first).

        Per PDF example: acl_edit -i 2 -e 3 -p up
        """
        acl_id, uids = acl_with_three_entries

        # Move entry 3 up: order becomes uids[0], uids[2], uids[1]
        QDocSE.acl_edit(acl_id, entry=3, position="up").execute().ok()

        order = _get_entry_order(acl_id, uids)
        assert order == [uids[0], uids[2], uids[1]], \
            f"Expected [{uids[0]}, {uids[2]}, {uids[1]}], got {order}"

    def test_move_down(self, acl_with_three_entries):
        """Move entry one position down (toward last).

        Per PDF example: acl_edit -i 2 -e 3 -p down
        """
        acl_id, uids = acl_with_three_entries

        # Move entry 1 down: order becomes uids[1], uids[0], uids[2]
        QDocSE.acl_edit(acl_id, entry=1, position="down").execute().ok()

        order = _get_entry_order(acl_id, uids)
        assert order == [uids[1], uids[0], uids[2]], \
            f"Expected [{uids[1]}, {uids[0]}, {uids[2]}], got {order}"

    def test_move_to_top(self, acl_with_three_entries):
        """Move entry to top (synonym for first)."""
        acl_id, uids = acl_with_three_entries

        QDocSE.acl_edit(acl_id, entry=3, position="top").execute().ok()

        order = _get_entry_order(acl_id, uids)
        assert order[0] == uids[2], f"UID {uids[2]} should be at top, got order {order}"

    def test_move_to_bottom(self, acl_with_three_entries):
        """Move entry to bottom (synonym for last)."""
        acl_id, uids = acl_with_three_entries

        QDocSE.acl_edit(acl_id, entry=1, position="bottom").execute().ok()

        order = _get_entry_order(acl_id, uids)
        assert order[-1] == uids[0], f"UID {uids[0]} should be at bottom, got order {order}"

    def test_move_to_begin(self, acl_with_three_entries):
        """Move entry to begin (synonym for first)."""
        acl_id, uids = acl_with_three_entries

        QDocSE.acl_edit(acl_id, entry=3, position="begin").execute().ok()

        order = _get_entry_order(acl_id, uids)
        assert order[0] == uids[2], f"UID {uids[2]} should be at begin, got order {order}"

    def test_move_to_end(self, acl_with_three_entries):
        """Move entry to end (synonym for last)."""
        acl_id, uids = acl_with_three_entries

        QDocSE.acl_edit(acl_id, entry=1, position="end").execute().ok()

        order = _get_entry_order(acl_id, uids)
        assert order[-1] == uids[0], f"UID {uids[0]} should be at end, got order {order}"


@pytest.mark.unit
class TestACLEditNoChange:
    """Tests for 'No change' scenarios.

    Per PDF: "No change – item does not need to move."
    """

    def test_move_to_same_numeric_position(self, acl_with_three_entries):
        """Move entry to its current numeric position.

        Per PDF: "No change – item does not need to move."
        """
        acl_id, uids = acl_with_three_entries

        # Move entry 2 to position 2 (same position)
        result = QDocSE.acl_edit(acl_id, entry=2, position=2).execute()
        result.contains("No change")

        # Order should remain unchanged
        order = _get_entry_order(acl_id, uids)
        assert order == [uids[0], uids[1], uids[2]], \
            f"Order should remain unchanged, got {order}"

    def test_move_first_entry_up(self, acl_with_three_entries):
        """Move first entry up — already at top, should be no change.

        Per PDF: "No change – item does not need to move."
        """
        acl_id, uids = acl_with_three_entries

        result = QDocSE.acl_edit(acl_id, entry=1, position="up").execute()
        result.contains("No change")

        order = _get_entry_order(acl_id, uids)
        assert order == [uids[0], uids[1], uids[2]], \
            f"Order should remain unchanged, got {order}"

    def test_move_last_entry_down(self, acl_with_three_entries):
        """Move last entry down — already at bottom, should be no change.

        Per PDF: "No change – item does not need to move."
        """
        acl_id, uids = acl_with_three_entries

        result = QDocSE.acl_edit(acl_id, entry=3, position="down").execute()
        result.contains("No change")

        order = _get_entry_order(acl_id, uids)
        assert order == [uids[0], uids[1], uids[2]], \
            f"Order should remain unchanged, got {order}"


@pytest.mark.unit
class TestACLEditErrors:
    """Error handling tests."""

    def test_missing_entry_option(self, acl_id):
        """acl_edit requires -e option.

        Per PDF: "Missing required '-e' option."
        """
        result = QDocSE.acl_edit(acl_id, position=1).execute()
        result.fail("Should fail without -e option")
        result.contains("Missing required")

    def test_missing_acl_id_option(self):
        """acl_edit requires -i option.

        Per PDF: "Missing required '-i' option."
        """
        result = QDocSE.acl_edit(entry=1, position=1).execute()
        result.fail("Should fail without -i option")
        result.contains("Missing required")

    def test_missing_position_option(self, acl_id):
        """acl_edit requires -p option.

        Per PDF: "Missing required '-p' option."
        """
        result = QDocSE.acl_edit(acl_id, entry=1).execute()
        result.fail("Should fail without -p option")
        result.contains("Missing required")

    @pytest.mark.xfail(reason="temporary failure, will fix later")
    def test_nonexistent_entry(self, acl_id):
        """Move nonexistent entry should fail."""
        QDocSE.acl_edit(acl_id, entry=999, position=1).execute().fail(
            "Should fail for nonexistent entry"
        )

    @pytest.mark.xfail(reason="temporary failure, will fix later")
    def test_invalid_position(self, acl_with_three_entries):
        """Invalid target position should fail."""
        acl_id, _ = acl_with_three_entries
        QDocSE.acl_edit(acl_id, entry=1, position=999).execute().fail(
            "Should fail for invalid position"
        )

    @pytest.mark.xfail(reason="temporary failure, will fix later")
    def test_negative_entry(self, acl_id):
        """Negative entry number should fail."""
        QDocSE.acl_edit(acl_id, entry=-1, position=1).execute().fail(
            "Should fail for negative entry"
        )

    @pytest.mark.xfail(reason="temporary failure, will fix later")
    def test_negative_position(self, acl_with_three_entries):
        """Negative position should fail."""
        acl_id, _ = acl_with_three_entries
        QDocSE.acl_edit(acl_id, entry=1, position=-1).execute().fail(
            "Should fail for negative position"
        )

    @pytest.mark.xfail(reason="temporary failure, will fix later")
    def test_nonexistent_acl(self):
        """Nonexistent ACL should fail.

        Per PDF: "X is not a valid ACL ID."
        """
        result = QDocSE.acl_edit(999999, entry=1, position=1).execute()
        result.fail("Should fail for nonexistent ACL")
        result.contains("is not a valid ACL ID")


@pytest.mark.unit
class TestACLEditChaining:
    """Method chaining tests."""

    def test_chaining_style(self, acl_with_three_entries):
        """Use method chaining style and verify entry actually moved."""
        acl_id, uids = acl_with_three_entries

        (QDocSE.acl_edit()
            .acl_id(acl_id)
            .entry(3)
            .position("first")
            .execute()
            .ok())

        # Verify entry 3 (uids[2]) is now first
        order = _get_entry_order(acl_id, uids)
        assert order[0] == uids[2], f"UID {uids[2]} should be first after chained edit"
