"""
acl_add command tests.

Options: -i <acl_id>, -a (allow), -d (deny), -u <uid>, -g <gid>,
         -m <mode>, -t <time>, -p <index>, -b (backup), -l (limited)
"""
import pytest
from helpers import QDocSE

# Map short mode strings to the acl_list display format (e.g. "r" -> "r--")
MODE_DISPLAY = {
    "r": "r--", "w": "-w-", "x": "--x",
    "rw": "rw-", "rx": "r-x", "wx": "-wx",
    "rwx": "rwx",
}

# Prerequisites (auto-checked)
pytestmark = [
    pytest.mark.requires_mode("elevated", "learning"),
    pytest.mark.requires_license("A"),
]


@pytest.mark.unit
class TestACLAddBasic:
    """Basic add functionality."""

    def test_add_user_entry(self, acl_id):
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Type: Allow")
        result.contains("User: 0")
        result.contains("Mode: r--")

    def test_add_group_entry(self, acl_id):
        QDocSE.acl_add(acl_id, group=0, mode="r").execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Type: Allow")
        result.contains("Group: 0")
        result.contains("Mode: r--")

    def test_add_allow_entry(self, acl_id):
        QDocSE.acl_add(acl_id, allow=True, user=0, mode="r").execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Type: Allow")
        result.contains("User: 0")
        result.contains("Mode: r--")

    def test_add_deny_entry(self, acl_id):
        QDocSE.acl_add(acl_id, allow=False, user=0, mode="w").execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Type: Deny")
        result.contains("User: 0")
        result.contains("Mode: -w-")


@pytest.mark.unit
class TestACLAddModes:
    """Permission mode tests."""

    @pytest.mark.parametrize("mode", ["r", "w", "x", "rw", "rx", "wx", "rwx"])
    def test_valid_modes(self, acl_id, mode):
        QDocSE.acl_add(acl_id, user=0, mode=mode).execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains(f"Mode: {MODE_DISPLAY[mode]}")

    @pytest.mark.parametrize("mode,desc", [
        ("", "empty"),
        ("abc", "invalid chars"),
        ("rrr", "duplicates"),
        ("rwxrwx", "too long"),
    ])
    def test_invalid_modes(self, acl_id, mode, desc):
        QDocSE.acl_add(acl_id, user=0, mode=mode).execute().fail(desc)


@pytest.mark.unit
class TestACLAddSubjects:
    """User/group subject tests."""

    @pytest.mark.parametrize("uid", [0, 1, 65534])
    def test_common_uids(self, acl_id, uid):
        QDocSE.acl_add(acl_id, user=uid, mode="r").execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains(f"User: {uid}")

    @pytest.mark.parametrize("gid", [0, 1])
    def test_common_gids(self, acl_id, gid):
        QDocSE.acl_add(acl_id, group=gid, mode="r").execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains(f"Group: {gid}")

    def test_user_by_name(self, acl_id):
        QDocSE.acl_add(acl_id, user="root", mode="r").execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("User: 0 (root)")

    def test_no_subject_should_fail(self, acl_id):
        QDocSE.acl_add(acl_id, mode="r").execute().fail("Must specify user or group")


@pytest.mark.unit
class TestACLAddTime:
    """Time specification tests."""

    @pytest.mark.parametrize("spec,desc", [
        ("08:30:00-18:00:00", "daily range"),
        ("mon-09:00:00-17:00:00", "single day"),
        ("monwedfri-08:00:00-18:00:00", "multi day"),
        ("00:00:00-23:59:59", "all day"),
    ])
    def test_valid_time_specs(self, acl_id, spec, desc):
        QDocSE.acl_add(acl_id, user=0, mode="r").time(spec).execute().ok(desc)

    @pytest.mark.parametrize("spec,desc", [
        ("25:00:00-18:00:00", "invalid hour"),
        ("08:60:00-18:00:00", "invalid minute"),
        ("18:00:00-08:00:00", "end before start"),
        ("invalid", "bad format"),
    ])
    def test_invalid_time_specs(self, acl_id, spec, desc):
        QDocSE.acl_add(acl_id, user=0, mode="r").time(spec).execute().fail(desc)


@pytest.mark.unit
class TestACLAddMultiple:
    """Multiple entries tests."""

    def test_add_multiple_entries(self, acl_id):
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=1, mode="w").execute().ok()
        QDocSE.acl_add(acl_id, user=2, mode="x").execute().ok()

        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Entry: 1")
        result.contains("Entry: 2")
        result.contains("Entry: 3")
        result.contains("User: 0")
        result.contains("User: 1")
        result.contains("User: 2")
        result.contains("Mode: r--")
        result.contains("Mode: -w-")
        result.contains("Mode: --x")

    def test_entries_order(self, acl_id):
        QDocSE.acl_add(acl_id, user=100, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=200, mode="w").execute().ok()

        stdout = QDocSE.acl_list(acl_id).execute().ok().result.stdout
        assert stdout.find("User: 100") < stdout.find("User: 200"), \
            "Entries should be in add order"


@pytest.mark.unit
class TestACLAddErrors:
    """Error handling tests."""

    def test_nonexistent_acl(self):
        QDocSE.acl_add(999999, user=0, mode="r").execute().fail()

    def test_negative_acl_id(self):
        QDocSE.acl_add(-1, user=0, mode="r").execute().fail()

    def test_missing_mode(self, acl_id):
        QDocSE.acl_add(acl_id, user=0).execute().fail("Mode is required")


@pytest.mark.unit
class TestACLAddChaining:
    """Fluent API tests."""

    def test_chaining_style(self, acl_id):
        QDocSE.acl_add().acl_id(acl_id).user(0).mode("rw").execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Type: Allow")
        result.contains("User: 0")
        result.contains("Mode: rw-")

    def test_chaining_with_time(self, acl_id):
        QDocSE.acl_add().acl_id(acl_id).user(0).mode("r").time("09:00:00-17:00:00").execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("User: 0")
        result.contains("Mode: r--")
        result.contains("09:00:00-17:00:00")
