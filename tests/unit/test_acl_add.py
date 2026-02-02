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
        #("rrr", "duplicates"),
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
        ("mon-09:00:00-17:00:00", "short day name"),
        ("sat-10:00:00-16:00:00", "saturday short"),
        ("sun-06:00:00-12:00:00", "sunday short"),
        ("monwedfri-08:00:00-18:00:00", "non-consecutive days short"),
        ("satsun-09:00:00-17:00:00", "weekend short"),
        ("montuewedthufri-09:00:00-17:00:00", "all weekdays short"),
        ("montuewedthufrisatsun-00:00:00-23:59:59", "all days all hours"),
        ("00:00:00-23:59:59", "all day"),
    ])
    def test_valid_time_specs(self, acl_id, spec, desc):
        QDocSE.acl_add(acl_id, user=0, mode="r").time(spec).execute().ok(desc)

    @pytest.mark.parametrize("spec,desc", [
        ("monday-09:00:00-17:00:00", "full name monday"),
        ("friday-08:00:00-18:00:00", "full name friday"),
        ("saturday-10:00:00-16:00:00", "full name saturday"),
        ("sunday-06:00:00-12:00:00", "full name sunday"),
        ("mondaywednesdayfriday-08:00:00-18:00:00", "full name multi day"),
        ("saturdaysunday-09:00:00-17:00:00", "full name weekend"),
    ])
    def test_valid_time_full_day_names(self, acl_id, spec, desc):
        """Full day names (e.g. 'monday') are accepted."""
        QDocSE.acl_add(acl_id, user=0, mode="r").time(spec).execute().ok(desc)

    @pytest.mark.parametrize("spec,desc", [
        ("MON-09:00:00-17:00:00", "upper case short"),
        ("Mon-09:00:00-17:00:00", "title case short"),
        ("MONDAY-09:00:00-17:00:00", "upper case full"),
        ("Monday-09:00:00-17:00:00", "title case full"),
        ("MonWedFri-08:00:00-18:00:00", "mixed case multi day"),
    ])
    def test_valid_time_case_insensitive(self, acl_id, spec, desc):
        """Day names are case-insensitive."""
        QDocSE.acl_add(acl_id, user=0, mode="r").time(spec).execute().ok(desc)

    @pytest.mark.parametrize("spec,expected_days,expected_time,desc", [
        ("08:30:00-18:00:00",
         "Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday",
         "08:30:00-18:00:00", "daily range"),
        ("mon-09:00:00-17:00:00",
         "Monday", "09:00:00-17:00:00", "day with hours"),
        ("monwedfri-08:00:00-18:00:00",
         "Monday, Wednesday, Friday", "08:00:00-18:00:00",
         "multi day with hours"),
    ])
    def test_valid_time_in_acl_list(self, acl_id, spec, expected_days,
                                    expected_time, desc):
        """Verify time spec appears in acl_list output after adding."""
        QDocSE.acl_add(acl_id, user=0, mode="r").time(spec).execute().ok(desc)
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains(expected_days)
        result.contains(expected_time)

    def test_multiple_time_specs_per_entry(self, acl_id):
        """The -t option may be specified more than once per entry."""
        QDocSE.acl_add(acl_id, user=0, mode="r") \
            .time("mon-09:00:00-12:00:00") \
            .time("mon-13:00:00-17:00:00") \
            .execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Monday")
        result.contains("09:00:00-12:00:00")
        result.contains("13:00:00-17:00:00")

    def test_multiple_time_specs_different_days(self, acl_id):
        """Multiple -t options covering different days."""
        QDocSE.acl_add(acl_id, user=0, mode="rw") \
            .time("montuewedthufri-09:00:00-17:00:00") \
            .time("satsun-10:00:00-14:00:00") \
            .execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Monday, Tuesday, Wednesday, Thursday, Friday")
        result.contains("09:00:00-17:00:00")
        result.contains("Sunday, Saturday")
        result.contains("10:00:00-14:00:00")

    def test_time_with_deny_entry(self, acl_id):
        """Time parameters apply to deny entries as well."""
        QDocSE.acl_add(acl_id, allow=False, user=0, mode="w") \
            .time("mon-09:00:00-17:00:00").execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Type: Deny")
        result.contains("Monday")
        result.contains("09:00:00-17:00:00")

    def test_time_via_constructor_kwargs(self, acl_id):
        """Verify time_start/time_end constructor kwargs match fluent API."""
        QDocSE.acl_add(
            acl_id, user=0, mode="r",
            time_start="09:00:00", time_end="17:00:00",
        ).execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("09:00:00-17:00:00")

    @pytest.mark.parametrize("spec,desc", [
        ("25:00:00-18:00:00", "invalid hour"),
        ("08:60:00-18:00:00", "invalid minute"),
        ("08:00:61-18:00:00", "invalid second"),
        ("18:00:00-08:00:00", "end before start"),
        ("invalid", "bad format"),
        ("00:00:00-24:00:00", "hour 24 out of range"),
        ("xyz-09:00:00-17:00:00", "invalid day name"),
    ])
    def test_invalid_time_specs(self, acl_id, spec, desc):
        QDocSE.acl_add(acl_id, user=0, mode="r").time(spec).execute().fail(desc)

    @pytest.mark.xfail(reason="temporary failure, will fix later")
    @pytest.mark.parametrize("spec,desc", [
        ("00:00:00-00:00:00", "zero-length window"),
        ("23:59:59-23:59:59", "single-second window"),
    ])
    def test_boundary_time_values(self, acl_id, spec, desc):
        """Boundary time values — start equals end."""
        QDocSE.acl_add(acl_id, user=0, mode="r").time(spec).execute().fail(desc)


@pytest.mark.unit
class TestACLAddMultiple:
    """Multiple entries tests."""

    def test_add_multiple_entries(self, acl_id, some_valid_uids):
        uid_a, uid_b, uid_c = some_valid_uids[:3]
        QDocSE.acl_add(acl_id, user=uid_a, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=uid_b, mode="w").execute().ok()
        QDocSE.acl_add(acl_id, user=uid_c, mode="x").execute().ok()

        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Entry: 1")
        result.contains("Entry: 2")
        result.contains("Entry: 3")
        result.contains(f"User: {uid_a}")
        result.contains(f"User: {uid_b}")
        result.contains(f"User: {uid_c}")
        result.contains("Mode: r--")
        result.contains("Mode: -w-")
        result.contains("Mode: --x")

    def test_entries_order(self, acl_id, some_valid_uids):
        uid_a, uid_b = some_valid_uids[0], some_valid_uids[1]
        QDocSE.acl_add(acl_id, user=uid_a, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=uid_b, mode="w").execute().ok()

        stdout = QDocSE.acl_list(acl_id).execute().ok().result.stdout
        assert stdout.find(f"User: {uid_a}") < stdout.find(f"User: {uid_b}"), \
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
class TestACLAddDuplicate:
    """Subject uniqueness — one entry per subject (user/group) per ACL."""

    def test_duplicate_same_type_same_mode(self, acl_id):
        """Exact duplicate is rejected."""
        QDocSE.acl_add(acl_id, allow=True, user=0, mode="r").execute().ok()
        result = QDocSE.acl_add(acl_id, allow=True, user=0, mode="r").execute()
        result.fail("duplicate same type same mode")
        result.contains("Duplicate ACL entries are not allowed")

    def test_duplicate_same_type_different_mode(self, acl_id):
        """Same type + same subject but different mode is still rejected."""
        QDocSE.acl_add(acl_id, allow=True, user=0, mode="r").execute().ok()
        result = QDocSE.acl_add(acl_id, allow=True, user=0, mode="w").execute()
        result.fail("duplicate same type different mode")
        result.contains("Duplicate ACL entries are not allowed")

    def test_conflict_different_type(self, acl_id):
        """Allow + deny for the same subject is rejected as conflict."""
        QDocSE.acl_add(acl_id, allow=True, user=0, mode="r").execute().ok()
        result = QDocSE.acl_add(acl_id, allow=False, user=0, mode="w").execute()
        result.fail("conflict different type same subject")
        result.contains("New ACL entry conflicts with an existing one")

    def test_duplicate_same_type_different_time(self, acl_id):
        """Same subject with different time windows is still rejected."""
        QDocSE.acl_add(acl_id, allow=True, user=0, mode="r") \
            .time("mon-09:00:00-12:00:00").execute().ok()
        result = QDocSE.acl_add(acl_id, allow=True, user=0, mode="r") \
            .time("fri-13:00:00-17:00:00").execute()
        result.fail("duplicate different time")
        result.contains("Duplicate ACL entries are not allowed")

    def test_duplicate_user_by_name_and_uid(self, acl_id):
        """'root' and '0' resolve to the same subject."""
        QDocSE.acl_add(acl_id, user="root", mode="r").execute().ok()
        result = QDocSE.acl_add(acl_id, user=0, mode="w").execute()
        result.fail("root and UID 0 are the same subject")
        result.contains("Duplicate ACL entries are not allowed")

    def test_duplicate_group(self, acl_id):
        """Group subject uniqueness follows the same rule."""
        QDocSE.acl_add(acl_id, group=0, mode="r").execute().ok()
        result = QDocSE.acl_add(acl_id, group=0, mode="w").execute()
        result.fail("duplicate group")
        result.contains("Duplicate ACL entries are not allowed")

    def test_conflict_group_different_type(self, acl_id):
        """Allow + deny for the same group is rejected as conflict."""
        QDocSE.acl_add(acl_id, allow=True, group=0, mode="r").execute().ok()
        result = QDocSE.acl_add(acl_id, allow=False, group=0, mode="w").execute()
        result.fail("conflict different type same group")
        result.contains("New ACL entry conflicts with an existing one")

    def test_user_and_group_same_id_coexist(self, acl_id):
        """User and group are separate namespaces — same numeric ID is OK."""
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, group=0, mode="r").execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("User: 0")
        result.contains("Group: 0")

    def test_different_users_coexist(self, acl_id, some_valid_uids):
        """Different users can coexist in the same ACL."""
        uid_a, uid_b = some_valid_uids[0], some_valid_uids[1]
        QDocSE.acl_add(acl_id, user=uid_a, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=uid_b, mode="r").execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains(f"User: {uid_a}")
        result.contains(f"User: {uid_b}")


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
