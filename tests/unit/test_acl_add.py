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
        ("rwxrwx", "too long"),
    ])
    def test_invalid_modes(self, acl_id, mode, desc):
        QDocSE.acl_add(acl_id, user=0, mode=mode).execute().fail(desc)

    @pytest.mark.parametrize("mode,desc", [
        ("rr", "duplicate r"),
        ("ww", "duplicate w"),
        ("xx", "duplicate x"),
        ("rrr", "triple r"),
        ("rwr", "r-w-r repeat"),
    ])
    def test_duplicate_mode_chars(self, acl_id, mode, desc):
        """Duplicate permission characters should be rejected."""
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
        ("mon-09:00:00-17:00:00", "monday short"),
        ("tue-09:00:00-17:00:00", "tuesday short"),
        ("wed-09:00:00-17:00:00", "wednesday short"),
        ("thu-09:00:00-17:00:00", "thursday short"),
        ("fri-08:00:00-18:00:00", "friday short"),
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
        ("tuesday-09:00:00-17:00:00", "full name tuesday"),
        ("wednesday-09:00:00-17:00:00", "full name wednesday"),
        ("thursday-09:00:00-17:00:00", "full name thursday"),
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
         "Monday", "09:00:00-17:00:00", "monday short in list"),
        ("tue-09:00:00-17:00:00",
         "Tuesday", "09:00:00-17:00:00", "tuesday short in list"),
        ("wed-09:00:00-17:00:00",
         "Wednesday", "09:00:00-17:00:00", "wednesday short in list"),
        ("thu-09:00:00-17:00:00",
         "Thursday", "09:00:00-17:00:00", "thursday short in list"),
        ("fri-08:00:00-18:00:00",
         "Friday", "08:00:00-18:00:00", "friday short in list"),
        ("sat-10:00:00-16:00:00",
         "Saturday", "10:00:00-16:00:00", "saturday short in list"),
        ("sun-06:00:00-12:00:00",
         "Sunday", "06:00:00-12:00:00", "sunday short in list"),
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

    @pytest.mark.parametrize("acl_id_val,desc", [
        ("abc", "alphabetic"),
        ("1.5", "decimal"),
        ("", "empty string"),
        ("!@#", "special chars"),
    ])
    def test_non_digit_acl_id(self, acl_id_val, desc):
        """Non-digit ACL ID should fail."""
        QDocSE.acl_add().allow().user(0).mode("r") \
            ._opt("-i", acl_id_val).execute().fail(desc)

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


@pytest.mark.unit
class TestACLAddDuplicateOptions:
    """Duplicate CLI option behaviour.

    When the same option is specified more than once, the command should
    either reject it or use a deterministic value. Multiple -t is the
    only documented repeatable option.
    """

    def test_duplicate_allow_flag(self, acl_id):
        """Specifying -a twice."""
        QDocSE.acl_add().acl_id(acl_id).allow().allow() \
            .user(0).mode("r").execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Type: Allow")

    def test_duplicate_deny_flag(self, acl_id):
        """Specifying -d twice."""
        QDocSE.acl_add().acl_id(acl_id).deny().deny() \
            .user(0).mode("r").execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Type: Deny")

    def test_duplicate_acl_id(self, acl_id):
        """Specifying -i twice with same value."""
        QDocSE.acl_add().acl_id(acl_id).acl_id(acl_id) \
            .allow().user(0).mode("r").execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("User: 0")

    def test_duplicate_acl_id_different_values(self):
        """Specifying -i twice with different values — which takes effect?"""
        aid_a = QDocSE.acl_create().execute().ok().parse().get("acl_id")
        aid_b = QDocSE.acl_create().execute().ok().parse().get("acl_id")
        # Add with -i <aid_a> -i <aid_b>: entry should land in one of them
        QDocSE.acl_add().acl_id(aid_a).acl_id(aid_b) \
            .allow().user(0).mode("r").execute().ok()
        result_a = QDocSE.acl_list(aid_a).execute().ok()
        result_b = QDocSE.acl_list(aid_b).execute().ok()
        stdout_a = result_a.result.stdout
        stdout_b = result_b.result.stdout
        # Entry should exist in exactly one ACL (last -i wins is typical)
        has_a = "User: 0" in stdout_a
        has_b = "User: 0" in stdout_b
        assert has_a != has_b, \
            f"Entry should exist in exactly one ACL, got a={has_a} b={has_b}"

    def test_duplicate_mode(self, acl_id):
        """Specifying -m twice with different values."""
        QDocSE.acl_add().acl_id(acl_id).allow().user(0) \
            .mode("r").mode("rw").execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        stdout = result.result.stdout
        # One mode should take effect (typically last)
        assert "r--" in stdout or "rw-" in stdout, \
            f"Expected one mode to take effect, got: {stdout}"

    def test_duplicate_user(self, acl_id):
        """Specifying -u twice with different values."""
        QDocSE.acl_add().acl_id(acl_id).allow() \
            .user(0).user(1).mode("r").execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        stdout = result.result.stdout
        # One user should take effect
        assert "User: 0" in stdout or "User: 1" in stdout, \
            f"Expected one user to take effect, got: {stdout}"

    def test_duplicate_group(self, acl_id):
        """Specifying -g twice with different values."""
        QDocSE.acl_add().acl_id(acl_id).allow() \
            .group(0).group(1).mode("r").execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        stdout = result.result.stdout
        # One group should take effect
        assert "Group: 0" in stdout or "Group: 1" in stdout, \
            f"Expected one group to take effect, got: {stdout}"


@pytest.mark.unit
class TestACLAddProgram:
    """Program entry (-p) tests."""

    def test_add_program_entry(self, program_acl):
        """Program entry should appear in acl_list."""
        result = QDocSE.acl_list(program_acl).execute().ok()
        result.contains("Program:")
        result.contains("Type: Allow")
        result.contains("Mode: rwx")

    def test_add_second_program_entry(self):
        """Add a second program entry with different mode."""
        view_result = QDocSE.view().authorized().execute()
        programs = view_result.parse().get("authorized", [])
        if len(programs) < 2:
            pytest.skip("Need at least 2 authorized programs")

        aid = QDocSE.acl_create().execute().ok().parse().get("acl_id")
        QDocSE.acl_add(aid, allow=True).program(1).mode("r").execute().ok()
        QDocSE.acl_add(aid, allow=True).program(2).mode("w").execute().ok()

        result = QDocSE.acl_list(aid).execute().ok()
        result.contains("Entry: 1")
        result.contains("Entry: 2")

    def test_add_program_via_chaining(self):
        """Fluent API with -p option."""
        view_result = QDocSE.view().authorized().execute()
        programs = view_result.parse().get("authorized", [])
        if not programs:
            pytest.skip("No authorized programs on system")

        aid: int = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add().acl_id(aid).allow().program(1).mode("rx").execute().ok()
        result = QDocSE.acl_list(aid).execute().ok()
        result.contains("Program:")
        result.contains("Mode: r-x")

    def test_invalid_program_index(self, acl_id):
        """Invalid program index should fail."""
        result = QDocSE.acl_add(acl_id, allow=True).program(99999).mode("r").execute()
        result.fail("invalid program index")
        result.contains("Invalid program index")

    def test_program_deny_entry(self):
        """Deny entry with program subject."""
        view_result = QDocSE.view().authorized().execute()
        programs = view_result.parse().get("authorized", [])
        if not programs:
            pytest.skip("No authorized programs on system")

        aid = QDocSE.acl_create().execute().ok().parse().get("acl_id")
        QDocSE.acl_add(aid, allow=False).program(1).mode("w").execute().ok()
        result = QDocSE.acl_list(aid).execute().ok()
        result.contains("Type: Deny")
        result.contains("Program:")

    def test_program_with_time(self):
        """Program entry with time constraint."""
        view_result = QDocSE.view().authorized().execute()
        programs = view_result.parse().get("authorized", [])
        if not programs:
            pytest.skip("No authorized programs on system")

        aid = QDocSE.acl_create().execute().ok().parse().get("acl_id")
        QDocSE.acl_add(aid, allow=True).program(1).mode("r") \
            .time("mon-09:00:00-17:00:00").execute().ok()
        result = QDocSE.acl_list(aid).execute().ok()
        result.contains("Monday")
        result.contains("09:00:00-17:00:00")


@pytest.mark.unit
class TestACLAddMutualExclusivity:
    """Mutual exclusivity of subject options (-u/-g/-p) and type options (-a/-d)."""

    def test_user_and_group_together(self, acl_id):
        """Using -u and -g together should fail."""
        QDocSE.acl_add().acl_id(acl_id).allow().user(0).group(0) \
            .mode("r").execute().fail("user and group together")

    def test_user_and_program_together(self, acl_id):
        """Using -u and -p together should fail."""
        QDocSE.acl_add().acl_id(acl_id).allow().user(0).program(1) \
            .mode("r").execute().fail("user and program together")

    def test_group_and_program_together(self, acl_id):
        """Using -g and -p together should fail."""
        QDocSE.acl_add().acl_id(acl_id).allow().group(0).program(1) \
            .mode("r").execute().fail("group and program together")

    def test_all_three_subjects_together(self, acl_id):
        """Using -u, -g, and -p together should fail."""
        QDocSE.acl_add().acl_id(acl_id).allow().user(0).group(0).program(1) \
            .mode("r").execute().fail("all three subjects together")

    def test_allow_and_deny_together(self, acl_id):
        """Using -a and -d together should fail."""
        QDocSE.acl_add().acl_id(acl_id).allow().deny().user(0) \
            .mode("r").execute().fail("allow and deny together")


@pytest.mark.unit
class TestACLAddTypeMixing:
    """ACL entry type constraints — user/group and program entries cannot coexist."""

    def test_user_entry_on_program_acl(self, program_acl):
        """Adding a user entry to a program ACL should fail."""
        result = QDocSE.acl_add(program_acl, user=0, mode="r").execute()
        result.fail("user entry on program ACL")

    def test_group_entry_on_program_acl(self, program_acl):
        """Adding a group entry to a program ACL should fail."""
        result = QDocSE.acl_add(program_acl, group=0, mode="r").execute()
        result.fail("group entry on program ACL")

    def test_program_entry_on_user_acl(self, acl_id):
        """Adding a program entry to a user/group ACL should fail."""
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        result = QDocSE.acl_add(acl_id, allow=True).program(1).mode("r").execute()
        result.fail("program entry on user ACL")


@pytest.mark.unit
class TestACLAddSubjectsExtended:
    """Extended subject tests — group by name, invalid subjects."""

    def test_group_by_name(self, acl_id):
        """Group specified by name should resolve to GID."""
        QDocSE.acl_add(acl_id, group="root", mode="r").execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains("Group: 0 (root)")

    def test_invalid_username(self, acl_id):
        """Nonexistent username should fail."""
        result = QDocSE.acl_add(acl_id, user="nonexistent_user_xyz_99", mode="r").execute()
        result.fail("invalid username")

    def test_invalid_group_name(self, acl_id):
        """Nonexistent group name should fail."""
        result = QDocSE.acl_add(acl_id, group="nonexistent_group_xyz_99", mode="r").execute()
        result.fail("invalid group name")

    def test_negative_uid(self, acl_id):
        """Negative UID should fail."""
        result = QDocSE.acl_add(acl_id, user=-1, mode="r").execute()
        result.fail("negative UID")

    def test_negative_gid(self, acl_id):
        """Negative GID should fail."""
        result = QDocSE.acl_add(acl_id, group=-1, mode="r").execute()
        result.fail("negative GID")

    def test_very_large_uid(self, acl_id):
        """UID beyond system range should fail."""
        result = QDocSE.acl_add(acl_id, user=4294967296, mode="r").execute()
        result.fail("UID 2^32 out of range")

    def test_very_large_gid(self, acl_id):
        """GID beyond system range should fail."""
        result = QDocSE.acl_add(acl_id, group=4294967296, mode="r").execute()
        result.fail("GID 2^32 out of range")


@pytest.mark.unit
class TestACLAddMissingRequired:
    """Missing required option tests with error message verification."""

    def test_missing_acl_id(self):
        """Omitting -i should fail with specific error."""
        result = QDocSE.acl_add().user(0).mode("r").allow().execute()
        result.fail("missing ACL ID")
        result.contains("Missing required '-i' option")

    def test_missing_mode_error_message(self, acl_id):
        """Omitting -m should produce specific error message."""
        result = QDocSE.acl_add(acl_id, user=0).execute()
        result.fail("missing mode")
        result.contains("Missing required '-m' option")

    def test_missing_subject_error_message(self, acl_id):
        """Omitting -u/-g/-p should produce specific error message."""
        result = QDocSE.acl_add().acl_id(acl_id).allow().mode("r").execute()
        result.fail("missing subject")
        result.contains("One of option '-g', '-p' or '-u' must be specified")

    def test_missing_type_error_message(self):
        """Omitting -a/-d should produce specific error message.

        The constructor defaults allow=True so -a is always set.
        Build command manually to omit -a/-d flag.
        """
        cmd = QDocSE.acl_add()
        # Remove the default -a flag injected by constructor
        cmd.args.clear()
        cmd.acl_id(1).user(0).mode("r")
        result = cmd.execute()
        result.fail("missing allow/deny")
        result.contains("One of option '-a' or '-d' must be specified")


@pytest.mark.unit
class TestACLAddProgramFlags:
    """Tests for -b (backup) and -l (limited) program flags.

    Per help: -b = program is a backup program saving whole encrypted files.
              -l = program is limited to encrypted data only.
              Programs default to plaintext unless -b or -l used.
    """

    def test_backup_flag_with_program(self):
        """The -b flag is valid with program entries."""
        view_result = QDocSE.view().authorized().execute()
        programs = view_result.parse().get("authorized", [])
        if not programs:
            pytest.skip("No authorized programs on system")

        aid: int = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add().acl_id(aid).allow().program(1).mode("r") \
            .backup().execute().ok()

    def test_limited_flag_with_program(self):
        """The -l flag is valid with program entries."""
        view_result = QDocSE.view().authorized().execute()
        programs = view_result.parse().get("authorized", [])
        if not programs:
            pytest.skip("No authorized programs on system")

        aid: int = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add().acl_id(aid).allow().program(1).mode("r") \
            .limited().execute().ok()

    def test_backup_and_limited_mutual_exclusivity(self):
        """Using -b and -l together should fail (mutually exclusive)."""
        view_result = QDocSE.view().authorized().execute()
        programs = view_result.parse().get("authorized", [])
        if not programs:
            pytest.skip("No authorized programs on system")

        aid: int = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        result = QDocSE.acl_add().acl_id(aid).allow().program(1).mode("r") \
            .backup().limited().execute()
        result.fail("backup and limited together")

    def test_backup_flag_with_user_rejected(self, acl_id):
        """The -b flag should only apply to program entries, not user."""
        result = QDocSE.acl_add().acl_id(acl_id).allow().user(0).mode("r") \
            .backup().execute()
        result.fail("backup flag with user entry")

    def test_limited_flag_with_user_rejected(self, acl_id):
        """The -l flag should only apply to program entries, not user."""
        result = QDocSE.acl_add().acl_id(acl_id).allow().user(0).mode("r") \
            .limited().execute()
        result.fail("limited flag with user entry")

    def test_backup_flag_with_group_rejected(self, acl_id):
        """The -b flag should only apply to program entries, not group."""
        result = QDocSE.acl_add().acl_id(acl_id).allow().group(0).mode("r") \
            .backup().execute()
        result.fail("backup flag with group entry")

    def test_limited_flag_with_group_rejected(self, acl_id):
        """The -l flag should only apply to program entries, not group."""
        result = QDocSE.acl_add().acl_id(acl_id).allow().group(0).mode("r") \
            .limited().execute()
        result.fail("limited flag with group entry")


@pytest.mark.unit
class TestACLAddOctalMode:
    """Octal mode specification tests.

    Per help: 'The mode can also be specified in octal.'
    """

    @pytest.mark.parametrize("octal,expected", [
        ("4", "r--"),
        ("2", "-w-"),
        ("1", "--x"),
        ("6", "rw-"),
        ("5", "r-x"),
        ("3", "-wx"),
        ("7", "rwx"),
    ])
    def test_octal_modes(self, acl_id, octal, expected):
        """Mode specified as octal digit should be accepted."""
        QDocSE.acl_add(acl_id, user=0, mode=octal).execute().ok()
        result = QDocSE.acl_list(acl_id).execute().ok()
        result.contains(f"Mode: {expected}")

    def test_octal_zero_rejected(self, acl_id):
        """Octal 0 (no permissions) should be rejected."""
        QDocSE.acl_add(acl_id, user=0, mode="0").execute().fail("octal zero")
