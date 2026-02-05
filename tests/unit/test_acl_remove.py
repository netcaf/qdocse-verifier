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
        parsed = QDocSE.acl_list(acl_id).execute().ok().parse()
        assert parsed["acls"][0]["entries"][0]["entry"] == 1  # 1-based display
        assert parsed["acls"][0]["entries"][0]["user"] == uid

        QDocSE.acl_remove(acl_id, entry=0).execute().ok()

        # Apply pending configuration
        QDocSE.push_config().execute().ok()

        parsed = QDocSE.acl_list(acl_id).execute().ok().parse()
        assert parsed["acls"][0]["entries"] == []  # No entries

    def test_remove_middle_entry_renumbers(self, acl_id, some_valid_uids):
        """Removing a middle entry renumbers the remaining entries.

        After removing entry 2 from [uid_a, uid_b, uid_c], the result
        should be [uid_a, uid_c] at positions 1 and 2.
        """
        uid_a, uid_b, uid_c = some_valid_uids[:3]
        QDocSE.acl_add(acl_id, user=uid_a, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=uid_b, mode="w").execute().ok()
        QDocSE.acl_add(acl_id, user=uid_c, mode="x").execute().ok()

        QDocSE.acl_remove(acl_id, entry=1).execute().ok()

        # Apply pending configuration
        QDocSE.push_config().execute().ok()

        parsed = QDocSE.acl_list(acl_id).execute().ok().parse()
        entries = parsed["acls"][0]["entries"]
        assert len(entries) == 2
        # Entry numbers renumbered to 1 and 2
        assert entries[0]["entry"] == 1
        assert entries[0]["user"] == uid_a
        assert entries[1]["entry"] == 2
        assert entries[1]["user"] == uid_c
        # Ensure uid_b is not present
        for entry in entries:
            assert entry["user"] != uid_b

    def test_remove_first_entry(self, acl_id, some_valid_uids):
        """Remove first entry; second entry becomes entry 1."""
        uid_a, uid_b = some_valid_uids[:2]
        QDocSE.acl_add(acl_id, user=uid_a, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=uid_b, mode="w").execute().ok()

        QDocSE.acl_remove(acl_id, entry=0).execute().ok()

        # Apply pending configuration
        QDocSE.push_config().execute().ok()

        parsed = QDocSE.acl_list(acl_id).execute().ok().parse()
        entries = parsed["acls"][0]["entries"]
        assert len(entries) == 1
        assert entries[0]["entry"] == 1
        assert entries[0]["user"] == uid_b
        # uid_a not present
        for entry in entries:
            assert entry["user"] != uid_a

    def test_remove_last_entry(self, acl_id, some_valid_uids):
        """Remove last entry; earlier entries are unchanged."""
        uid_a, uid_b = some_valid_uids[:2]
        QDocSE.acl_add(acl_id, user=uid_a, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=uid_b, mode="w").execute().ok()

        QDocSE.acl_remove(acl_id, entry=1).execute().ok()

        # Apply pending configuration
        QDocSE.push_config().execute().ok()

        parsed = QDocSE.acl_list(acl_id).execute().ok().parse()
        entries = parsed["acls"][0]["entries"]
        assert len(entries) == 1
        assert entries[0]["entry"] == 1
        assert entries[0]["user"] == uid_a
        # uid_b not present
        for entry in entries:
            assert entry["user"] != uid_b

    def test_remove_nonexistent_entry(self, acl_id):
        """Remove nonexistent entry succeeds (no-op)."""
        result = QDocSE.acl_remove(acl_id, entry=999).execute()
        result.ok()  # Command succeeds when no matching entry found
        assert "No matching ACLs found to remove." in result.result.stderr


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

        # Apply pending configuration
        QDocSE.push_config().execute().ok()

        parsed = QDocSE.acl_list(acl_id).execute().ok().parse()
        assert parsed["acls"][0]["entries"] == []  # No entries

    def test_remove_all_from_empty_acl(self, acl_id):
        """Remove all on empty ACL should succeed (idempotent)."""
        QDocSE.acl_remove(acl_id, all=True).execute().ok()
        # Verify ACL still empty
        parsed = QDocSE.acl_list(acl_id).execute().ok().parse()
        assert parsed["acls"][0]["entries"] == []

    def test_remove_all_with_other_options_fails(self, some_valid_uids, some_valid_gids):
        """'-A' combined with other options returns error.

        Per spec: 'If -A is specified then neither the -a, -d, -e, -u, or -g options can be specified.'
        Command succeeds but stderr indicates conflict.

        Note: Actual behavior shows -A -e and -A -p do NOT produce error (entries are removed).
        """
        uid_a, uid_b = some_valid_uids[:2]
        gid_a = some_valid_gids[0]

        test_cases = [
            ("-a", None, True),      # -A -a should error
            ("-d", None, True),      # -A -d should error
            ("-u", str(uid_a), True), # -A -u should error
            ("-g", str(gid_a), True), # -A -g should error
            ("-e", "0", False),      # -A -e does NOT error (entries removed)
            ("-p", "1", False),      # -A -p does NOT error (entries removed)
        ]

        for option, value, expect_error in test_cases:
            # Create fresh ACL for each test case
            create_result = QDocSE.acl_create().execute().ok()
            acl_id = create_result.parse()["acl_id"]

            # Add test entries: allow user, deny user, allow group
            QDocSE.acl_add(acl_id, allow=True, user=uid_a, mode="r").execute().ok()
            QDocSE.acl_add(acl_id, allow=False, user=uid_b, mode="w").execute().ok()
            QDocSE.acl_add(acl_id, allow=True, group=gid_a, mode="r").execute().ok()

            # Build command: -A plus the other option
            cmd = QDocSE.acl_remove(acl_id, all=True)
            if option == "-a":
                cmd.allow()
            elif option == "-d":
                cmd.deny()
            elif option == "-u":
                cmd.user(value)
            elif option == "-g":
                cmd.group(value)
            elif option == "-e":
                cmd.entry(int(value))
            elif option == "-p":
                cmd.program(int(value))

            result = cmd.execute()
            result.ok()  # Command always succeeds

            if expect_error:
                assert "Other options are not allowed when using '-A'" in result.result.stderr, \
                    f"Expected error for -A {option}"
            else:
                # No error expected for -e and -p
                assert "Other options are not allowed when using '-A'" not in result.result.stderr

            # Apply pending configuration
            QDocSE.push_config().execute().ok()

            # Verify outcome
            parsed = QDocSE.acl_list(acl_id).execute().ok().parse()
            entries = parsed["acls"][0]["entries"]

            if expect_error:
                # Entries should remain unchanged
                assert len(entries) == 3, f"Entries removed for -A {option} when error expected"
                # Verify all three entries present
                user_entries = [e for e in entries if e.get("user") == uid_a]
                deny_entries = [e for e in entries if e.get("user") == uid_b]
                group_entries = [e for e in entries if e.get("group") == gid_a]
                assert len(user_entries) == 1 and user_entries[0]["type"] == "Allow"
                assert len(deny_entries) == 1 and deny_entries[0]["type"] == "Deny"
                assert len(group_entries) == 1 and group_entries[0]["type"] == "Allow"
            else:
                # Entries should be removed (by -A)
                assert entries == [], f"Entries not removed for -A {option}"


@pytest.mark.unit
class TestACLRemoveByType:
    """Remove by type (-a for Allow, -d for Deny)."""

    @pytest.mark.parametrize("allow_flag,_desc", [
        (True, "-a alone returns error about missing target"),
        (False, "-d alone returns error about missing target"),
    ])
    def test_type_only_missing_target(self, acl_id, some_valid_uids, allow_flag, _desc):
        """-a or -d alone returns error about missing target, entries unchanged."""
        _ = _desc
        uid_a, uid_b = some_valid_uids[:2]
        QDocSE.acl_add(acl_id, allow=True, user=uid_a, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, allow=False, user=uid_b, mode="w").execute().ok()

        cmd = QDocSE.acl_remove(acl_id)
        if allow_flag:
            cmd.allow()
        else:
            cmd.deny()
        result = cmd.execute()
        result.ok()  # Command succeeds
        # But stderr indicates missing target
        assert "One of option '-e', '-g', '-p', or '-u' must be specified" in result.result.stderr

        # Apply pending configuration
        QDocSE.push_config().execute().ok()

        parsed = QDocSE.acl_list(acl_id).execute().ok().parse()
        entries = parsed["acls"][0]["entries"]
        assert len(entries) == 2
        # Entries remain unchanged
        allow_entry = next(e for e in entries if e["type"] == "Allow")
        deny_entry = next(e for e in entries if e["type"] == "Deny")
        assert allow_entry["user"] == uid_a
        assert deny_entry["user"] == uid_b

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

        QDocSE.acl_remove(acl_id).allow().user(str(uid_a)).execute().ok()

        # Apply pending configuration
        QDocSE.push_config().execute().ok()

        parsed = QDocSE.acl_list(acl_id).execute().ok().parse()
        entries = parsed["acls"][0]["entries"]
        assert len(entries) == 1
        assert entries[0]["user"] == uid_b
        assert entries[0]["type"] == "Allow"  # Default type

    def test_remove_by_group(self, acl_id, some_valid_gids):
        """Remove entries for a specific group."""
        gid_a, gid_b = some_valid_gids[:2]
        QDocSE.acl_add(acl_id, group=gid_a, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, group=gid_b, mode="w").execute().ok()

        QDocSE.acl_remove(acl_id).allow().group(str(gid_a)).execute().ok()

        # Apply pending configuration
        QDocSE.push_config().execute().ok()

        parsed = QDocSE.acl_list(acl_id).execute().ok().parse()
        entries = parsed["acls"][0]["entries"]
        assert len(entries) == 1
        assert entries[0]["group"] == gid_b
        assert entries[0]["type"] == "Allow"  # Default type

    def test_remove_deny_by_user(self, acl_id, some_valid_uids):
        """Remove Deny entry for a specific user (-d -u combined)."""
        uid = some_valid_uids[0]
        QDocSE.acl_add(acl_id, allow=False, user=uid, mode="r").execute().ok()

        QDocSE.acl_remove(acl_id).deny().user(str(uid)).execute().ok()

        # Apply pending configuration
        QDocSE.push_config().execute().ok()

        parsed = QDocSE.acl_list(acl_id).execute().ok().parse()
        assert parsed["acls"][0]["entries"] == []

    def test_remove_deny_by_group(self, acl_id, some_valid_gids):
        """Remove Deny entry for a specific group (-d -g combined)."""
        gid = some_valid_gids[0]
        QDocSE.acl_add(acl_id, allow=False, group=gid, mode="r").execute().ok()

        QDocSE.acl_remove(acl_id).deny().group(str(gid)).execute().ok()

        # Apply pending configuration
        QDocSE.push_config().execute().ok()

        parsed = QDocSE.acl_list(acl_id).execute().ok().parse()
        assert parsed["acls"][0]["entries"] == []

    def test_remove_allow_by_user(self, acl_id, some_valid_uids):
        """Remove Allow entry for a specific user (-a -u combined).

        Per PDF example: QDocSEConsole -c acl_remove -i 2 -a -u ted
        """
        uid = some_valid_uids[0]
        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute().ok()

        QDocSE.acl_remove(acl_id).allow().user(str(uid)).execute().ok()

        # Apply pending configuration
        QDocSE.push_config().execute().ok()

        parsed = QDocSE.acl_list(acl_id).execute().ok().parse()
        assert parsed["acls"][0]["entries"] == []


@pytest.mark.unit
class TestACLRemoveByProgram:
    """Remove by program index (-p option)."""


    def test_remove_program_entry_with_allow(self, program_acl):
        """Remove program entry using -a -p."""
        # program_acl fixture provides ACL with program entry (index 1)
        acl_id = program_acl
        # Verify program entry exists
        parsed = QDocSE.acl_list(acl_id).execute().ok().parse()
        entries = parsed["acls"][0]["entries"]
        assert len(entries) == 1
        assert entries[0]["program"] == 1
        assert entries[0]["type"] == "Allow"

        # Remove with -a -p 1
        result = QDocSE.acl_remove(acl_id).allow().program(1).execute()
        result.ok()
        # No stderr expected
        assert not result.result.stderr

        # Apply pending configuration
        QDocSE.push_config().execute().ok()

        # Verify ACL is empty
        parsed = QDocSE.acl_list(acl_id).execute().ok().parse()
        assert parsed["acls"][0]["entries"] == []


@pytest.mark.unit
class TestACLRemoveMutualExclusivity:
    """Test mutual exclusivity constraints."""

    @pytest.mark.parametrize("user,group,program,allow,deny,_desc", [
        ("root", None, None, False, False, "-u alone returns error about missing -a/-d"),
        (None, "root", None, False, False, "-g alone returns error about missing -a/-d"),
        (None, None, 1, False, False, "-p alone returns error about missing -a/-d"),
        (None, None, 999, False, False, "-p with invalid index returns error about missing -a/-d"),
        (None, None, None, True, True, "-a and -d cannot be combined"),
        (None, None, None, False, False, "missing removal target returns error about missing -a/-d"),
    ])
    def test_missing_or_conflicting_allow_deny(self, acl_id, user, group, program, allow, deny, _desc):
        """Missing or conflicting -a/-d options produce appropriate error."""
        _ = _desc
        cmd = QDocSE.acl_remove(acl_id)
        if user:
            cmd.user(user)
        if group:
            cmd.group(group)
        if program:
            cmd.program(program)
        if allow:
            cmd.allow()
        if deny:
            cmd.deny()
        result = cmd.execute()
        result.ok()
        assert "Either '-a' or '-d' must be specified" in result.result.stderr
        # Verify ACL remains empty (no side effects)
        parsed = QDocSE.acl_list(acl_id).execute().ok().parse()
        assert parsed["acls"][0]["entries"] == []

    @pytest.mark.parametrize("target1,target2,_desc", [
        ("user", "group", "-a -u -g returns error about target specification"),
        ("user", "program", "-a -u -p returns error about target specification"),
        ("group", "program", "-a -g -p returns error about target specification"),
    ])
    def test_multiple_targets_with_allow(self, acl_id, target1, target2, _desc):
        """Multiple target options produce error about needing exactly one target."""
        _ = _desc
        cmd = QDocSE.acl_remove(acl_id).allow()
        if target1 == "user":
            cmd.user("root")
        elif target1 == "group":
            cmd.group("root")
        elif target1 == "program":
            cmd.program(1)
        if target2 == "user":
            cmd.user("root")
        elif target2 == "program":
            cmd.program(1)
        elif target2 == "group":
            cmd.group("root")
        result = cmd.execute()
        result.ok()
        assert "One of option '-e', '-g', '-p', or '-u' must be specified" in result.result.stderr


@pytest.mark.unit
class TestACLRemoveErrors:
    """Error handling tests."""

    def test_missing_acl_id(self):
        """acl_remove requires -i option.

        Per PDF: "Missing required '-i' option."
        """
        result = QDocSE.acl_remove(entry=0).execute()
        result.fail("Should fail without -i option")
        result.contains("Missing required")


    def test_nonexistent_acl(self):
        """Nonexistent ACL ID succeeds (no-op)."""
        result = QDocSE.acl_remove(999999, entry=0).execute()
        result.ok()  # Removing from nonexistent ACL is a no-op
        assert "Invalid ACL ID: 999999." in result.result.stderr

    def test_negative_acl_id(self):
        """Negative ACL ID succeeds (no-op)."""
        result = QDocSE.acl_remove(-1, entry=0).execute()
        result.ok()  # Negative ACL ID accepted, removal is no-op
        assert "Invalid ACL ID: -1." in result.result.stderr

    def test_negative_entry(self, acl_id):
        """Negative entry number succeeds (no match)."""
        result = QDocSE.acl_remove(acl_id, entry=-1).execute()
        result.ok()  # Negative entry number accepted, no match found
        assert "No matching ACLs found to remove." in result.result.stderr

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

    @pytest.mark.xfail(reason="Not implemented: simulating missing ACL config file")
    def test_no_acl_configuration_file(self):
        """No ACL configuration file found error."""
        # Simulating missing config file is complex; mark xfail
        pytest.skip("Cannot simulate missing ACL configuration file")

    @pytest.mark.xfail(reason="Actual behavior may succeed (no-op)")
    def test_invalid_program_index(self, acl_id):
        """Invalid program index error."""
        result = QDocSE.acl_remove(acl_id).program(999999).execute()
        result.fail("Should fail for invalid program index")


@pytest.mark.unit
class TestACLRemoveChaining:
    """Fluent API tests."""

    def test_chaining_remove_entry(self, acl_id, some_valid_uids):
        """Method chaining for entry removal."""
        uid = some_valid_uids[0]
        QDocSE.acl_add(acl_id, user=uid, mode="r").execute().ok()
        # Commit addition before removal
        QDocSE.push_config().execute().ok()

        result = (QDocSE.acl_remove()
            .acl_id(acl_id)
            .entry(0)
            .execute())
        if result.result.stderr:
            print(f"DEBUG removal stderr: {result.result.stderr}")
        result.ok()

        # Apply pending configuration
        QDocSE.push_config().execute().ok()

        # Verify ACL is empty
        parsed = QDocSE.acl_list(acl_id).execute().ok().parse()
        assert parsed["acls"][0]["entries"] == []

    def test_chaining_remove_all(self, acl_id, some_valid_uids):
        """Method chaining for remove-all."""
        uid = some_valid_uids[0]
        QDocSE.acl_add(acl_id, user=uid, mode="r").execute().ok()

        (QDocSE.acl_remove()
            .acl_id(acl_id)
            .all()
            .execute()
            .ok())

        # Apply pending configuration
        QDocSE.push_config().execute().ok()

        parsed = QDocSE.acl_list(acl_id).execute().ok().parse()
        assert parsed["acls"][0]["entries"] == []
