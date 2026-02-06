"""Adjust command tests."""
import pytest
import os
from helpers import QDocSE

# Prerequisites (auto-checked)
pytestmark = [
    pytest.mark.requires_mode("elevated", "learning"),
    pytest.mark.requires_license("A"),
]


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def temp_executable(tmp_path):
    """Create a temporary executable file (ELF dummy) that QDocSE recognizes.

    Uses /bin/true as a template - copy it to a temporary location.
    """
    import shutil
    src = "/bin/true"
    if not os.path.exists(src):
        # Fallback to /usr/bin/true
        src = "/usr/bin/true"
    dst = tmp_path / "test_executable"
    shutil.copy(src, dst)
    os.chmod(dst, 0o755)
    return str(dst)


@pytest.fixture
def authorized_index():
    """Return index of an already authorized program (first in list)."""
    result = QDocSE.view().authorized().execute()
    programs = result.parse().get("authorized", [])
    if not programs:
        pytest.skip("No authorized programs on system")
    return programs[0]["index"]


@pytest.fixture
def blocked_index():
    """Return index of an already blocked program (first in list)."""
    result = QDocSE.view().blocked().execute()
    programs = result.parse().get("blocked", [])
    if not programs:
        pytest.skip("No blocked programs on system")
    return programs[0]["index"]


@pytest.fixture
def acl_with_entry(acl_id, some_valid_uids):
    """ACL with one user entry (required for -A option)."""
    QDocSE.acl_add(acl_id, user=some_valid_uids[0], mode="r").execute().ok()
    return acl_id


# =============================================================================
# Basic Success Tests
# =============================================================================

@pytest.mark.unit
class TestAdjustBasic:
    """Basic authorize/block operations."""

    def test_authorize_by_path(self, temp_executable, request):
        """Authorize by path (-apf)."""
        # Ensure cleanup runs even if assertions fail
        request.addfinalizer(
            lambda: QDocSE.adjust().block_path(temp_executable).execute()
        )
        # Act
        result = QDocSE.adjust().auth_path(temp_executable).execute()
        # Assert
        result.ok()
        # Verify appears in authorized list
        view = QDocSE.view().authorized().execute().ok().parse()
        paths = [p["path"] for p in view.get("authorized", [])]
        assert temp_executable in paths

    def test_block_by_path(self, temp_executable, request):
        """Block by path (-bpf)."""
        # First authorize it
        QDocSE.adjust().auth_path(temp_executable).execute().ok()
        # Ensure cleanup runs even if assertions fail
        request.addfinalizer(
            lambda: QDocSE.adjust().auth_path(temp_executable).execute()
        )
        # Then block it
        result = QDocSE.adjust().block_path(temp_executable).execute()
        result.ok()
        # Verify appears in blocked list
        view = QDocSE.view().blocked().execute().ok().parse()
        paths = [p["path"] for p in view.get("blocked", [])]
        assert temp_executable in paths

    def test_authorize_by_index(self, blocked_index, request):
        """Authorize by index (-api) moves program from blocked to authorized."""
        # Get program details before
        view_before = QDocSE.view().execute().ok().parse()
        blocked_before = [p for p in view_before["blocked"] if p["index"] == blocked_index]
        assert len(blocked_before) == 1
        target_path = blocked_before[0]["path"]

        # Ensure cleanup: re-block the program by path (works regardless of index change)
        request.addfinalizer(
            lambda: QDocSE.adjust().block_path(target_path).execute()
        )

        # Act
        result = QDocSE.adjust().auth_index(blocked_index).execute()
        result.ok()

        # Verify moved
        view_after = QDocSE.view().execute().ok().parse()
        # Should not be in blocked
        blocked_after = [p for p in view_after["blocked"] if p["index"] == blocked_index]
        assert len(blocked_after) == 0
        # Should be in authorized (index may change)
        auth_after = [p for p in view_after["authorized"] if p["path"] == target_path]
        assert len(auth_after) == 1

    def test_block_by_index(self, authorized_index, request):
        """Block by index (-b) moves program from authorized to blocked."""
        # Get program details before
        view_before = QDocSE.view().execute().ok().parse()
        auth_before = [p for p in view_before["authorized"] if p["index"] == authorized_index]
        assert len(auth_before) == 1
        target_path = auth_before[0]["path"]

        # Ensure cleanup: re-authorize the program by path (works regardless of index change)
        request.addfinalizer(
            lambda: QDocSE.adjust().auth_path(target_path).execute()
        )

        # Act
        result = QDocSE.adjust().block_index(authorized_index).execute()
        result.ok()

        # Verify moved
        view_after = QDocSE.view().execute().ok().parse()
        # Should not be in authorized
        auth_after = [p for p in view_after["authorized"] if p["index"] == authorized_index]
        assert len(auth_after) == 0
        # Should be in blocked (index may change)
        blocked_after = [p for p in view_after["blocked"] if p["path"] == target_path]
        assert len(blocked_after) == 1

    def test_authorize_without_acl_uses_default(self, temp_executable, request):
        """Authorize without -A uses built-in ACL ID 0 (allow access).

        Docs: "When the ACL ID is not specified, this is the equivalent of
        fixed, built-in ACL ID 0 (zero) which has an 'allow access' setting."
        """
        request.addfinalizer(
            lambda: QDocSE.adjust().block_path(temp_executable).execute()
        )
        # Act
        result = QDocSE.adjust().auth_path(temp_executable).execute()
        result.ok()

        # Assert: ACL field should be None (no explicit ACL) or 0
        view = QDocSE.view().authorized().execute().ok().parse()
        target = [p for p in view.get("authorized", []) if p["path"] == temp_executable]
        assert len(target) == 1, f"Expected {temp_executable} in authorized list"
        assert target[0]["acl"] is None or target[0]["acl"] == 0, (
            f"Without -A, ACL should be None/0 (default), got {target[0]['acl']}"
        )


# =============================================================================
# With-ACL Tests
# =============================================================================

@pytest.mark.unit
class TestAdjustWithACL:
    """Authorize/block with ACL association (-A option)."""

    def test_authorize_with_acl(self, blocked_index, acl_with_entry, request):
        """Authorize with ACL association (-api -A)."""
        # Arrange: capture program path before move
        view_before = QDocSE.view().blocked().execute().ok().parse()
        target_before = [p for p in view_before["blocked"] if p["index"] == blocked_index]
        assert len(target_before) == 1
        target_path = target_before[0]["path"]

        request.addfinalizer(
            lambda: QDocSE.adjust().block_path(target_path).execute()
        )

        # Act
        result = QDocSE.adjust().auth_index(blocked_index).with_acl(acl_with_entry).execute()
        result.ok()

        # Verify program moved to authorized with correct ACL
        view = QDocSE.view().authorized().execute().ok().parse()
        target = [p for p in view["authorized"] if p["path"] == target_path]
        assert len(target) == 1, f"Expected {target_path} in authorized list"
        assert target[0]["acl"] == acl_with_entry

    def test_block_with_acl(self, authorized_index, acl_with_entry, request):
        """Block with ACL association (-b -A)."""
        # Arrange: capture program path before move
        view_before = QDocSE.view().authorized().execute().ok().parse()
        target_before = [p for p in view_before["authorized"] if p["index"] == authorized_index]
        assert len(target_before) == 1
        target_path = target_before[0]["path"]

        request.addfinalizer(
            lambda: QDocSE.adjust().auth_path(target_path).execute()
        )

        # Act
        result = QDocSE.adjust().block_index(authorized_index).with_acl(acl_with_entry).execute()
        result.ok()

        # Verify program moved to blocked with correct ACL
        view = QDocSE.view().blocked().execute().ok().parse()
        target = [p for p in view["blocked"] if p["path"] == target_path]
        assert len(target) == 1, f"Expected {target_path} in blocked list"
        assert target[0]["acl"] == acl_with_entry

    def test_authorize_by_path_with_acl(self, temp_executable, acl_with_entry, request):
        """Authorize by path with ACL (-apf -A)."""
        request.addfinalizer(
            lambda: QDocSE.adjust().block_path(temp_executable).execute()
        )
        # First block it
        QDocSE.adjust().block_path(temp_executable).execute().ok()
        # Then authorize with ACL
        result = QDocSE.adjust().auth_path(temp_executable).with_acl(acl_with_entry).execute()
        result.ok()

        # Verify ACL appears
        view = QDocSE.view().authorized().execute().ok().parse()
        target = [p for p in view["authorized"] if p["path"] == temp_executable]
        assert len(target) == 1
        assert target[0]["acl"] == acl_with_entry

    def test_block_by_path_with_acl(self, temp_executable, acl_with_entry, request):
        """Block by path with ACL (-bpf -A)."""
        # Arrange: authorize it first
        QDocSE.adjust().auth_path(temp_executable).execute().ok()
        request.addfinalizer(
            lambda: QDocSE.adjust().auth_path(temp_executable).execute()
        )

        # Act: block with ACL
        result = QDocSE.adjust().block_path(temp_executable).with_acl(acl_with_entry).execute()
        result.ok()

        # Assert: ACL appears in blocked list
        view = QDocSE.view().blocked().execute().ok().parse()
        target = [p for p in view["blocked"] if p["path"] == temp_executable]
        assert len(target) == 1
        assert target[0]["acl"] == acl_with_entry


# =============================================================================
# Error & Validation Tests
# =============================================================================

@pytest.mark.unit
class TestAdjustErrors:
    """Error cases and invalid inputs."""

    def test_missing_auth_block_option(self):
        """adjust without -api/-apf/-b/-bpf fails."""
        result = QDocSE.adjust().execute()
        result.fail("Should fail without auth/block option")
        assert "Missing required options" in result.result.stderr

    @pytest.mark.parametrize("index", [-1, 0, 99999])
    def test_invalid_index(self, index):
        """Invalid index fails with appropriate error.

        Docs: index_number comes from the view command which uses 1-based
        indices, so -1, 0, and 99999 are all invalid.
        """
        # Try auth_index
        result = QDocSE.adjust().auth_index(index).execute()
        result.fail(f"Should fail for invalid index {index}")
        assert "does not exist" in result.result.stderr
        assert "Use '-h' for help" in result.result.stderr
        # Try block_index (should behave similarly)
        result = QDocSE.adjust().block_index(index).execute()
        result.fail(f"Should fail for invalid index {index}")
        assert "does not exist" in result.result.stderr
        assert "Use '-h' for help" in result.result.stderr

    def test_invalid_acl_id(self, authorized_index):
        """Invalid ACL ID fails."""
        result = QDocSE.adjust().auth_index(authorized_index).with_acl(999999).execute()
        result.fail("Should fail for invalid ACL ID")
        assert "Invalid ACL ID" in result.result.stderr

    def test_with_acl_without_auth_block(self):
        """-A without auth/block option fails.

        Docs don't explicitly specify the error for '-A' alone.
        Expected: missing auth/block error (like test_missing_auth_block_option).
        Observed: returns "Invalid ACL ID" instead — likely validates ACL before
        checking required options. Kept as-is to document actual behavior.
        """
        result = QDocSE.adjust().with_acl(1).execute()
        result.fail("Should fail without auth/block option")
        # NOTE: Docs would suggest "Missing required options" but implementation
        # returns "Invalid ACL ID".  If this changes, update to match docs.
        assert "Invalid ACL ID" in result.result.stderr

    def test_duplicate_authorization(self, authorized_index):
        """Authorizing an already authorized program succeeds (no-op)."""
        result = QDocSE.adjust().auth_index(authorized_index).execute()
        # Should succeed (no change)
        result.ok()
        # Verify still authorized
        view = QDocSE.view().authorized().execute().ok().parse()
        still_auth = [p for p in view["authorized"] if p["index"] == authorized_index]
        assert len(still_auth) == 1

    def test_duplicate_block(self, blocked_index):
        """Blocking an already blocked program succeeds (no-op)."""
        result = QDocSE.adjust().block_index(blocked_index).execute()
        result.ok()
        # Verify still blocked
        view = QDocSE.view().blocked().execute().ok().parse()
        still_blocked = [p for p in view["blocked"] if p["index"] == blocked_index]
        assert len(still_blocked) == 1

    def test_invalid_path_nonexistent(self):
        """Authorize nonexistent path fails."""
        result = QDocSE.adjust().auth_path("/nonexistent/path/to/program").execute()
        result.fail("Should fail for nonexistent path")
        # Error should indicate path issue
        assert "does not exist" in result.result.stderr or "not found" in result.result.stderr.lower()

    def test_shell_script_silently_ignored(self, tmp_path):
        """Shell scripts (non-ELF) are silently ignored - command succeeds but no effect.

        Docs (adjust section): "every shared library used by the program is being
        evaluated" — implies only ELF binaries are processed.  Docs do not
        explicitly state that non-ELF files are silently ignored, so this test
        documents observed implementation behavior.

        push_config is called here (unlike other adjust tests) to verify the
        script remains absent even after configuration is applied.
        """
        # Arrange: create a shell script
        script = tmp_path / "script.sh"
        script.write_text("#!/bin/bash\necho hello\n")
        script.chmod(0o755)
        script_path = str(script)

        # Act
        result = QDocSE.adjust().auth_path(script_path).execute()

        # Assert: command succeeds (exit 0) but script is NOT added
        result.ok()
        QDocSE.push_config().execute().ok()

        # Verify NOT in authorized list (silently ignored)
        view = QDocSE.view().authorized().execute().ok().parse()
        paths = [p["path"] for p in view.get("authorized", [])]
        assert script_path not in paths, "Shell scripts should be silently ignored"

    def test_block_invalid_path_nonexistent(self):
        """Block nonexistent path fails."""
        result = QDocSE.adjust().block_path("/nonexistent/path/to/program").execute()
        result.fail("Should fail for nonexistent path")
        assert "does not exist" in result.result.stderr or "not found" in result.result.stderr.lower()


# =============================================================================
# Mutual Exclusivity Tests
# =============================================================================

@pytest.mark.unit
class TestAdjustMutualExclusivity:
    """Mutually exclusive option combinations."""

    def test_auth_path_and_block_path_same(self, temp_executable):
        """-apf and -bpf with same path fails."""
        result = QDocSE.adjust().auth_path(temp_executable).block_path(temp_executable).execute()
        result.fail("Should fail when same path used for both auth and block")
        assert "should not be the same" in result.result.stderr

    def test_auth_index_and_block_index_same(self, authorized_index):
        """-api and -b with same index fails."""
        result = QDocSE.adjust().auth_index(authorized_index).block_index(authorized_index).execute()
        result.fail("Should fail when same index used for both auth and block")
        assert "cannot be same" in result.result.stderr

    @pytest.mark.parametrize("auth_opt,block_opt", [
        ("auth_index", "block_index"),
        ("auth_index", "block_path"),
        ("auth_path", "block_index"),
        ("auth_path", "block_path"),
    ])
    def test_auth_and_block_different_targets_succeed(self, tmp_path, temp_executable, authorized_index, blocked_index, auth_opt, block_opt):
        """Different auth and block targets can be combined in one command."""
        # For auth_path+block_path case, need two different executables
        if auth_opt == "auth_path" and block_opt == "block_path":
            # Create second temp executable
            import shutil, os
            src = "/bin/true"
            if not os.path.exists(src):
                src = "/usr/bin/true"
            second_executable = tmp_path / "test_executable2"
            shutil.copy(src, second_executable)
            os.chmod(second_executable, 0o755)
            second_path = str(second_executable)
            # Authorize second executable so block_path has effect
            QDocSE.adjust().auth_path(second_path).execute().ok()
            auth_target = temp_executable
            block_target = second_path
        else:
            auth_target = temp_executable if auth_opt == "auth_path" else None
            block_target = temp_executable if block_opt == "block_path" else None
            # Ensure temp_executable is authorized (so block_path has effect)
            if block_opt == "block_path":
                QDocSE.adjust().auth_path(temp_executable).execute().ok()

        cmd = QDocSE.adjust()
        if auth_opt == "auth_index":
            cmd.auth_index(authorized_index)
        else:
            cmd.auth_path(auth_target)
        if block_opt == "block_index":
            cmd.block_index(blocked_index)
        else:
            cmd.block_path(block_target)
        result = cmd.execute()
        result.ok("Should succeed when auth and block targets are different")
        # Cleanup: restore state
        if block_opt == "block_path":
            # block_target is now blocked; re-authorize for other tests
            target_to_restore = block_target if auth_opt != "auth_path" else temp_executable
            QDocSE.adjust().auth_path(target_to_restore).execute().ok()
        if block_opt == "block_index":
            # blocked program moved to authorized; re-block
            QDocSE.adjust().block_index(blocked_index).execute().ok()
        # Cleanup second executable if created
        if auth_opt == "auth_path" and block_opt == "block_path":
            # block_target (second_path) is blocked; authorize then block to remove from system
            QDocSE.adjust().auth_path(second_path).execute().ok()
            QDocSE.adjust().block_path(second_path).execute().ok()

    def test_auth_index_and_auth_path_together_succeeds(self, temp_executable, authorized_index):
        """Both -api and -apf can be specified."""
        result = QDocSE.adjust().auth_index(authorized_index).auth_path(temp_executable).execute()
        result.ok("Should succeed with both auth options")

    def test_block_index_and_block_path_together_succeeds(self, temp_executable, blocked_index):
        """Both -b and -bpf can be specified."""
        # Ensure temp_executable is authorized first
        QDocSE.adjust().auth_path(temp_executable).execute().ok()
        result = QDocSE.adjust().block_index(blocked_index).block_path(temp_executable).execute()
        result.ok("Should succeed with both block options")
        # Cleanup
        QDocSE.adjust().auth_path(temp_executable).execute().ok()