"""
Access Mode Tests - Execute Mode

Tests for execute permission effectiveness:
- Files with execute permission can be executed
- Files without execute permission cannot be executed
- Execute permission boundary conditions

Uses QDocSE API with protected_dir and apply_acl from conftest.
"""
import pytest
import os
import stat
from pathlib import Path
from helpers import QDocSE
from conftest import apply_acl


def _cleanup_acl(acl_id):
    try:
        QDocSE.acl_destroy(acl_id, force=True).execute()
        QDocSE.push_config().execute()
    except Exception:
        pass


def _create_script(directory, name="test_script.sh"):
    """Create an executable test script."""
    script_path = Path(directory) / name
    script_path.write_text("#!/bin/bash\necho 'Script executed successfully'\nexit 0\n")
    script_path.chmod(script_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script_path


class TestExecuteModeAllow:
    """Test cases where execute access should be allowed."""

    def test_execute_with_x_permission(self, protected_dir, request):
        """User with 'x' permission can execute files."""
        uid = os.getuid()
        script = _create_script(protected_dir)

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="x").execute()
        try:
            apply_acl(protected_dir, acl_id)
            # Execute via subprocess
            import subprocess
            proc = subprocess.run([str(script)], capture_output=True, text=True)
            assert proc.returncode == 0
            assert "Script executed successfully" in proc.stdout
        finally:
            _cleanup_acl(acl_id)

    def test_execute_with_rx_permission(self, protected_dir, request):
        """User with 'rx' permission can execute files."""
        uid = os.getuid()
        script = _create_script(protected_dir)

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rx").execute()
        try:
            apply_acl(protected_dir, acl_id)
            import subprocess
            proc = subprocess.run([str(script)], capture_output=True, text=True)
            assert proc.returncode == 0
        finally:
            _cleanup_acl(acl_id)

    def test_execute_with_rwx_permission(self, protected_dir, request):
        """User with 'rwx' (full) permission can execute files."""
        uid = os.getuid()
        script = _create_script(protected_dir)

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rwx").execute()
        try:
            apply_acl(protected_dir, acl_id)
            import subprocess
            proc = subprocess.run([str(script)], capture_output=True, text=True)
            assert proc.returncode == 0
        finally:
            _cleanup_acl(acl_id)


class TestExecuteModeDeny:
    """Test cases where execute access should be denied."""

    def test_execute_without_permission(self, protected_dir, request):
        """User without any ACL entry cannot execute files."""
        _create_script(protected_dir)

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        try:
            apply_acl(protected_dir, acl_id)
            import subprocess
            script = Path(protected_dir) / "test_script.sh"
            proc = subprocess.run([str(script)], capture_output=True, text=True)
            assert proc.returncode != 0, "Execute should fail without permission"
        finally:
            _cleanup_acl(acl_id)

    def test_execute_with_only_r_permission(self, protected_dir, request):
        """User with only 'r' permission cannot execute files."""
        uid = os.getuid()
        _create_script(protected_dir)

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute()
        try:
            apply_acl(protected_dir, acl_id)
            import subprocess
            script = Path(protected_dir) / "test_script.sh"
            proc = subprocess.run([str(script)], capture_output=True, text=True)
            assert proc.returncode != 0, "Execute should fail with only r permission"
        finally:
            _cleanup_acl(acl_id)

    def test_execute_with_only_w_permission(self, protected_dir, request):
        """User with only 'w' permission cannot execute files."""
        uid = os.getuid()
        _create_script(protected_dir)

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="w").execute()
        try:
            apply_acl(protected_dir, acl_id)
            import subprocess
            script = Path(protected_dir) / "test_script.sh"
            proc = subprocess.run([str(script)], capture_output=True, text=True)
            assert proc.returncode != 0, "Execute should fail with only w permission"
        finally:
            _cleanup_acl(acl_id)

    def test_execute_with_rw_permission(self, protected_dir, request):
        """User with 'rw' permission cannot execute files (no x)."""
        uid = os.getuid()
        _create_script(protected_dir)

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rw").execute()
        try:
            apply_acl(protected_dir, acl_id)
            import subprocess
            script = Path(protected_dir) / "test_script.sh"
            proc = subprocess.run([str(script)], capture_output=True, text=True)
            assert proc.returncode != 0, "Execute should fail with rw permission (no x)"
        finally:
            _cleanup_acl(acl_id)

    def test_execute_with_explicit_deny(self, protected_dir, request):
        """User with explicit deny entry cannot execute files."""
        uid = os.getuid()
        _create_script(protected_dir)

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=False, user=uid, mode="rwx").execute()
        try:
            apply_acl(protected_dir, acl_id)
            import subprocess
            script = Path(protected_dir) / "test_script.sh"
            proc = subprocess.run([str(script)], capture_output=True, text=True)
            assert proc.returncode != 0, "Execute should fail with explicit deny"
        finally:
            _cleanup_acl(acl_id)


class TestExecuteModeEdgeCases:
    """Edge cases for execute permission testing."""

    def test_execute_binary(self, protected_dir, request):
        """Can execute binary files with execute permission."""
        uid = os.getuid()
        import shutil

        # Copy a system binary
        binary_path = Path(protected_dir) / "test_echo"
        shutil.copy2("/bin/echo", str(binary_path))

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rx").execute()
        try:
            apply_acl(protected_dir, acl_id)
            import subprocess
            proc = subprocess.run([str(binary_path), "test output"], capture_output=True, text=True)
            assert proc.returncode == 0
            assert "test output" in proc.stdout
        finally:
            _cleanup_acl(acl_id)

    def test_execute_in_subdirectory(self, protected_dir, request):
        """Execute permission works for files in subdirectories."""
        uid = os.getuid()
        subdir = Path(protected_dir) / "scripts"
        subdir.mkdir()
        script = _create_script(str(subdir), "subdir_script.sh")

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rx").execute()
        try:
            apply_acl(protected_dir, acl_id)
            import subprocess
            proc = subprocess.run([str(script)], capture_output=True, text=True)
            assert proc.returncode == 0
        finally:
            _cleanup_acl(acl_id)
