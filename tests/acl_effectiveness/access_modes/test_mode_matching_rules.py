"""
Access Mode Tests - Mode Matching Rules

Tests for permission mode matching behavior:
- Exact permission match
- Partial permission match
- Permission combination rules

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


class TestExactPermissionMatch:
    """Test exact permission matching scenarios."""

    def test_r_grants_only_read(self, protected_dir, request):
        """'r' permission grants only read access, denies write."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute()
        try:
            apply_acl(protected_dir, acl_id)
            # Should allow read
            content = Path(protected_dir, "test.txt").read_text()
            assert content == "test content"

            # Should deny write
            with pytest.raises((PermissionError, OSError)):
                Path(protected_dir, "test.txt").write_text("fail")
        finally:
            _cleanup_acl(acl_id)

    def test_w_grants_only_write(self, protected_dir, request):
        """'w' permission grants only write access, denies read."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="w").execute()
        try:
            apply_acl(protected_dir, acl_id)
            # Should deny read
            with pytest.raises((PermissionError, OSError)):
                Path(protected_dir, "test.txt").read_text()

            # Should allow write
            Path(protected_dir, "test.txt").write_text("new content")
        finally:
            _cleanup_acl(acl_id)

    def test_x_grants_only_execute(self, protected_dir, request):
        """'x' permission grants only execute access."""
        uid = os.getuid()
        script = Path(protected_dir) / "script.sh"
        script.write_text("#!/bin/bash\necho 'executed'\n")
        script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="x").execute()
        try:
            apply_acl(protected_dir, acl_id)
            # Should deny read
            with pytest.raises((PermissionError, OSError)):
                script.read_text()
        finally:
            _cleanup_acl(acl_id)


class TestCombinedPermissions:
    """Test combined permission scenarios."""

    def test_rw_grants_read_and_write(self, protected_dir, request):
        """'rw' permission grants both read and write access."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rw").execute()
        try:
            apply_acl(protected_dir, acl_id)
            # Should allow read
            content = Path(protected_dir, "test.txt").read_text()
            assert content == "test content"

            # Should allow write
            Path(protected_dir, "test.txt").write_text("updated")
            assert Path(protected_dir, "test.txt").read_text() == "updated"
        finally:
            _cleanup_acl(acl_id)

    def test_rx_grants_read_and_execute(self, protected_dir, request):
        """'rx' permission grants both read and execute access."""
        uid = os.getuid()
        script = Path(protected_dir) / "script.sh"
        script.write_text("#!/bin/bash\necho 'executed'\n")
        script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rx").execute()
        try:
            apply_acl(protected_dir, acl_id)
            # Should allow read
            content = script.read_text()
            assert "executed" in content

            # Should allow execute
            import subprocess
            proc = subprocess.run([str(script)], capture_output=True, text=True)
            assert proc.returncode == 0

            # Should deny write
            with pytest.raises((PermissionError, OSError)):
                script.write_text("fail")
        finally:
            _cleanup_acl(acl_id)

    def test_rwx_grants_all_access(self, protected_dir, request):
        """'rwx' permission grants full access."""
        uid = os.getuid()
        script = Path(protected_dir) / "script.sh"
        script.write_text("#!/bin/bash\necho 'executed'\n")
        script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rwx").execute()
        try:
            apply_acl(protected_dir, acl_id)
            # All operations should succeed
            content = script.read_text()
            assert "executed" in content

            script.write_text("#!/bin/bash\necho 'modified'\n")
            script.chmod(script.stat().st_mode | stat.S_IXUSR)

            import subprocess
            proc = subprocess.run([str(script)], capture_output=True, text=True)
            assert proc.returncode == 0
        finally:
            _cleanup_acl(acl_id)


class TestPermissionInheritance:
    """Test permission inheritance and override scenarios."""

    def test_first_match_wins(self, protected_dir, request):
        """First matching ACL entry determines access (first-match-wins)."""
        uid = os.getuid()
        gid = os.getgid()

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        # User entry (r only) first, then group entry (rwx)
        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute()
        QDocSE.acl_add(acl_id, allow=True, group=gid, mode="rwx").execute()

        try:
            apply_acl(protected_dir, acl_id)
            # First-match-wins: user entry matches first, only read
            content = Path(protected_dir, "test.txt").read_text()
            assert content == "test content"
        finally:
            _cleanup_acl(acl_id)

    def test_multiple_matching_entries(self, protected_dir, request):
        """
        When multiple entries match, first-match-wins applies.

        PDF: ACL uses first-match-wins evaluation. The first entry
        that matches the subject gets applied.
        """
        uid = os.getuid()

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        # Add entry with read permission first
        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute()
        # Add another entry with write permission second
        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="w").execute()

        try:
            apply_acl(protected_dir, acl_id)
            # First-match-wins: first entry (r) is applied
            content = Path(protected_dir, "test.txt").read_text()
            assert content == "test content"
        finally:
            _cleanup_acl(acl_id)
