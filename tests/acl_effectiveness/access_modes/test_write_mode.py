"""
Access Mode Tests - Write Mode

Tests for write permission effectiveness:
- Files with write permission can be modified
- Files without write permission cannot be modified
- Write permission boundary conditions

Uses QDocSE API with protected_dir and apply_acl from conftest.
"""
import pytest
import os
from pathlib import Path
from helpers import QDocSE
from conftest import apply_acl


def _cleanup_acl(acl_id):
    try:
        QDocSE.acl_destroy(acl_id, force=True).execute()
        QDocSE.push_config().execute()
    except Exception:
        pass


class TestWriteModeAllow:
    """Test cases where write access should be allowed."""

    def test_write_with_w_permission(self, protected_dir, request):
        """User with 'w' permission can write to files."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="w").execute()
        try:
            apply_acl(protected_dir, acl_id)
            Path(protected_dir, "test.txt").write_text("new content")
        finally:
            _cleanup_acl(acl_id)

    def test_write_with_rw_permission(self, protected_dir, request):
        """User with 'rw' permission can write to files."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rw").execute()
        try:
            apply_acl(protected_dir, acl_id)
            test_file = Path(protected_dir, "test.txt")
            test_file.write_text("updated content")
            content = test_file.read_text()
            assert content == "updated content"
        finally:
            _cleanup_acl(acl_id)

    def test_append_with_w_permission(self, protected_dir, request):
        """User with 'w' permission can append to files."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rw").execute()
        try:
            apply_acl(protected_dir, acl_id)
            test_file = Path(protected_dir, "test.txt")
            with open(test_file, "a") as f:
                f.write("\nappended text")
            content = test_file.read_text()
            assert "appended text" in content
        finally:
            _cleanup_acl(acl_id)

    def test_truncate_with_w_permission(self, protected_dir, request):
        """User with 'w' permission can truncate files."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="w").execute()
        try:
            apply_acl(protected_dir, acl_id)
            test_file = Path(protected_dir, "test.txt")
            test_file.write_text("")
            assert test_file.stat().st_size == 0
        finally:
            _cleanup_acl(acl_id)


class TestWriteModeDeny:
    """Test cases where write access should be denied."""

    def test_write_without_permission(self, protected_dir, request):
        """User without any ACL entry cannot write to files."""
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        try:
            apply_acl(protected_dir, acl_id)
            with pytest.raises((PermissionError, OSError)):
                Path(protected_dir, "test.txt").write_text("fail")
        finally:
            _cleanup_acl(acl_id)

    def test_write_with_only_r_permission(self, protected_dir, request):
        """User with only 'r' permission cannot write to files."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute()
        try:
            apply_acl(protected_dir, acl_id)
            with pytest.raises((PermissionError, OSError)):
                Path(protected_dir, "test.txt").write_text("fail")
        finally:
            _cleanup_acl(acl_id)

    def test_write_with_only_x_permission(self, protected_dir, request):
        """User with only 'x' permission cannot write to files."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="x").execute()
        try:
            apply_acl(protected_dir, acl_id)
            with pytest.raises((PermissionError, OSError)):
                Path(protected_dir, "test.txt").write_text("fail")
        finally:
            _cleanup_acl(acl_id)

    def test_write_with_explicit_deny(self, protected_dir, request):
        """User with explicit deny entry cannot write to files."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=False, user=uid, mode="rwx").execute()
        try:
            apply_acl(protected_dir, acl_id)
            with pytest.raises((PermissionError, OSError)):
                Path(protected_dir, "test.txt").write_text("fail")
        finally:
            _cleanup_acl(acl_id)


class TestWriteModeEdgeCases:
    """Edge cases for write permission testing."""

    def test_create_new_file_with_w_permission(self, protected_dir, request):
        """User with 'w' permission can create new files."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="w").execute()
        try:
            apply_acl(protected_dir, acl_id)
            new_file = Path(protected_dir) / "new_file.txt"
            new_file.write_text("content")
            assert new_file.exists()
        finally:
            _cleanup_acl(acl_id)

    def test_overwrite_file_with_rw_permission(self, protected_dir, request):
        """User with 'rw' permission can overwrite existing files."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rw").execute()
        try:
            apply_acl(protected_dir, acl_id)
            test_file = Path(protected_dir, "test.txt")
            new_content = "completely new content"
            test_file.write_text(new_content)
            assert test_file.read_text() == new_content
        finally:
            _cleanup_acl(acl_id)
