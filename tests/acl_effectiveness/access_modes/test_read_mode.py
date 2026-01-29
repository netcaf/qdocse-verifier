"""
Access Mode Tests - Read Mode

Tests for read permission effectiveness:
- Files with read permission can be read
- Files without read permission cannot be read
- Read permission boundary conditions

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


class TestReadModeAllow:
    """Test cases where read access should be allowed."""

    def test_read_with_r_permission(self, protected_dir, request):
        """User with 'r' permission can read files."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute()
        try:
            apply_acl(protected_dir, acl_id)
            content = Path(protected_dir, "test.txt").read_text()
            assert content == "test content"
        finally:
            _cleanup_acl(acl_id)

    def test_read_with_rw_permission(self, protected_dir, request):
        """User with 'rw' permission can read files (write doesn't block read)."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rw").execute()
        try:
            apply_acl(protected_dir, acl_id)
            content = Path(protected_dir, "test.txt").read_text()
            assert content == "test content"
        finally:
            _cleanup_acl(acl_id)

    def test_read_with_rwx_permission(self, protected_dir, request):
        """User with 'rwx' (full) permission can read files."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rwx").execute()
        try:
            apply_acl(protected_dir, acl_id)
            content = Path(protected_dir, "test.txt").read_text()
            assert content == "test content"
        finally:
            _cleanup_acl(acl_id)


class TestReadModeDeny:
    """Test cases where read access should be denied."""

    def test_read_without_permission(self, protected_dir, request):
        """User without any ACL entry cannot read files (empty ACL = deny all)."""
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        try:
            apply_acl(protected_dir, acl_id)
            with pytest.raises((PermissionError, OSError)):
                Path(protected_dir, "test.txt").read_text()
        finally:
            _cleanup_acl(acl_id)

    def test_read_with_only_w_permission(self, protected_dir, request):
        """User with only 'w' permission cannot read files."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="w").execute()
        try:
            apply_acl(protected_dir, acl_id)
            with pytest.raises((PermissionError, OSError)):
                Path(protected_dir, "test.txt").read_text()
        finally:
            _cleanup_acl(acl_id)

    def test_read_with_only_x_permission(self, protected_dir, request):
        """User with only 'x' permission cannot read files."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="x").execute()
        try:
            apply_acl(protected_dir, acl_id)
            with pytest.raises((PermissionError, OSError)):
                Path(protected_dir, "test.txt").read_text()
        finally:
            _cleanup_acl(acl_id)

    def test_read_with_explicit_deny(self, protected_dir, request):
        """User with explicit deny entry cannot read files."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=False, user=uid, mode="rwx").execute()
        try:
            apply_acl(protected_dir, acl_id)
            with pytest.raises((PermissionError, OSError)):
                Path(protected_dir, "test.txt").read_text()
        finally:
            _cleanup_acl(acl_id)


class TestReadModeEdgeCases:
    """Edge cases for read permission testing."""

    def test_read_empty_file(self, protected_dir, request):
        """Can read empty files with read permission."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute()
        try:
            empty_file = Path(protected_dir) / "empty.txt"
            empty_file.write_text("")

            apply_acl(protected_dir, acl_id)
            content = empty_file.read_text()
            assert content == ""
        finally:
            _cleanup_acl(acl_id)

    def test_read_large_file(self, protected_dir, request):
        """Can read large files with read permission."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute()
        try:
            large_file = Path(protected_dir) / "large.txt"
            large_file.write_text("x" * (1024 * 1024))

            apply_acl(protected_dir, acl_id)
            content = large_file.read_text()
            assert len(content) == 1024 * 1024
        finally:
            _cleanup_acl(acl_id)

    def test_read_binary_file(self, protected_dir, request):
        """Can read binary files with read permission."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute()
        try:
            binary_file = Path(protected_dir) / "binary.bin"
            binary_file.write_bytes(bytes(range(256)))

            apply_acl(protected_dir, acl_id)
            data = binary_file.read_bytes()
            assert len(data) == 256
        finally:
            _cleanup_acl(acl_id)
