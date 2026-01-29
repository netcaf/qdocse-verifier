"""
File Lifecycle Tests - Create Operations

Tests for file creation in protected directories:
- Creating new files with write permission
- Creating files without permission (should fail)
- File creation inheritance

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


class TestFileCreationAllowed:
    """Test cases where file creation should succeed."""

    def test_create_file_with_w_permission(self, protected_dir, request):
        """User with 'w' permission can create new files."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="w").execute()
        try:
            apply_acl(protected_dir, acl_id)
            new_file = Path(protected_dir) / "created_file.txt"
            new_file.write_text("new content")
            assert new_file.exists()
        finally:
            _cleanup_acl(acl_id)

    def test_create_file_with_rw_permission(self, protected_dir, request):
        """User with 'rw' permission can create new files."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rw").execute()
        try:
            apply_acl(protected_dir, acl_id)
            new_file = Path(protected_dir) / "created_rw.txt"
            new_file.touch()
            assert new_file.exists()
        finally:
            _cleanup_acl(acl_id)

    def test_create_multiple_files(self, protected_dir, request):
        """Can create multiple files in protected directory."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="w").execute()
        try:
            apply_acl(protected_dir, acl_id)
            for i in range(5):
                f = Path(protected_dir) / f"file_{i}.txt"
                f.write_text(f"content {i}")
                assert f.exists()

            files = [f for f in os.listdir(protected_dir) if f.startswith("file_")]
            assert len(files) == 5
        finally:
            _cleanup_acl(acl_id)


class TestFileCreationDenied:
    """Test cases where file creation should fail."""

    def test_create_file_without_permission(self, protected_dir, request):
        """User without permission cannot create files (empty ACL = deny all)."""
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        try:
            apply_acl(protected_dir, acl_id)
            new_file = Path(protected_dir) / "unauthorized.txt"
            with pytest.raises((PermissionError, OSError)):
                new_file.write_text("fail")
        finally:
            _cleanup_acl(acl_id)

    def test_create_file_with_only_r_permission(self, protected_dir, request):
        """User with only 'r' permission cannot create files."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute()
        try:
            apply_acl(protected_dir, acl_id)
            new_file = Path(protected_dir) / "readonly_create.txt"
            with pytest.raises((PermissionError, OSError)):
                new_file.write_text("fail")
        finally:
            _cleanup_acl(acl_id)

    def test_create_file_with_only_x_permission(self, protected_dir, request):
        """User with only 'x' permission cannot create files."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="x").execute()
        try:
            apply_acl(protected_dir, acl_id)
            new_file = Path(protected_dir) / "execonly_create.txt"
            with pytest.raises((PermissionError, OSError)):
                new_file.write_text("fail")
        finally:
            _cleanup_acl(acl_id)


class TestFileCreationInheritance:
    """Test ACL inheritance for newly created files."""

    def test_new_file_inherits_directory_acl(self, protected_dir, request):
        """Newly created files inherit directory ACL protection."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rw").execute()
        try:
            apply_acl(protected_dir, acl_id)
            new_file = Path(protected_dir) / "inherited.txt"
            new_file.write_text("content")

            # User should be able to read the file they created
            content = new_file.read_text()
            assert content == "content"
        finally:
            _cleanup_acl(acl_id)

    def test_new_file_in_subdirectory(self, protected_dir, request):
        """Files created in subdirectories inherit ACL."""
        uid = os.getuid()
        subdir = Path(protected_dir) / "subdir"
        subdir.mkdir()

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rw").execute()
        try:
            apply_acl(protected_dir, acl_id)
            sub_file = subdir / "subfile.txt"
            sub_file.write_text("subdir content")
            assert sub_file.exists()
        finally:
            _cleanup_acl(acl_id)
