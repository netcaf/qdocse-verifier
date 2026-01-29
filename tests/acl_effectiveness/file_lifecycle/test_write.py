"""
File Lifecycle Tests - Write Operations

Tests for writing to files in protected directories:
- Writing with appropriate permissions
- Appending content
- Truncating files

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


class TestFileWriteOperations:
    """Test file write operations in protected directories."""

    def test_write_new_content(self, protected_dir, request):
        """Can write new content to file with write permission."""
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

    def test_append_content(self, protected_dir, request):
        """Can append content to file with write permission."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rw").execute()
        try:
            apply_acl(protected_dir, acl_id)
            test_file = Path(protected_dir, "test.txt")
            original = test_file.read_text()
            with open(test_file, "a") as f:
                f.write("\nappended text")
            content = test_file.read_text()
            assert original in content
            assert "appended text" in content
        finally:
            _cleanup_acl(acl_id)

    def test_truncate_file(self, protected_dir, request):
        """Can truncate file with write permission."""
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

    def test_write_binary_content(self, protected_dir, request):
        """Can write binary content with write permission."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="w").execute()
        try:
            apply_acl(protected_dir, acl_id)
            binary_file = Path(protected_dir) / "binary.bin"
            binary_file.write_bytes(os.urandom(1024))
            assert binary_file.exists()
            assert binary_file.stat().st_size == 1024
        finally:
            _cleanup_acl(acl_id)


class TestWriteDenied:
    """Test write operations that should be denied."""

    def test_write_without_permission(self, protected_dir, request):
        """Cannot write to file without any permission."""
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        try:
            apply_acl(protected_dir, acl_id)
            with pytest.raises((PermissionError, OSError)):
                Path(protected_dir, "test.txt").write_text("fail")
        finally:
            _cleanup_acl(acl_id)

    def test_write_with_only_read_permission(self, protected_dir, request):
        """Cannot write to file with only read permission."""
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

    def test_truncate_with_only_read_permission(self, protected_dir, request):
        """Cannot truncate file with only read permission."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute()
        try:
            apply_acl(protected_dir, acl_id)
            with pytest.raises((PermissionError, OSError)):
                Path(protected_dir, "test.txt").write_text("")
        finally:
            _cleanup_acl(acl_id)


class TestWriteEdgeCases:
    """Edge cases for write operations."""

    def test_concurrent_writes(self, protected_dir, request):
        """Multiple sequential writes to same file."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rw").execute()
        try:
            apply_acl(protected_dir, acl_id)
            test_file = Path(protected_dir) / "concurrent.txt"
            for i in range(10):
                with open(test_file, "a") as f:
                    f.write(f"write {i}\n")

            content = test_file.read_text()
            assert "write 0" in content
            assert "write 9" in content
        finally:
            _cleanup_acl(acl_id)
