"""
File Lifecycle Tests - Read Operations

Tests for reading files in protected directories:
- Reading with appropriate permissions
- Reading file metadata
- Reading partial content

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


class TestFileReadOperations:
    """Test file read operations in protected directories."""

    def test_read_entire_file(self, protected_dir, request):
        """Can read entire file with read permission."""
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

    def test_read_multiline_file(self, protected_dir, request):
        """Can read multi-line file with read permission."""
        uid = os.getuid()
        multiline = Path(protected_dir) / "multiline.txt"
        lines = [f"Line {i}" for i in range(10)]
        multiline.write_text("\n".join(lines))

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute()
        try:
            apply_acl(protected_dir, acl_id)
            content = multiline.read_text()
            assert "Line 0" in content
            assert "Line 9" in content
        finally:
            _cleanup_acl(acl_id)

    def test_read_with_search_pattern(self, protected_dir, request):
        """Can search file content with read permission."""
        uid = os.getuid()
        searchable = Path(protected_dir) / "searchable.txt"
        searchable.write_text("apple\nbanana\ncherry\napricot\n")

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute()
        try:
            apply_acl(protected_dir, acl_id)
            content = searchable.read_text()
            assert "apple" in content
            assert "apricot" in content
            assert "banana" in content
        finally:
            _cleanup_acl(acl_id)


class TestFileMetadataRead:
    """Test reading file metadata in protected directories."""

    def test_stat_file(self, protected_dir, request):
        """Can stat file to get metadata with read permission."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute()
        try:
            apply_acl(protected_dir, acl_id)
            test_file = Path(protected_dir, "test.txt")
            st = test_file.stat()
            assert st.st_size > 0
        finally:
            _cleanup_acl(acl_id)

    def test_list_directory(self, protected_dir, request):
        """Can list directory contents with read permission."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute()
        try:
            apply_acl(protected_dir, acl_id)
            files = os.listdir(protected_dir)
            assert "test.txt" in files
        finally:
            _cleanup_acl(acl_id)

    def test_get_file_size(self, protected_dir, request):
        """Can get file size with read permission."""
        uid = os.getuid()
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute()
        try:
            apply_acl(protected_dir, acl_id)
            test_file = Path(protected_dir, "test.txt")
            size = test_file.stat().st_size
            assert size >= len("test content")
        finally:
            _cleanup_acl(acl_id)


class TestReadDenied:
    """Test read operations that should be denied."""

    def test_read_without_permission(self, protected_dir, request):
        """Cannot read file without any permission."""
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        try:
            apply_acl(protected_dir, acl_id)
            with pytest.raises((PermissionError, OSError)):
                Path(protected_dir, "test.txt").read_text()
        finally:
            _cleanup_acl(acl_id)

    def test_read_with_only_write_permission(self, protected_dir, request):
        """Cannot read file with only write permission."""
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
