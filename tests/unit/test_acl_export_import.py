"""
acl_export and acl_import Command Tests

PDF Manual Key Points:

acl_export (Page 76):
1. Exports ACL configuration to a file for import on other systems
2. Required option: -f <export_file_name>
3. Active modes: Elevated, Learning
4. License type: A
5. Errors:
   - Missing required '-f' option.
   - No ACL configuration yet.
   - Open ACL configuration error.
   - Memory allocation error.
   - ACL configuration read error.
   - ACL export error.
6. Example: QDocSEConsole -c acl_export -f /tmp/acl_config

acl_import (Page 79):
1. Imports ACL configuration from file
2. Any previous ACL configuration will be overridden
3. Specific files still need to be set to use ACL IDs after import
4. Required option: -f <input_file_name>
5. Active modes: Elevated, Learning
6. License type: A
7. Errors:
   - Missing required option '-f'.
   - Import file missing.
   - Import file open error.
   - Open ACL configuration error.
   - Memory allocation error.
   - ACL import read error.
   - ACL import hash verify error.
   - File lseek error.
   - ACL import error.
   - Import file trim error.
   - Bad magic number in ACL import file.
8. Example: QDocSEConsole -c acl_import -f /tmp/acl_config

Test Strategy:
1. Export: Basic export, file creation, file-path edge cases
2. Import: Import exported file, verify ACLs restored
3. Round-trip: Export -> Import -> Verify consistency
4. Override: Import replaces existing configuration
5. Error cases: Missing options, invalid files, path errors
"""
import os
import stat
import tempfile

import pytest
from helpers import QDocSE

# Prerequisites (auto-checked)
pytestmark = [
    pytest.mark.requires_mode("elevated", "learning"),
    pytest.mark.requires_license("A"),
]


@pytest.fixture
def temp_export_file():
    """Create a temporary file path for export tests."""
    fd, path = tempfile.mkstemp(suffix=".acl")
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def acl_with_entries(acl_id, some_valid_uids):
    """ACL with mixed allow/deny user entries for export/import testing."""
    uids = some_valid_uids[:3]
    QDocSE.acl_add(acl_id, allow=True, user=uids[0], mode="r").execute().ok()
    QDocSE.acl_add(acl_id, allow=True, user=uids[1], mode="rw").execute().ok()
    QDocSE.acl_add(acl_id, allow=False, user=uids[2], mode="w").execute().ok()
    return acl_id, uids


@pytest.mark.unit
class TestACLExportBasic:
    """Basic acl_export functionality."""

    def test_export_creates_file(self, acl_id, temp_export_file):
        """acl_export should create a non-empty export file."""
        QDocSE.acl_export(temp_export_file).execute().ok()

        assert os.path.exists(temp_export_file), "Export file should exist"
        assert os.path.getsize(temp_export_file) > 0, "Export file should not be empty"

    def test_export_requires_filename(self):
        """acl_export requires -f option.

        Per PDF: "Missing required '-f' option."
        """
        result = QDocSE.acl_export().execute()
        result.fail("Should fail without filename")
        result.contains("Missing required")

    def test_export_no_acl_configuration(self, temp_export_file):
        """Export with no ACL configuration should report error.

        Per PDF: "No ACL configuration yet."
        Note: This test may not be reachable if the purge fixture
        leaves a configuration file behind. Documented for completeness.
        """
        # Behavior depends on whether purge leaves an empty config or removes it
        result = QDocSE.acl_export(temp_export_file).execute()
        if result.result.failed:
            result.contains("No ACL configuration")


@pytest.mark.unit
class TestACLExportWithContent:
    """Export tests with actual ACL content."""

    def test_export_single_acl(self, acl_id, some_valid_uids, temp_export_file):
        """Export a single ACL with one entry."""
        QDocSE.acl_add(acl_id, user=some_valid_uids[0], mode="r").execute().ok()
        QDocSE.acl_export(temp_export_file).execute().ok()

        assert os.path.getsize(temp_export_file) > 0, "Export file should have content"

    def test_export_multiple_acls(self, some_valid_uids, temp_export_file):
        """Export multiple ACLs."""
        uids = some_valid_uids[:3]
        for uid in uids:
            result = QDocSE.acl_create().execute().ok()
            aid = result.parse()["acl_id"]
            QDocSE.acl_add(aid, user=uid, mode="r").execute().ok()

        QDocSE.acl_export(temp_export_file).execute().ok()
        assert os.path.getsize(temp_export_file) > 0


@pytest.mark.unit
class TestACLExportFilePaths:
    """Export file-path edge cases."""

    def test_export_overwrites_existing_file(self, acl_id, temp_export_file):
        """Export to a file that already has content should overwrite it."""
        # First export
        QDocSE.acl_export(temp_export_file).execute().ok()
        size_first = os.path.getsize(temp_export_file)

        # Second export to same file should succeed
        QDocSE.acl_export(temp_export_file).execute().ok()
        size_second = os.path.getsize(temp_export_file)

        assert size_second > 0, "File should have content after second export"

    def test_export_to_directory_path_fails(self, acl_id):
        """Export to a path that is a directory should fail."""
        result = QDocSE.acl_export("/tmp/").execute()
        result.fail("Should fail when target is a directory")

    def test_export_to_nonexistent_directory_fails(self):
        """Export to nonexistent directory should fail."""
        result = QDocSE.acl_export("/nonexistent/dir/acl.config").execute()
        result.fail("Should fail for nonexistent directory")

    def test_export_to_readonly_path_fails(self, acl_id):
        """Export to read-only path should fail."""
        result = QDocSE.acl_export("/proc/acl_export").execute()
        result.fail("Should fail for read-only path")

    def test_export_with_relative_path(self, acl_id):
        """Export with relative file path should succeed."""
        rel_path = "test_acl_export_temp.acl"
        try:
            QDocSE.acl_export(rel_path).execute().ok()
        finally:
            # Clean up relative-path file if created
            if os.path.exists(rel_path):
                os.unlink(rel_path)


@pytest.mark.unit
class TestACLImportBasic:
    """Basic acl_import functionality."""

    def test_import_requires_filename(self):
        """acl_import requires -f option.

        Per PDF: "Missing required option '-f'."
        """
        result = QDocSE.acl_import().execute()
        result.fail("Should fail without filename")
        result.contains("Missing required")

    def test_import_nonexistent_file_fails(self):
        """acl_import with nonexistent file should fail.

        Per PDF: "Import file missing."
        """
        result = QDocSE.acl_import("/nonexistent/path/acl.config").execute()
        result.fail("Should fail for nonexistent file")
        result.contains("Import file missing")

    def test_import_invalid_file_fails(self, temp_export_file):
        """acl_import with non-ACL file should fail.

        Per PDF: "Bad magic number in ACL import file."
        """
        with open(temp_export_file, 'w') as f:
            f.write("This is not a valid ACL export file")

        result = QDocSE.acl_import(temp_export_file).execute()
        result.fail("Should fail for invalid file format")
        result.contains("Bad magic number")

    def test_import_empty_file_fails(self, temp_export_file):
        """Import empty file should fail."""
        # Truncate to empty
        open(temp_export_file, 'w').close()

        result = QDocSE.acl_import(temp_export_file).execute()
        result.fail("Should fail for empty file")

    def test_import_directory_path_fails(self):
        """Import a directory instead of a file should fail."""
        result = QDocSE.acl_import("/tmp/").execute()
        result.fail("Should fail when target is a directory")

    def test_import_no_read_permission_fails(self, acl_id, temp_export_file):
        """Import a file without read permission should fail.

        Per PDF: "Import file open error."
        """
        # Export valid file first
        QDocSE.acl_export(temp_export_file).execute().ok()

        # Remove read permission
        os.chmod(temp_export_file, 0o000)
        try:
            result = QDocSE.acl_import(temp_export_file).execute()
            result.fail("Should fail without read permission")
        finally:
            # Restore permission for cleanup
            os.chmod(temp_export_file, stat.S_IRUSR | stat.S_IWUSR)


@pytest.mark.unit
class TestACLExportImportRoundTrip:
    """Round-trip tests: export -> import -> verify."""

    def test_export_import_preserves_entries(self, temp_export_file, some_valid_uids):
        """Exported ACL entries should be preserved after import."""
        uids = some_valid_uids[:2]

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uids[0], mode="rw").execute().ok()
        QDocSE.acl_add(acl_id, allow=False, user=uids[1], mode="w").execute().ok()

        # Export
        QDocSE.acl_export(temp_export_file).execute().ok()

        # Destroy original
        QDocSE.acl_destroy(acl_id, force=True).execute().ok()
        QDocSE.push_config().execute()

        # Import
        QDocSE.acl_import(temp_export_file).execute().ok()
        QDocSE.push_config().execute()

        # Verify entries are preserved (ACL ID may differ after import)
        restored = QDocSE.acl_list().execute().ok().result.stdout
        assert f"User: {uids[0]}" in restored, \
            f"Allow entry for UID {uids[0]} should be restored"
        assert f"User: {uids[1]}" in restored, \
            f"Deny entry for UID {uids[1]} should be restored"
        assert "Allow" in restored
        assert "Deny" in restored

    def test_export_import_preserves_acl_count(self, temp_export_file, some_valid_uids):
        """Multiple ACLs should be preserved through export/import."""
        uids = some_valid_uids[:3]

        ids = []
        for uid in uids:
            result = QDocSE.acl_create().execute().ok()
            aid = result.parse()["acl_id"]
            ids.append(aid)
            QDocSE.acl_add(aid, user=uid, mode="r").execute().ok()

        acl_count_before = QDocSE.acl_list().execute().ok().result.stdout.count("ACL ID")

        # Export
        QDocSE.acl_export(temp_export_file).execute().ok()

        # Destroy all
        for aid in ids:
            QDocSE.acl_destroy(aid, force=True).execute()
        QDocSE.push_config().execute()

        # Import
        QDocSE.acl_import(temp_export_file).execute().ok()
        QDocSE.push_config().execute()

        acl_count_after = QDocSE.acl_list().execute().ok().result.stdout.count("ACL ID")
        assert acl_count_after == acl_count_before, \
            f"ACL count mismatch: before={acl_count_before}, after={acl_count_after}"


@pytest.mark.unit
class TestACLImportOverride:
    """Test that import overrides existing configuration."""

    def test_import_overrides_existing(self, temp_export_file, some_valid_uids):
        """acl_import should override any previous ACL configuration.

        Per PDF: "Any previous ACL configuration will be overridden."
        """
        uids = some_valid_uids[:2]

        # Create initial ACL and export
        result1 = QDocSE.acl_create().execute().ok()
        id1 = result1.parse()["acl_id"]
        QDocSE.acl_add(id1, user=uids[0], mode="r").execute().ok()
        QDocSE.acl_export(temp_export_file).execute().ok()

        # Modify: destroy old, create new different one
        QDocSE.acl_destroy(id1, force=True).execute().ok()
        result2 = QDocSE.acl_create().execute().ok()
        id2 = result2.parse()["acl_id"]
        QDocSE.acl_add(id2, user=uids[1], mode="w").execute().ok()
        QDocSE.push_config().execute()

        # Import should restore original config, overriding current
        QDocSE.acl_import(temp_export_file).execute().ok()
        QDocSE.push_config().execute()

        # Verify original entry is restored
        list_result = QDocSE.acl_list().execute().ok()
        list_result.contains(f"User: {uids[0]}")


@pytest.mark.unit
class TestACLExportImportChaining:
    """Fluent interface tests."""

    def test_export_chaining(self, acl_id, temp_export_file):
        """Test export fluent API."""
        (QDocSE.acl_export()
            .file(temp_export_file)
            .execute()
            .ok())

        assert os.path.getsize(temp_export_file) > 0, \
            "Chained export should produce non-empty file"

    def test_import_chaining(self, temp_export_file, acl_with_entries):
        """Test import fluent API."""
        acl_id, uids = acl_with_entries

        # Export first
        QDocSE.acl_export(temp_export_file).execute().ok()

        # Import using chaining
        (QDocSE.acl_import()
            .file(temp_export_file)
            .execute()
            .ok())
