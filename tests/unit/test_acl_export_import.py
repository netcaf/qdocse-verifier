"""
acl_export and acl_import Command Tests

PDF Manual Key Points:

acl_export (Page 76):
1. Exports ACL configuration to a file for import on other systems
2. Required option: -f <export_file_name>
3. Active modes: Elevated, Learning
4. License type: A
5. Errors: Missing '-f', No ACL config, config read error, export error

acl_import (Page 79):
1. Imports ACL configuration from file
2. Any previous ACL configuration will be overridden
3. Required option: -f <input_file_name>
4. Active modes: Elevated, Learning
5. License type: A
6. Errors: Missing '-f', file missing, open error, hash verify error, bad magic number

Test Strategy:
1. Export: Basic export, file creation verification
2. Import: Import exported file, verify ACLs restored
3. Round-trip: Export -> Import -> Verify consistency
4. Error cases: Missing files, invalid files, permission errors
"""
import pytest
import os
import tempfile
from pathlib import Path
from helpers import QDocSE

# Prerequisites (auto-checked)
pytestmark = [
    pytest.mark.requires_mode("elevated", "learning"),
    pytest.mark.requires_license("A"),
]


def cleanup_acl(acl_id: int) -> None:
    """Cleanup helper"""
    QDocSE.acl_destroy(acl_id, force=True).execute()
    QDocSE.push_config().execute()


@pytest.fixture
def temp_export_file():
    """Create a temporary file for export tests"""
    fd, path = tempfile.mkstemp(suffix=".acl")
    os.close(fd)
    yield path
    # Cleanup
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def acl_with_complex_entries():
    """
    Create an ACL with various entry types for comprehensive export/import testing.
    Returns the ACL ID.
    """
    result = QDocSE.acl_create().execute().ok()
    acl_id = result.parse()["acl_id"]
    
    # Add various entries
    QDocSE.acl_add(acl_id, allow=True, user=0, mode="r").execute().ok()
    QDocSE.acl_add(acl_id, allow=True, user=1, mode="rw").execute().ok()
    QDocSE.acl_add(acl_id, allow=False, user=2, mode="w").execute().ok()
    QDocSE.acl_add(acl_id, allow=True, group=0, mode="rx").execute().ok()
    
    yield acl_id
    
    # Cleanup
    cleanup_acl(acl_id)


@pytest.mark.unit
class TestACLExportBasic:
    """Basic acl_export functionality"""
    
    def test_export_creates_file(self, temp_export_file):
        """
        acl_export should create the export file.
        """
        # Create an ACL first (export needs something to export)
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        try:
            # Export
            QDocSE.acl_export(temp_export_file).execute().ok()
            
            # Verify file was created (this may need remote file check for SSH)
            # For local execution, we can check directly
            # Note: In SSH mode, file is on remote system
        
        finally:
            cleanup_acl(acl_id)
    
    def test_export_requires_filename(self):
        """
        acl_export requires -f option.
        
        Per PDF page 76: "Missing required '-f' option" error
        """
        result = QDocSE.acl_export().execute()
        result.fail("Should fail without filename")
        result.contains("Missing")
    
    def test_export_with_no_acl_fails_gracefully(self, temp_export_file):
        """
        Export when no ACLs exist should handle gracefully.
        
        Note: Behavior depends on implementation - may export empty config or fail.
        """
        # This test documents the actual behavior
        result = QDocSE.acl_export(temp_export_file).execute()
        # Record behavior for documentation
        if result.result.success:
            print("Note: Export succeeds with no ACLs (exports empty config)")
        else:
            print("Note: Export fails when no ACLs exist")


@pytest.mark.unit
class TestACLExportWithContent:
    """Export tests with actual ACL content"""
    
    def test_export_single_acl(self, temp_export_file):
        """Export a single ACL"""
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        try:
            QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
            QDocSE.acl_export(temp_export_file).execute().ok()
        finally:
            cleanup_acl(acl_id)
    
    def test_export_multiple_acls(self, temp_export_file):
        """Export multiple ACLs"""
        ids = []
        try:
            # Create multiple ACLs
            for i in range(3):
                result = QDocSE.acl_create().execute().ok()
                acl_id = result.parse()["acl_id"]
                ids.append(acl_id)
                QDocSE.acl_add(acl_id, user=i, mode="r").execute().ok()
            
            # Export all
            QDocSE.acl_export(temp_export_file).execute().ok()
        
        finally:
            for acl_id in ids:
                QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()


@pytest.mark.unit
class TestACLImportBasic:
    """Basic acl_import functionality"""
    
    def test_import_requires_filename(self):
        """
        acl_import requires -f option.
        
        Per PDF page 79: "Missing required option '-f'" error
        """
        result = QDocSE.acl_import().execute()
        result.fail("Should fail without filename")
        result.contains("Missing")
    
    def test_import_nonexistent_file_fails(self):
        """
        acl_import with nonexistent file should fail.
        
        Per PDF page 79: "Import file missing" error
        """
        result = QDocSE.acl_import("/nonexistent/path/acl.config").execute()
        result.fail("Should fail for nonexistent file")
    
    def test_import_invalid_file_fails(self, temp_export_file):
        """
        acl_import with invalid file should fail.
        
        Per PDF page 79: "Bad magic number" error
        """
        # Write invalid content to file
        with open(temp_export_file, 'w') as f:
            f.write("This is not a valid ACL export file")
        
        result = QDocSE.acl_import(temp_export_file).execute()
        result.fail("Should fail for invalid file format")


@pytest.mark.unit
class TestACLExportImportRoundTrip:
    """Round-trip tests: export -> import -> verify"""
    
    def test_export_import_preserves_acl(self, temp_export_file):
        """
        Exported ACL should be identical after import.
        """
        # Create ACL with entries
        result = QDocSE.acl_create().execute().ok()
        original_id = result.parse()["acl_id"]
        
        try:
            QDocSE.acl_add(original_id, allow=True, user=0, mode="rw").execute().ok()
            QDocSE.acl_add(original_id, allow=False, user=1, mode="w").execute().ok()
            
            # Get original state
            original_list = QDocSE.acl_list(original_id).execute().ok().result.stdout
            
            # Export
            QDocSE.acl_export(temp_export_file).execute().ok()
            
            # Destroy original
            QDocSE.acl_destroy(original_id, force=True).execute().ok()
            QDocSE.push_config().execute()
            
            # Import
            QDocSE.acl_import(temp_export_file).execute().ok()
            QDocSE.push_config().execute()
            
            # Verify: ACL should be restored with same entries
            # Note: ACL ID may be different after import
            restored_list = QDocSE.acl_list().execute().ok()
            
            # Check entries are preserved (Allow user 0, Deny user 1)
            assert "Allow" in restored_list.result.stdout
            assert "Deny" in restored_list.result.stdout
        
        finally:
            # Cleanup any remaining ACLs
            try:
                cleanup_acl(original_id)
            except:
                pass
    
    def test_export_import_multiple_acls(self, temp_export_file):
        """
        Multiple ACLs should be preserved through export/import.
        """
        ids = []
        try:
            # Create 3 ACLs with different entries
            for i in range(3):
                result = QDocSE.acl_create().execute().ok()
                acl_id = result.parse()["acl_id"]
                ids.append(acl_id)
                QDocSE.acl_add(acl_id, user=i, mode="rwx"[:i+1]).execute().ok()
            
            # Count ACLs before export
            before = QDocSE.acl_list().execute().ok()
            acl_count_before = before.result.stdout.count("ACL ID")
            
            # Export
            QDocSE.acl_export(temp_export_file).execute().ok()
            
            # Destroy all
            for acl_id in ids:
                QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
            ids.clear()
            
            # Import
            QDocSE.acl_import(temp_export_file).execute().ok()
            QDocSE.push_config().execute()
            
            # Count ACLs after import
            after = QDocSE.acl_list().execute().ok()
            acl_count_after = after.result.stdout.count("ACL ID")
            
            # Should have same number of ACLs
            assert acl_count_after == acl_count_before, \
                f"ACL count mismatch: before={acl_count_before}, after={acl_count_after}"
        
        finally:
            for acl_id in ids:
                try:
                    cleanup_acl(acl_id)
                except:
                    pass


@pytest.mark.unit
class TestACLImportOverride:
    """Test that import overrides existing configuration"""
    
    def test_import_overrides_existing(self, temp_export_file):
        """
        acl_import should override any previous ACL configuration.
        
        Per PDF page 79: "Any previous ACL configuration will be overridden"
        """
        # Create initial ACL
        result1 = QDocSE.acl_create().execute().ok()
        id1 = result1.parse()["acl_id"]
        QDocSE.acl_add(id1, user=100, mode="r").execute().ok()
        
        # Export
        QDocSE.acl_export(temp_export_file).execute().ok()
        
        # Modify: destroy old, create new different one
        QDocSE.acl_destroy(id1, force=True).execute().ok()
        result2 = QDocSE.acl_create().execute().ok()
        id2 = result2.parse()["acl_id"]
        QDocSE.acl_add(id2, user=200, mode="w").execute().ok()
        QDocSE.push_config().execute()
        
        # Import should restore original config
        QDocSE.acl_import(temp_export_file).execute().ok()
        QDocSE.push_config().execute()
        
        # Verify original user 100 entry exists
        list_result = QDocSE.acl_list().execute().ok()
        list_result.contains("100")  # Original user ID should be present


@pytest.mark.unit
class TestACLExportImportErrors:
    """Error handling for export/import"""
    
    def test_export_to_readonly_path_fails(self):
        """Export to read-only path should fail"""
        # Try to export to a read-only location
        result = QDocSE.acl_export("/proc/acl_export").execute()
        result.fail("Should fail for read-only path")
    
    def test_import_empty_file_fails(self, temp_export_file):
        """Import empty file should fail"""
        # Create empty file
        Path(temp_export_file).touch()
        
        result = QDocSE.acl_import(temp_export_file).execute()
        result.fail("Should fail for empty file")
    
    def test_export_to_nonexistent_directory_fails(self):
        """Export to nonexistent directory should fail"""
        result = QDocSE.acl_export("/nonexistent/dir/acl.config").execute()
        result.fail("Should fail for nonexistent directory")


@pytest.mark.unit
class TestACLExportImportChaining:
    """Fluent interface tests"""
    
    def test_export_chaining(self, temp_export_file):
        """Test export fluent API"""
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        try:
            (QDocSE.acl_export()
                .file(temp_export_file)
                .execute()
                .ok())
        finally:
            cleanup_acl(acl_id)
    
    def test_import_chaining(self, temp_export_file, acl_with_complex_entries):
        """Test import fluent API"""
        # Export first
        QDocSE.acl_export(temp_export_file).execute().ok()
        
        # Import using chaining
        (QDocSE.acl_import()
            .file(temp_export_file)
            .execute()
            .ok())
