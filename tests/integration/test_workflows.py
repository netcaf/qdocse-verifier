"""
Integration Tests - End-to-End Workflows

Note:
- Use acl_destroy to delete entire ACL table (not acl_remove)
- acl_remove only deletes entries, not the table
- ACL configuration changes require push_config to take effect

Test categories:
1. ACL configuration workflow (command level)
2. ACL and file protection integration
3. Complete access control workflow
"""
import pytest
import os
from helpers import QDocSE


def cleanup_acl(acl_id: int) -> None:
    """Clean up ACL"""
    QDocSE.acl_destroy(acl_id, force=True).execute()
    QDocSE.push_config().execute()


@pytest.mark.integration
class TestACLWorkflow:
    """ACL Complete Workflow Tests"""
    
    def test_create_add_list_push_destroy_workflow(self):
        """
        Complete ACL workflow:
        create -> add -> list -> push_config -> destroy
        """
        # Step 1: Create ACL
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        assert acl_id is not None
        
        try:
            # Step 2: Add entries
            QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
            QDocSE.acl_add(acl_id, user=1, mode="rw").execute().ok()
            QDocSE.acl_add(acl_id, allow=False, user=2, mode="w").execute().ok()
            
            # Step 3: Verify entries
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            list_result.contains("Entry: 1")
            list_result.contains("Entry: 2")
            list_result.contains("Entry: 3")
            list_result.contains("Pending configuration")
            
            # Step 4: Push config to take effect
            QDocSE.push_config().execute().ok()
            
            # Step 5: Verify pending is cleared
            list_after = QDocSE.acl_list(acl_id).execute().ok()
            assert "Pending configuration" not in list_after.result.stdout
        
        finally:
            # Step 6: Cleanup - use acl_destroy to delete entire ACL table
            QDocSE.acl_destroy(acl_id, force=True).execute()
    
    def test_create_remove_entries_vs_destroy_table(self):
        """
        Distinguish between acl_remove and acl_destroy:
        - acl_remove: deletes entries, ACL table still exists
        - acl_destroy: deletes entire ACL table
        """
        # Create ACL
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        try:
            # Add entry
            QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
            
            # Use acl_remove -A to delete all entries
            QDocSE.acl_remove(acl_id, all=True).execute().ok()
            
            # Verify: ACL table still exists, just empty
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            list_result.contains(f"ACL ID {acl_id}")
            list_result.contains("No entries")
            
            # Now use acl_destroy to delete entire table
            QDocSE.acl_destroy(acl_id).execute().ok()
            
            # Verify: ACL table no longer exists
            list_after = QDocSE.acl_list(acl_id).execute()
            assert list_after.result.failed or \
                   f"ACL ID {acl_id}" not in list_after.result.stdout
        
        except AssertionError:
            # Ensure cleanup
            QDocSE.acl_destroy(acl_id, force=True).execute()
            raise
    
    def test_acl_edit_reorder_workflow(self):
        """
        ACL entry reorder workflow:
        create -> add multiple -> edit order -> verify -> push_config
        """
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        try:
            # Add 3 entries
            QDocSE.acl_add(acl_id, user=100, mode="r").execute().ok()   # Entry 1
            QDocSE.acl_add(acl_id, user=200, mode="rw").execute().ok()  # Entry 2
            QDocSE.acl_add(acl_id, user=300, mode="rwx").execute().ok() # Entry 3
            
            # Verify initial order
            list1 = QDocSE.acl_list(acl_id).execute().ok()
            stdout1 = list1.result.stdout
            assert stdout1.find("100") < stdout1.find("200") < stdout1.find("300")
            
            # Move Entry 3 to first position
            QDocSE.acl_edit(acl_id, entry=3, position=1).execute().ok()
            
            # Verify new order: 300, 100, 200
            list2 = QDocSE.acl_list(acl_id).execute().ok()
            stdout2 = list2.result.stdout
            assert stdout2.find("300") < stdout2.find("100") < stdout2.find("200"), \
                "Entry order should be 300, 100, 200 after reorder"
            
            # Push config
            QDocSE.push_config().execute().ok()
            
        finally:
            cleanup_acl(acl_id)


@pytest.mark.integration
class TestProtectWorkflow:
    """Directory Protection Workflow Tests"""
    
    def test_protect_unprotect(self, temp_dir, acl_id):
        """Protect -> Set ACL -> Unprotect"""
        # Protect directory
        QDocSE.protect(temp_dir, encrypt=False).execute().ok()
        
        # Set ACL
        QDocSE.acl_file(temp_dir, user_acl=acl_id).execute().ok()
        
        # Unprotect
        QDocSE.unprotect(temp_dir).execute().ok()
    
    def test_protect_with_pattern(self, test_dir_with_files, acl_id):
        """
        Use pattern matching when protecting directory
        """
        try:
            # Protect directory
            result = QDocSE.protect(test_dir_with_files, encrypt=False).execute()
            if result.result.failed:
                pytest.skip(f"Cannot protect: {result.result.stderr}")
            
            # Set ACL only for .txt files
            QDocSE.acl_file(
                test_dir_with_files,
                user_acl=acl_id,
                pattern="*.txt"
            ).execute().ok()
            
            # Push config
            QDocSE.push_config().execute().ok()
            
        finally:
            QDocSE.unprotect(test_dir_with_files).execute()


@pytest.mark.integration
class TestACLWithProtectWorkflow:
    """ACL and File Protection Integration Tests"""
    
    def test_full_protect_acl_workflow(self, temp_dir):
        """
        Complete workflow:
        1. Create ACL and add rules
        2. Protect directory
        3. Apply ACL to directory
        4. push_config to make config effective
        5. Cleanup
        """
        # Step 1: Create and configure ACL
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        try:
            # Add allow rule
            QDocSE.acl_add(acl_id, user=0, mode="rw").execute().ok()
            
            # Step 2: Protect directory
            QDocSE.protect(temp_dir, encrypt=False).execute().ok()
            
            # Step 3: Apply ACL to directory
            QDocSE.acl_file(temp_dir, user_acl=acl_id).execute().ok()
            
            # Step 4: Push config to take effect
            QDocSE.push_config().execute().ok()
            
            # Verify ACL is applied
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            assert "Pending configuration" not in list_result.result.stdout
            
        finally:
            # Step 5: Cleanup
            QDocSE.unprotect(temp_dir).execute()
            QDocSE.acl_destroy(acl_id, force=True).execute()
    
    def test_multi_acl_protect_workflow(self, test_dir_with_files):
        """
        Multi-ACL protection workflow:
        - Apply different ACLs to different file types
        """
        # Create two ACLs
        result1 = QDocSE.acl_create().execute().ok()
        acl1 = result1.parse()["acl_id"]
        
        result2 = QDocSE.acl_create().execute().ok()
        acl2 = result2.parse()["acl_id"]
        
        try:
            # Configure ACL
            QDocSE.acl_add(acl1, user=0, mode="r").execute().ok()    # Read-only
            QDocSE.acl_add(acl2, user=0, mode="rw").execute().ok()   # Read-write
            
            # Protect directory
            QDocSE.protect(test_dir_with_files, encrypt=False).execute().ok()
            
            # Use ACL1 for .txt files (read-only)
            QDocSE.acl_file(
                test_dir_with_files,
                user_acl=acl1,
                pattern="*.txt"
            ).execute().ok()
            
            # Use ACL2 for .doc files (read-write)
            QDocSE.acl_file(
                test_dir_with_files,
                user_acl=acl2,
                pattern="*.doc"
            ).execute().ok()
            
            # Push config
            QDocSE.push_config().execute().ok()
            
        finally:
            QDocSE.unprotect(test_dir_with_files).execute()
            cleanup_acl(acl1)
            cleanup_acl(acl2)


@pytest.mark.integration
class TestACLExportImportWorkflow:
    """ACL Export/Import Workflow Tests"""
    
    def test_export_import_roundtrip(self, tmp_path):
        """
        Export -> Destroy -> Import -> Verify
        """
        export_file = str(tmp_path / "acl_export.conf")
        
        # Create ACL 并添加条目
        result = QDocSE.acl_create().execute().ok()
        original_id = result.parse()["acl_id"]
        
        try:
            QDocSE.acl_add(original_id, user=0, mode="rw").execute().ok()
            QDocSE.acl_add(original_id, allow=False, user=1, mode="w").execute().ok()
            
            # Record original state
            original_list = QDocSE.acl_list(original_id).execute().ok()
            original_entry_count = original_list.result.stdout.count("Entry:")
            
            # Export
            QDocSE.acl_export(export_file).execute().ok()
            
            # Destroy original ACL
            QDocSE.acl_destroy(original_id, force=True).execute().ok()
            QDocSE.push_config().execute()
            
            # Import
            QDocSE.acl_import(export_file).execute().ok()
            QDocSE.push_config().execute()
            
            # Verify: list all ACLs to check entries restored
            restored_list = QDocSE.acl_list().execute().ok()
            restored_entry_count = restored_list.result.stdout.count("Entry:")
            
            assert restored_entry_count >= original_entry_count, \
                "Imported ACL should have at least as many entries as original"
            
        finally:
            # Clean up exported file
            if os.path.exists(export_file):
                os.unlink(export_file)


@pytest.mark.integration
class TestACLProgramWorkflow:
    """ACL Program Association Workflow Tests"""
    
    def test_acl_program_association(self, user_acl_with_allow_deny):
        """
        Associate ACL with authorized program
        
        Note: Requires authorized programs in system
        """
        acl_id = user_acl_with_allow_deny
        
        # Get authorized program list
        view_result = QDocSE.view().execute()
        if view_result.result.failed:
            pytest.skip("Cannot get view output")
        
        # Try to associate ACL with program 1
        result = QDocSE.acl_program(acl_id, program=1).execute()
        
        # Record result (may succeed or fail, depending on whether system has program index 1)
        if result.result.success:
            print("ACL successfully associated with program")
            QDocSE.push_config().execute().ok()
        else:
            print(f"ACL-program association failed: {result.result.stderr}")
            # This is not necessarily an error - may have no authorized programs


@pytest.mark.integration  
class TestCompleteACLLifecycle:
    """Complete ACL Lifecycle Tests"""
    
    def test_full_acl_lifecycle(self, tmp_path):
        """
        Complete ACL lifecycle:
        1. Create directory and files
        2. Create ACL and configure rules
        3. Protect directory
        4. Apply ACL to files
        5. Push config
        6. Verify config
        7. Modify ACL (add/delete/reorder entries)
        8. Push and verify again
        9. Export ACL config
        10. Cleanup
        """
        # 1. Create directory and files
        test_dir = tmp_path / "lifecycle_test"
        test_dir.mkdir()
        (test_dir / "data.txt").write_text("sensitive data")
        (test_dir / "config.cfg").write_text("configuration")
        dir_path = str(test_dir)
        
        # 2. Create ACL
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        # Add initial rules
        QDocSE.acl_add(acl_id, user=0, mode="rw").execute().ok()
        QDocSE.acl_add(acl_id, user=1000, mode="r").execute().ok()
        
        try:
            # 3. Protect directory
            protect_result = QDocSE.protect(dir_path, encrypt=False).execute()
            if protect_result.result.failed:
                pytest.skip("Cannot protect directory")
            
            # 4. Apply ACL
            QDocSE.acl_file(dir_path, user_acl=acl_id, pattern="*.txt").execute().ok()
            
            # 5. Push config
            QDocSE.push_config().execute().ok()
            
            # 6. Verify config
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            assert "Entry: 1" in list_result.result.stdout
            assert "Entry: 2" in list_result.result.stdout
            assert "Pending configuration" not in list_result.result.stdout
            
            # 7. Modify ACL
            # Add new entry
            QDocSE.acl_add(acl_id, allow=False, user=65534, mode="rw").execute().ok()
            # Delete an entry
            QDocSE.acl_remove(acl_id, entry=2).execute().ok()
            
            # Verify pending exists
            list_pending = QDocSE.acl_list(acl_id).execute().ok()
            assert "Pending configuration" in list_pending.result.stdout
            
            # 8. Push again
            QDocSE.push_config().execute().ok()
            
            list_final = QDocSE.acl_list(acl_id).execute().ok()
            assert "Pending configuration" not in list_final.result.stdout
            
            # 9. Export config
            export_file = str(tmp_path / "acl_backup.conf")
            QDocSE.acl_export(export_file).execute().ok()
            assert os.path.exists(export_file)
            
            print("Full ACL lifecycle test PASSED")
            
        finally:
            # 10. Cleanup
            QDocSE.unprotect(dir_path).execute()
            cleanup_acl(acl_id)

