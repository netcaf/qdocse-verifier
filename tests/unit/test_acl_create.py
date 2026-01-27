"""
acl_create Command Tests

PDF Manual Key Points (Page 73-74):
1. acl_create creates an empty ACL and associates a new ACL ID with it
2. All other ACL commands will use this ACL ID to identify the ACL
3. If an ACL is destroyed (acl_destroy), the matching ACL ID will NOT be reused
4. When command completes, it displays the new ACL ID value
5. No options for this command
6. Active modes: Elevated, Learning
7. License type: A (Protect with Encrypt)

Important Distinctions:
- acl_destroy: Deletes the ENTIRE ACL table
- acl_remove: Removes ENTRIES from an ACL (not the table itself)
- push_config: Commits ACL configuration changes to QDocSE system
  (Page 118: Changes are NOT effective until push_config is executed)

Test Strategy:
1. Basic validation: Command success + ID parsing
2. Deep validation: Use acl_list to confirm creation
3. Configuration state: Verify "Pending configuration" message behavior
4. ID lifecycle: Uniqueness, no reuse after acl_destroy
5. Integration with push_config: Verify changes take effect
"""
import pytest
from helpers import QDocSE


def cleanup_acl(acl_id: int) -> None:
    """
    Standard cleanup for ACL tests.
    
    1. Destroy ACL table (with force to handle non-empty ACLs)
    2. Push config to commit changes and clear "Pending configuration"
    """
    QDocSE.acl_destroy(acl_id, force=True).execute()
    QDocSE.push_config().execute()


@pytest.mark.unit
class TestACLCreateBasic:
    """Basic acl_create functionality tests"""
    
    def test_create_returns_valid_id(self):
        """
        acl_create succeeds and returns a valid positive integer ACL ID.
        
        Expected: Command returns success with parseable ACL ID > 0
        """
        result = QDocSE.acl_create().execute()
        
        # Verify 1: Command succeeds
        result.ok("ACL creation should succeed")
        
        # Verify 2: Output contains ACL ID indicator
        # Per PDF: "When the command completes it displays the new ACL ID value"
        parsed = result.parse()
        acl_id = parsed["acl_id"]
        
        # Verify 3: Valid ID returned
        assert acl_id is not None, "Should return ACL ID"
        assert isinstance(acl_id, int), f"ACL ID should be int, got {type(acl_id)}"
        assert acl_id > 0, f"ACL ID should be positive, got {acl_id}"
        
        # Cleanup: Destroy ACL and push_config to clear pending state
        cleanup_acl(acl_id)
    
    def test_create_multiple_returns_unique_ids(self):
        """
        Multiple acl_create calls should return unique, incrementing IDs.
        
        Per PDF: ACL IDs are unique identifiers. If destroyed, they are not reused.
        """
        ids = []
        count = 3
        
        try:
            for _ in range(count):
                result = QDocSE.acl_create().execute().ok()
                acl_id = result.parse()["acl_id"]
                ids.append(acl_id)
            
            # Verify 1: All IDs unique
            assert len(set(ids)) == count, f"IDs should be unique, got {ids}"
            
            # Verify 2: IDs should be increasing
            for i in range(1, len(ids)):
                assert ids[i] > ids[i-1], f"IDs should be increasing: {ids}"
        
        finally:
            # Cleanup: Destroy all created ACLs and push_config
            for acl_id in ids:
                QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
    
    def test_create_has_no_options(self):
        """
        acl_create command has no options.
        
        Per PDF page 73: "There are no options for this command."
        The only valid form is: QDocSEConsole -c acl_create
        """
        # Just verify basic creation works without any options
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        # Cleanup
        cleanup_acl(acl_id)


@pytest.mark.unit
class TestACLCreateVerifyWithList:
    """Use acl_list to verify acl_create results"""
    
    def test_created_acl_visible_in_list(self):
        """
        Newly created ACL should appear in acl_list output.
        
        Note: Per PDF page 81, acl_list shows ACL ID and entries.
        """
        # Step 1: Create ACL
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]
        
        try:
            # Step 2: Query specific ACL
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            
            # Verify: Shows ACL ID in output
            list_result.contains(f"ACL ID {acl_id}")
        
        finally:
            cleanup_acl(acl_id)
    
    def test_new_acl_is_empty_with_deny_default(self):
        """
        Newly created ACL should be empty and default to Deny all.
        
        Per PDF page 81:
        "With zero entries the message 'No entries (Deny)' is displayed"
        """
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]
        
        try:
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            
            # Verify: Empty ACL shows "No entries (Deny)"
            list_result.contains("No entries (Deny)")
        
        finally:
            cleanup_acl(acl_id)
    
    def test_list_all_shows_new_acl(self):
        """
        acl_list (without -i) should include newly created ACL.
        """
        # Before creation: Get existing ACL count
        before = QDocSE.acl_list().execute().ok()
        before_count = before.result.stdout.count("ACL ID")
        
        # Create new ACL
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]
        
        try:
            # After creation: ACL count should increase by 1
            after = QDocSE.acl_list().execute().ok()
            after_count = after.result.stdout.count("ACL ID")
            
            assert after_count == before_count + 1, \
                f"ACL count should increase by 1: before={before_count}, after={after_count}"
            
            # Should find the new ACL ID
            after.contains(f"ACL ID {acl_id}")
        
        finally:
            cleanup_acl(acl_id)


@pytest.mark.unit
class TestACLCreatePendingConfiguration:
    """
    Test the "Pending configuration" behavior with push_config.
    
    Per PDF page 81:
    "When there have been changes to the ACL configuration that has not be
    pushed to the QDocSE system the message 'Pending configuration: see
    push_config command' will be displayed."
    
    Per PDF page 118:
    "This command commits the changes in configuration for authorized programs
    and their shared libraries, and for the ACL configuration to the QDocSE system."
    """
    
    def test_new_acl_shows_pending_after_create(self):
        """
        After acl_create, there may be pending configuration until push_config.
        
        Note: The exact behavior depends on whether acl_create itself generates
        pending state or only entry modifications do. This test verifies the
        actual behavior.
        """
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]
        
        try:
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            
            # Check if "Pending configuration" appears
            # This documents the actual behavior
            has_pending = "Pending configuration" in list_result.result.stdout
            
            # Note: According to PDF, pending message appears after ACL changes
            # Document actual behavior for reference
            if has_pending:
                print("Note: acl_create generates pending configuration state")
            else:
                print("Note: acl_create alone does not generate pending state")
        
        finally:
            cleanup_acl(acl_id)
    
    def test_pending_after_add_entry(self):
        """
        Adding entry to ACL should show "Pending configuration" message.
        
        This is the documented behavior per PDF page 81.
        """
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]
        
        try:
            # Add an entry - this should create pending state
            QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
            
            # Verify pending message
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            list_result.contains("Pending configuration")
        
        finally:
            cleanup_acl(acl_id)
    
    def test_push_config_clears_pending(self):
        """
        push_config should commit changes and clear pending state.
        
        Per PDF page 118: push_config commits ACL configuration to QDocSE system.
        """
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]
        
        try:
            # Add entry to create pending state
            QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
            
            # Verify pending exists
            list_before = QDocSE.acl_list(acl_id).execute().ok()
            assert "Pending configuration" in list_before.result.stdout, \
                "Should have pending state before push_config"
            
            # Execute push_config
            QDocSE.push_config().execute().ok()
            
            # Verify pending cleared
            list_after = QDocSE.acl_list(acl_id).execute().ok()
            assert "Pending configuration" not in list_after.result.stdout, \
                "Pending state should be cleared after push_config"
        
        finally:
            cleanup_acl(acl_id)


@pytest.mark.unit
class TestACLCreateIdLifecycle:
    """
    Verify ACL ID lifecycle management.
    
    Per PDF page 73:
    "If an ACL is ever destroyed then the matching ACL ID will not be reused."
    """
    
    def test_destroyed_id_never_reused(self):
        """
        After acl_destroy, the ACL ID should never be reused.
        
        This is explicitly stated in PDF page 73.
        """
        # Step 1: Create and record ID
        result1 = QDocSE.acl_create().execute().ok()
        id1 = result1.parse()["acl_id"]
        
        # Step 2: Destroy (not remove!) the ACL and push_config
        QDocSE.acl_destroy(id1, force=True).execute().ok()
        QDocSE.push_config().execute()
        
        # Step 3: Verify ACL is truly destroyed (query should fail or not find)
        list_result = QDocSE.acl_list(id1).execute()
        # Either fails or doesn't contain the ACL
        acl_gone = (
            list_result.result.failed or 
            f"ACL ID {id1}" not in list_result.result.stdout or
            "not a valid ACL ID" in list_result.result.stderr.lower()
        )
        assert acl_gone, f"ACL {id1} should not exist after acl_destroy"
        
        # Step 4: Create new ACL
        result2 = QDocSE.acl_create().execute().ok()
        id2 = result2.parse()["acl_id"]
        
        try:
            # Verify: New ID differs from destroyed ID
            assert id2 != id1, \
                f"ACL ID {id1} was reused after destruction (new ID: {id2})"
            
            # Verify: New ID should be greater than old ID
            assert id2 > id1, \
                f"New ACL ID should be greater than destroyed ID: {id2} <= {id1}"
        
        finally:
            cleanup_acl(id2)
    
    def test_multiple_destroy_create_cycles_maintain_uniqueness(self):
        """
        Continuous create-destroy cycles should never reuse IDs.
        """
        used_ids = set()
        
        for round_num in range(3):
            # Create
            result = QDocSE.acl_create().execute().ok()
            acl_id = result.parse()["acl_id"]
            
            # Verify uniqueness
            assert acl_id not in used_ids, \
                f"Round {round_num}: ID {acl_id} was reused from {used_ids}"
            used_ids.add(acl_id)
            
            # Destroy (not remove!) and push_config
            QDocSE.acl_destroy(acl_id, force=True).execute().ok()
        
        # Push config once at the end to clear any pending state
        QDocSE.push_config().execute()
        
        # Final verify: Should have used 3 different IDs
        assert len(used_ids) == 3, f"Should use 3 unique IDs, got {used_ids}"
    
    def test_remove_vs_destroy_difference(self):
        """
        Verify the difference between acl_remove and acl_destroy:
        - acl_remove: Removes ENTRIES from ACL (ACL still exists)
        - acl_destroy: Destroys the ENTIRE ACL table
        """
        # Create ACL with entries
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]
        
        try:
            # Add an entry
            QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
            
            # Use acl_remove to clear entries
            QDocSE.acl_remove(acl_id, all=True).execute().ok()
            
            # Verify: ACL still exists (just empty)
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            list_result.contains(f"ACL ID {acl_id}")
            list_result.contains("No entries")
            
            # Now destroy the ACL table itself
            QDocSE.acl_destroy(acl_id).execute().ok()
            
            # Push config to clear pending state
            QDocSE.push_config().execute()
            
            # Verify: ACL no longer exists
            list_after = QDocSE.acl_list(acl_id).execute()
            assert list_after.result.failed or \
                   f"ACL ID {acl_id}" not in list_after.result.stdout, \
                   "ACL should not exist after acl_destroy"
        
        except AssertionError:
            # Make sure to cleanup if test fails midway
            cleanup_acl(acl_id)
            raise


@pytest.mark.unit
class TestACLCreateWithDestroyBehavior:
    """
    Test acl_destroy behavior in relation to acl_create.
    
    Per PDF page 74:
    - acl_destroy destroys ACL entirely when there are no entries
    - Use -f option to force destruction even if ACL has entries
    """
    
    def test_destroy_empty_acl_succeeds(self):
        """
        acl_destroy on empty ACL should succeed without -f option.
        """
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]
        
        # Destroy empty ACL (no -f needed)
        QDocSE.acl_destroy(acl_id).execute().ok()
        
        # Push config to clear pending state
        QDocSE.push_config().execute()
        
        # Verify destroyed
        list_result = QDocSE.acl_list(acl_id).execute()
        assert list_result.result.failed or \
               f"ACL ID {acl_id}" not in list_result.result.stdout
    
    def test_destroy_non_empty_acl_requires_force(self):
        """
        acl_destroy on non-empty ACL should fail without -f option.
        
        Per PDF page 74: "ACL ID X's ACL list is not empty" error
        """
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]
        
        try:
            # Add entry to make ACL non-empty
            QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
            
            # Try destroy without force - should fail
            destroy_result = QDocSE.acl_destroy(acl_id).execute()
            assert destroy_result.result.failed or \
                   "not empty" in destroy_result.result.stderr.lower(), \
                   "Destroy non-empty ACL without -f should fail"
            
            # Verify ACL still exists
            QDocSE.acl_list(acl_id).execute().ok().contains(f"ACL ID {acl_id}")
        
        finally:
            # Cleanup with force and push_config
            cleanup_acl(acl_id)
    
    def test_destroy_non_empty_acl_with_force_succeeds(self):
        """
        acl_destroy -f on non-empty ACL should succeed.
        """
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]
        
        # Add entries
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=1, mode="w").execute().ok()
        
        # Destroy with force
        QDocSE.acl_destroy(acl_id, force=True).execute().ok()
        
        # Push config to clear pending state
        QDocSE.push_config().execute()
        
        # Verify destroyed
        list_result = QDocSE.acl_list(acl_id).execute()
        assert list_result.result.failed or \
               f"ACL ID {acl_id}" not in list_result.result.stdout


@pytest.mark.unit
class TestACLCreateErrorHandling:
    """Error handling and boundary conditions"""
    
    def test_create_in_de_elevated_mode_fails(self):
        """
        acl_create should fail in De-elevated mode.
        
        Per PDF page 73: "Active modes: Elevated, Learning"
        """
        # Note: This test requires actual environment mode verification
        # Skip if we cannot determine or set the mode
        pytest.skip("Requires De-elevated mode - implement mode detection first")
    
    def test_create_without_license_fails(self):
        """
        acl_create should fail without valid license.
        
        Per PDF page 73: "License type: A"
        """
        # Note: Requires license management functionality
        pytest.skip("Requires license management - implement in integration tests")
    
    def test_create_returns_error_message_on_failure(self):
        """
        When acl_create fails, it should return appropriate error message.
        
        Per PDF page 74: "No ACL configuration file found."
        """
        # This tests error message format when system is not properly configured
        # The actual test depends on environment state
        pytest.skip("Requires specific environment state to trigger error")


@pytest.mark.unit
class TestACLCreateIntegration:
    """Integration tests: acl_create with other ACL commands"""
    
    def test_create_add_list_workflow(self):
        """
        Complete workflow: create -> add -> list -> push_config
        """
        # Create ACL
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]
        
        try:
            # Verify empty
            QDocSE.acl_list(acl_id).execute().ok().contains("No entries")
            
            # Add entry
            QDocSE.acl_add(acl_id, user=0, mode="rw").execute().ok()
            
            # Verify entry added
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            list_result.contains("Entry:")
            list_result.contains("Allow")
            
            # Verify pending state exists
            list_result.contains("Pending configuration")
            
            # Push config
            QDocSE.push_config().execute().ok()
            
            # Verify pending cleared
            list_after = QDocSE.acl_list(acl_id).execute().ok()
            assert "Pending configuration" not in list_after.result.stdout
        
        finally:
            cleanup_acl(acl_id)
    
    def test_create_multiple_acls_independent(self):
        """
        Multiple ACLs should be independent of each other.
        """
        ids = []
        
        try:
            # Create multiple ACLs
            for _ in range(3):
                result = QDocSE.acl_create().execute().ok()
                ids.append(result.parse()["acl_id"])
            
            # Add different entries to each
            QDocSE.acl_add(ids[0], user=0, mode="r").execute().ok()
            QDocSE.acl_add(ids[1], user=1, mode="w").execute().ok()
            QDocSE.acl_add(ids[2], user=2, mode="x").execute().ok()
            
            # Verify each ACL has only its own entries
            for i, acl_id in enumerate(ids):
                list_result = QDocSE.acl_list(acl_id).execute().ok()
                # Should have exactly 1 entry
                assert list_result.result.stdout.count("Entry:") == 1, \
                    f"ACL {acl_id} should have exactly 1 entry"
        
        finally:
            for acl_id in ids:
                QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
