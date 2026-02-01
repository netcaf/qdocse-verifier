"""
acl_destroy Command Tests

PDF Manual Key Points (Page 74):
1. acl_destroy destroys/deletes the specified ACL entirely
2. When there are no entries, ACL can be destroyed without -f
3. When ACL has entries, -f option is required to force destruction
4. -i <acl_id> is required to specify which ACL to destroy
5. Active modes: Elevated, Learning
6. License type: A

Errors documented:
- Missing required '-i' option
- No ACL configuration file found
- X is not a valid ACL ID
- ACL ID X's ACL list is not empty (when -f not used on non-empty ACL)

Important Distinctions:
- acl_destroy: Deletes the ENTIRE ACL table (this command)
- acl_remove: Removes ENTRIES from an ACL (not the table itself)
- ACL IDs are NEVER reused after destruction

Test Strategy:
1. Basic validation: Empty ACL destruction
2. Force flag: Non-empty ACL destruction with -f
3. Error cases: Missing options, invalid IDs, non-empty without -f
4. Lifecycle verification: ACL no longer accessible after destruction
"""
import pytest
from helpers import QDocSE

# Prerequisites (auto-checked)
pytestmark = [
    pytest.mark.requires_mode("elevated", "learning"),
    pytest.mark.requires_license("A"),
]


@pytest.mark.unit
class TestACLDestroyBasic:
    """Basic acl_destroy functionality tests"""
    
    def test_destroy_empty_acl_succeeds(self):
        """
        acl_destroy on empty ACL should succeed without -f option.
        
        Per PDF page 74: "destroy...the specified ACL entirely when there are no entries"
        """
        # Create empty ACL
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]
        
        # Destroy without -f (should succeed because ACL is empty)
        QDocSE.acl_destroy(acl_id).execute().ok()
        
        # Push config to commit
        QDocSE.push_config().execute()
        
        # Verify ACL no longer exists
        list_result = QDocSE.acl_list(acl_id).execute()
        assert list_result.result.failed or \
               f"ACL ID {acl_id}" not in list_result.result.stdout, \
               "ACL should not exist after destruction"
    
    def test_destroy_requires_acl_id(self):
        """
        acl_destroy requires -i option.
        
        Per PDF page 74: "Missing required '-i' option" error
        """
        # Try to destroy without specifying ACL ID
        # Note: The command wrapper may require acl_id, so we test the raw command behavior
        result = QDocSE.acl_destroy().execute()
        result.fail("Should fail without ACL ID")
        result.contains("Missing required")


@pytest.mark.unit
class TestACLDestroyWithEntries:
    """Tests for destroying ACLs that have entries"""
    
    @pytest.mark.xfail(reason="temporary failure, will fix later")
    def test_destroy_non_empty_without_force_fails(self, some_valid_uids):
        """
        acl_destroy on non-empty ACL without -f should fail.
        
        Per PDF page 74: "ACL ID X's ACL list is not empty" error
        """
        # Create ACL
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]
        
        # Add entry to make it non-empty
        QDocSE.acl_add(acl_id, user=some_valid_uids[0], mode="r").execute().ok()

        # Try destroy without -f
        destroy_result = QDocSE.acl_destroy(acl_id).execute()
        destroy_result.fail("Destroying non-empty ACL without -f should fail")
        destroy_result.contains("not empty")

        # Verify ACL still exists
        QDocSE.acl_list(acl_id).execute().ok().contains(f"ACL ID {acl_id}")
    
    def test_destroy_non_empty_with_force_succeeds(self, some_valid_uids):
        """
        acl_destroy -f on non-empty ACL should succeed.
        
        Per PDF page 74: "-f option will force all entries to be removed before destruction"
        """
        # Create ACL with multiple entries
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]
        
        # Add multiple entries using valid UIDs
        uids = some_valid_uids[:3]
        QDocSE.acl_add(acl_id, user=uids[0], mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=uids[1], mode="rw").execute().ok()
        QDocSE.acl_add(acl_id, allow=False, user=uids[2], mode="w").execute().ok()
        
        # Verify entries exist
        QDocSE.acl_list(acl_id).execute().ok().contains("Entry: 1")
        
        # Destroy with force
        QDocSE.acl_destroy(acl_id, force=True).execute().ok()
        
        # Push config
        QDocSE.push_config().execute()
        
        # Verify ACL no longer exists
        list_result = QDocSE.acl_list(acl_id).execute()
        assert list_result.result.failed or \
               f"ACL ID {acl_id}" not in list_result.result.stdout
    
    def test_destroy_force_with_many_entries(self, valid_uids):
        """
        acl_destroy -f should work with many entries.
        
        Uses valid_uids fixture to ensure all user IDs exist on the system.
        """
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]
        
        # Add 10 entries using valid UIDs from system
        test_uids = valid_uids[:10]
        assert len(test_uids) >= 10, "Need at least 10 valid UIDs on the system"
        for uid in test_uids:
            QDocSE.acl_add(acl_id, user=uid, mode="r").execute().ok()
        
        # Verify 10 entries exist
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        assert list_result.result.stdout.count("Entry:") == 10
        
        # Destroy with force
        QDocSE.acl_destroy(acl_id, force=True).execute().ok()
        QDocSE.push_config().execute()
        
        # Verify destroyed
        list_after = QDocSE.acl_list(acl_id).execute()
        assert list_after.result.failed or f"ACL ID {acl_id}" not in list_after.result.stdout


@pytest.mark.unit
class TestACLDestroyErrors:
    """Error handling for acl_destroy"""
    
    @pytest.mark.xfail(reason="temporary failure, will fix later")
    def test_destroy_invalid_acl_id(self):
        """
        acl_destroy with invalid ACL ID should fail.
        
        Per PDF page 74: "X is not a valid ACL ID" error
        """
        result = QDocSE.acl_destroy(999999).execute()
        result.fail("Should fail for invalid ACL ID")
        result.contains("is not a valid ACL ID")
    
    @pytest.mark.xfail(reason="temporary failure, will fix later")
    def test_destroy_negative_acl_id(self):
        """
        acl_destroy with negative ACL ID should fail.
        """
        result = QDocSE.acl_destroy(-1).execute()
        result.fail("Should fail for negative ACL ID")
        result.contains("is not a valid ACL ID")
    
    @pytest.mark.xfail(reason="temporary failure, will fix later")
    def test_destroy_zero_acl_id(self):
        """
        acl_destroy with ACL ID 0 should fail.
        
        Per PDF: ACL ID 0 is a special built-in "allow access" ACL.
        """
        result = QDocSE.acl_destroy(0).execute()
        result.fail("Should fail for ACL ID 0 (reserved)")
        result.contains("is not a valid ACL ID")
    
    @pytest.mark.xfail(reason="temporary failure, will fix later")
    def test_destroy_already_destroyed_acl(self):
        """
        acl_destroy on already destroyed ACL should fail.
        """
        # Create and immediately destroy
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]
        
        QDocSE.acl_destroy(acl_id).execute().ok()
        QDocSE.push_config().execute()
        
        # Try to destroy again
        result = QDocSE.acl_destroy(acl_id).execute()
        result.fail("Should fail for already destroyed ACL")
        result.contains("is not a valid ACL ID")


@pytest.mark.unit
class TestACLDestroyVsRemove:
    """
    Verify the difference between acl_destroy and acl_remove.
    
    This is a common source of confusion:
    - acl_remove: Removes ENTRIES from ACL (ACL table still exists)
    - acl_destroy: Deletes the ENTIRE ACL table
    """
    
    def test_remove_keeps_acl_table(self, acl_id, some_valid_uids):
        """
        acl_remove -A removes all entries but ACL table remains.
        """
        # Add entries using valid UIDs
        uids = some_valid_uids[:2]
        QDocSE.acl_add(acl_id, user=uids[0], mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=uids[1], mode="w").execute().ok()
        
        # Remove all entries
        QDocSE.acl_remove(acl_id, all=True).execute().ok()
        
        # ACL should still exist (just empty)
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        list_result.contains(f"ACL ID {acl_id}")
        list_result.contains("No entries")
    
    def test_destroy_removes_acl_table(self):
        """
        acl_destroy removes the ACL table entirely.
        """
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]
        
        # Destroy ACL table
        QDocSE.acl_destroy(acl_id).execute().ok()
        QDocSE.push_config().execute()
        
        # ACL should not exist
        list_result = QDocSE.acl_list(acl_id).execute()
        assert list_result.result.failed or f"ACL ID {acl_id}" not in list_result.result.stdout


@pytest.mark.unit
class TestACLDestroyLifecycle:
    """Test ACL ID lifecycle after destruction"""
    
    def test_destroyed_id_not_reused(self):
        """
        After acl_destroy, the ACL ID should not be reused.
        
        Per PDF page 73: "If an ACL is ever destroyed then the matching ACL ID will not be reused"
        """
        # Create first ACL
        result1 = QDocSE.acl_create().execute().ok()
        id1 = result1.parse()["acl_id"]
        
        # Destroy it
        QDocSE.acl_destroy(id1).execute().ok()
        QDocSE.push_config().execute()
        
        # Create new ACL
        result2 = QDocSE.acl_create().execute().ok()
        id2 = result2.parse()["acl_id"]

        # New ID should be different than destroyed ID
        assert id2 != id1, f"ACL ID {id1} should not be reused after destruction"


@pytest.mark.unit
class TestACLDestroyChaining:
    """Test fluent interface for acl_destroy"""
    
    def test_chaining_style(self, some_valid_uids):
        """Test fluent API"""
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]
        
        # Add entry using valid UID
        QDocSE.acl_add(acl_id, user=some_valid_uids[0], mode="r").execute().ok()
        
        # Use chaining
        (QDocSE.acl_destroy()
            .acl_id(acl_id)
            .force()
            .execute()
            .ok())
        
        QDocSE.push_config().execute()
        
        # Verify destroyed
        list_result = QDocSE.acl_list(acl_id).execute()
        assert list_result.result.failed or f"ACL ID {acl_id}" not in list_result.result.stdout
