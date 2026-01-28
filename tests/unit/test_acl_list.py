"""
acl_list command tests.

Command description:
- List all ACLs or entries of a specific ACL
- Options: -i <acl_id> optional, specify ACL to display

Output format:
- "ACL ID <n>: No entries (Deny)" - Empty ACL
- "ACL ID <n>: Entry: <m> ..." - ACL with entries
- "Pending configuration: See push_config command." - Uncommitted changes

Test strategy:
1. Basic validation: exit code + output format
2. Verify list content with acl_create/acl_add
"""
import pytest
from helpers import QDocSE

# Prerequisites (auto-checked)
pytestmark = [
    pytest.mark.requires_mode("elevated", "learning"),
    pytest.mark.requires_license("A"),
]


def cleanup_acl(acl_id: int) -> None:
    """
    Standard cleanup for ACL tests.
    
    1. Destroy ACL table (with force to handle non-empty ACLs)
    2. Push config to commit changes and clear "Pending configuration"
    
    Note: acl_remove only removes ENTRIES, not the ACL table itself!
    """
    QDocSE.acl_destroy(acl_id, force=True).execute()
    QDocSE.push_config().execute()


@pytest.mark.unit
class TestACLListBasic:
    """Basic functionality tests."""
    
    def test_list_all(self):
        """List all ACLs."""
        # Create an ACL first to ensure content exists
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        try:
            # List all
            list_result = QDocSE.acl_list().execute().ok()
            list_result.contains(f"ACL ID {acl_id}")
        finally:
            # Cleanup: use acl_destroy (not acl_remove!)
            cleanup_acl(acl_id)
    
    def test_list_specific_acl(self):
        """List specific ACL."""
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        try:
            # List only this ACL
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            list_result.contains(f"ACL ID {acl_id}")
        finally:
            # Cleanup: use acl_destroy (not acl_remove!)
            cleanup_acl(acl_id)
    
    def test_empty_acl_shows_no_entries(self):
        """Empty ACL shows 'No entries (Deny)'."""
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        try:
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            list_result.contains("No entries (Deny)")
        finally:
            # Cleanup: use acl_destroy (not acl_remove!)
            cleanup_acl(acl_id)


@pytest.mark.unit
class TestACLListWithEntries:
    """List tests with entries."""
    
    def test_list_shows_entries(self, acl_id):
        """After adding entries, should display entry info."""
        # Add an entry
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        
        # Verify list
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        list_result.contains("Entry:")
        list_result.contains("Allow")  # Default is Allow
    
    def test_list_shows_multiple_entries(self, acl_id):
        """Multiple entries should all be displayed."""
        # Add multiple entries
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=1, mode="rw").execute().ok()
        QDocSE.acl_add(acl_id, allow=False, user=2, mode="w").execute().ok()
        
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        
        # Should have both Allow and Deny entries
        list_result.contains("Allow")
        list_result.contains("Deny")
    
    def test_list_shows_entry_numbers(self, acl_id):
        """Entries should have numbers."""
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=1, mode="w").execute().ok()
        
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        
        # Entry numbers start from 1
        list_result.contains("Entry: 1")
        list_result.contains("Entry: 2")


@pytest.mark.unit
class TestACLListPendingConfig:
    """Pending configuration message tests."""
    
    def test_shows_pending_message(self, acl_id):
        """After modification, should show pending message."""
        # Add entry (creates uncommitted configuration)
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        list_result.contains("Pending configuration")


@pytest.mark.unit
class TestACLListErrors:
    """Error handling tests."""
    
    def test_nonexistent_acl(self):
        """Query nonexistent ACL."""
        result = QDocSE.acl_list(999999).execute()
        # Decide fail() or check specific error message based on actual behavior
        # Assuming it fails here
        result.fail()
    
    def test_negative_acl_id(self):
        """Negative ACL ID."""
        result = QDocSE.acl_list(-1).execute()
        result.fail()