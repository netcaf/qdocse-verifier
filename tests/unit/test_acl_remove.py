"""
acl_remove command tests.

Command description:
- Remove entries from ACL
- Options:
  -i <acl_id>   Specify ACL ID
  -e <entry>    Remove entry by number
  -A            Remove all entries (clear ACL)
  -a            Remove only Allow entries
  -d            Remove only Deny entries
  -u <uid>      Remove entries for specific user
  -g <gid>      Remove entries for specific group

Test strategy:
1. Basic validation: exit code
2. Verify entry removal with acl_list
"""
import pytest
from helpers import QDocSE

# Prerequisites (auto-checked)
pytestmark = [
    pytest.mark.requires_mode("elevated", "learning"),
    pytest.mark.requires_license("A"),
]


@pytest.mark.unit
class TestACLRemoveByEntry:
    """Remove by entry number."""
    
    def test_remove_single_entry(self, acl_id):
        """Remove single entry."""
        # Add entry
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        
        # Verify exists
        QDocSE.acl_list(acl_id).execute().ok().contains("Entry: 1")
        
        # Remove
        QDocSE.acl_remove(acl_id, entry=1).execute().ok()
        
        # Verify removed
        QDocSE.acl_list(acl_id).execute().ok().contains("No entries")
    
    def test_remove_middle_entry(self, acl_id):
        """Remove middle entry."""
        # Add 3 entries
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=1, mode="w").execute().ok()
        QDocSE.acl_add(acl_id, user=2, mode="x").execute().ok()
        
        # Remove entry 2
        QDocSE.acl_remove(acl_id, entry=2).execute().ok()
        
        # Verify: should have 2 entries remaining
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        list_result.contains("Entry: 1")
        list_result.contains("Entry: 2")  # Original entry 3 becomes entry 2
    
    def test_remove_nonexistent_entry(self, acl_id):
        """Remove nonexistent entry should fail."""
        QDocSE.acl_remove(acl_id, entry=999).execute().fail()


@pytest.mark.unit
class TestACLRemoveAll:
    """Remove all entries."""
    
    def test_remove_all_entries(self, acl_id):
        """Clear all entries."""
        # Add multiple entries
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=1, mode="w").execute().ok()
        QDocSE.acl_add(acl_id, user=2, mode="x").execute().ok()
        
        # Remove all
        QDocSE.acl_remove(acl_id, all=True).execute().ok()
        
        # Verify cleared
        QDocSE.acl_list(acl_id).execute().ok().contains("No entries")
    
    def test_remove_all_from_empty_acl(self, acl_id):
        """Clear already empty ACL."""
        # Remove all on empty ACL should succeed (idempotent)
        QDocSE.acl_remove(acl_id, all=True).execute().ok()


@pytest.mark.unit
class TestACLRemoveByType:
    """Remove by type (Allow/Deny)."""
    
    def test_remove_allow_only(self, acl_id):
        """Remove only Allow entries."""
        # Add Allow and Deny entries
        QDocSE.acl_add(acl_id, allow=True, user=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, allow=False, user=1, mode="w").execute().ok()
        
        # Remove all Allow
        QDocSE.acl_remove(acl_id).allow().execute().ok()
        
        # Verify: only Deny remains
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        assert "Allow" not in list_result.result.stdout
        list_result.contains("Deny")
    
    def test_remove_deny_only(self, acl_id):
        """Remove only Deny entries."""
        # Add Allow and Deny entries
        QDocSE.acl_add(acl_id, allow=True, user=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, allow=False, user=1, mode="w").execute().ok()
        
        # Remove all Deny
        QDocSE.acl_remove(acl_id).deny().execute().ok()
        
        # Verify: only Allow remains
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        list_result.contains("Allow")
        assert "Deny" not in list_result.result.stdout or "No entries (Deny)" in list_result.result.stdout


@pytest.mark.unit
class TestACLRemoveBySubject:
    """Remove by subject."""
    
    def test_remove_by_user(self, acl_id):
        """Remove entries for specific user."""
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=1, mode="w").execute().ok()
        
        # Remove user 0's entries
        QDocSE.acl_remove(acl_id).user("0").execute().ok()
        
        # Verify: only user 1 remains
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        list_result.contains("Entry:")  # Still has entries
    
    def test_remove_by_group(self, acl_id):
        """Remove entries for specific group."""
        QDocSE.acl_add(acl_id, group=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, group=1, mode="w").execute().ok()
        
        # Remove group 0's entries
        QDocSE.acl_remove(acl_id).group("0").execute().ok()
        
        # Verify
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        list_result.contains("Entry:")


@pytest.mark.unit
class TestACLRemoveErrors:
    """Error handling."""
    
    def test_nonexistent_acl(self):
        """Nonexistent ACL."""
        QDocSE.acl_remove(999999, entry=1).execute().fail()
    
    def test_negative_acl_id(self):
        """Negative ACL ID."""
        QDocSE.acl_remove(-1, entry=1).execute().fail()
    
    def test_negative_entry(self, acl_id):
        """Negative entry number."""
        QDocSE.acl_remove(acl_id, entry=-1).execute().fail()


@pytest.mark.unit
class TestACLRemoveChaining:
    """Method chaining."""
    
    def test_chaining_style(self, acl_id):
        """Use method chaining."""
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        
        (QDocSE.acl_remove()
            .acl_id(acl_id)
            .entry(1)
            .execute()
            .ok())
        
        QDocSE.acl_list(acl_id).execute().ok().contains("No entries")