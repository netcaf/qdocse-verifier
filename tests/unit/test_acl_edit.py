"""
acl_edit command tests.

Command description:
- Edit ACL entry order/position
- Options:
  -i <acl_id>    Specify ACL ID
  -e <entry>     Entry number to move
  -p <position>  Target position (number, "first", "last")

Test strategy:
1. Basic validation: exit code
2. Verify entry order change with acl_list

Note: ACL entry order matters - first matching rule takes priority
"""
import pytest
from helpers import QDocSE

# Prerequisites (auto-checked)
pytestmark = [
    pytest.mark.requires_mode("elevated", "learning"),
    pytest.mark.requires_license("A"),
]


@pytest.fixture
def acl_with_three_entries(acl_id):
    """Create ACL with 3 entries for move testing."""
    # Entry 1: user 100
    QDocSE.acl_add(acl_id, user=100, mode="r").execute().ok()
    # Entry 2: user 200
    QDocSE.acl_add(acl_id, user=200, mode="w").execute().ok()
    # Entry 3: user 300
    QDocSE.acl_add(acl_id, user=300, mode="x").execute().ok()
    return acl_id


@pytest.mark.unit
class TestACLEditPosition:
    """Entry position adjustment tests."""
    
    def test_move_to_first(self, acl_with_three_entries):
        """Move entry to first position."""
        acl_id = acl_with_three_entries
        
        # Move entry 3 (user 300) to first position
        QDocSE.acl_edit(acl_id, entry=3, position="first").execute().ok()
        
        # Verify: user 300 should now be first
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        stdout = list_result.result.stdout
        
        # 300 should appear before 100 and 200
        pos_300 = stdout.find("300")
        pos_100 = stdout.find("100")
        pos_200 = stdout.find("200")
        assert pos_300 < pos_100, "Entry 300 should be first"
        assert pos_300 < pos_200, "Entry 300 should be before 200"
    
    def test_move_to_last(self, acl_with_three_entries):
        """Move entry to last position."""
        acl_id = acl_with_three_entries
        
        # Move entry 1 (user 100) to last position
        QDocSE.acl_edit(acl_id, entry=1, position="last").execute().ok()
        
        # Verify: user 100 should now be last
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        stdout = list_result.result.stdout
        
        pos_100 = stdout.find("100")
        pos_200 = stdout.find("200")
        pos_300 = stdout.find("300")
        assert pos_100 > pos_200, "Entry 100 should be after 200"
        assert pos_100 > pos_300, "Entry 100 should be last"
    
    def test_move_to_specific_position(self, acl_with_three_entries):
        """Move entry to specific position."""
        acl_id = acl_with_three_entries
        
        # Move entry 3 to position 2
        QDocSE.acl_edit(acl_id, entry=3, position=2).execute().ok()
        
        # Verify order becomes: 100, 300, 200
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        stdout = list_result.result.stdout
        
        pos_100 = stdout.find("100")
        pos_300 = stdout.find("300")
        pos_200 = stdout.find("200")
        assert pos_100 < pos_300 < pos_200, "Order should be 100, 300, 200"


@pytest.mark.unit
class TestACLEditSamePosition:
    """Move to same position (no-op)."""
    
    def test_move_to_same_position(self, acl_with_three_entries):
        """Move to current position should succeed (idempotent)."""
        acl_id = acl_with_three_entries
        
        # Move entry 2 to position 2
        QDocSE.acl_edit(acl_id, entry=2, position=2).execute().ok()
        
        # Order should remain unchanged
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        stdout = list_result.result.stdout
        
        pos_100 = stdout.find("100")
        pos_200 = stdout.find("200")
        pos_300 = stdout.find("300")
        assert pos_100 < pos_200 < pos_300, "Order should remain unchanged"


@pytest.mark.unit
class TestACLEditErrors:
    """Error handling tests."""
    
    def test_nonexistent_entry(self, acl_id):
        """Move nonexistent entry should fail."""
        QDocSE.acl_edit(acl_id, entry=999, position=1).execute().fail()
    
    def test_invalid_position(self, acl_with_three_entries):
        """Invalid target position should fail."""
        acl_id = acl_with_three_entries
        QDocSE.acl_edit(acl_id, entry=1, position=999).execute().fail()
    
    def test_negative_entry(self, acl_id):
        """Negative entry number should fail."""
        QDocSE.acl_edit(acl_id, entry=-1, position=1).execute().fail()
    
    def test_negative_position(self, acl_with_three_entries):
        """Negative position should fail."""
        acl_id = acl_with_three_entries
        QDocSE.acl_edit(acl_id, entry=1, position=-1).execute().fail()
    
    def test_nonexistent_acl(self):
        """Nonexistent ACL should fail."""
        QDocSE.acl_edit(999999, entry=1, position=1).execute().fail()


@pytest.mark.unit
class TestACLEditChaining:
    """Method chaining tests."""
    
    def test_chaining_style(self, acl_with_three_entries):
        """Use method chaining style."""
        acl_id = acl_with_three_entries
        
        (QDocSE.acl_edit()
            .acl_id(acl_id)
            .entry(3)
            .position("first")
            .execute()
            .ok())