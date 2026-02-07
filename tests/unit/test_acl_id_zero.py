"""
ACL ID 0 reserved behavior tests.

Per PDF documentation:
"When the ACL ID is not specified then this is the equivalent of
fixed, built-in ACL ID 0 (zero) which has an 'allow access' setting."

ACL ID 0 is built-in and cannot be modified by any ACL command.
"""
import pytest
from helpers import QDocSE

# All tests in this file require these conditions (auto-checked)
pytestmark = [
    pytest.mark.requires_mode("elevated", "learning"),
    pytest.mark.requires_license("A"),
]


@pytest.mark.unit
class TestACLIDZeroReserved:
    """ACL ID 0 is built-in and cannot be modified."""

    def test_acl_zero_is_builtin_allow(self):
        """ACL ID 0 exists as built-in 'allow access' default."""
        result = QDocSE.acl_list(0).execute()
        assert result.result.success or "built-in" in result.result.stdout.lower()

    def test_cannot_add_entry_to_acl_zero(self):
        """acl_add to ACL ID 0 should fail."""
        result = QDocSE.acl_add(0, user=0, mode="r").execute()
        assert result.result.failed, "Should not allow adding to built-in ACL 0"

    def test_cannot_destroy_acl_zero(self):
        """acl_destroy ACL ID 0 should fail."""
        result = QDocSE.acl_destroy(0).execute()
        assert result.result.failed, "Should not allow destroying built-in ACL 0"

    def test_cannot_destroy_acl_zero_with_force(self):
        """acl_destroy ACL ID 0 with -f should also fail."""
        result = QDocSE.acl_destroy(0, force=True).execute()
        assert result.result.failed, "Should not allow destroying built-in ACL 0 even with force"

    def test_cannot_edit_acl_zero(self):
        """acl_edit ACL ID 0 should fail."""
        result = QDocSE.acl_edit(0, entry=0, position=1).execute()
        assert result.result.failed, "Should not allow editing built-in ACL 0"

    def test_cannot_remove_from_acl_zero(self):
        """acl_remove from ACL ID 0 should fail."""
        result = QDocSE.acl_remove(0, entry=0).execute()
        assert result.result.failed, "Should not allow removing from built-in ACL 0"

    def test_user_created_acl_id_always_greater_than_zero(self):
        """acl_create always returns ID > 0 (0 is reserved)."""
        ids = []
        try:
            for _ in range(5):
                result = QDocSE.acl_create().execute().ok()
                acl_id = result.parse()["acl_id"]
                assert acl_id > 0, f"User-created ACL ID must be > 0, got {acl_id}"
                ids.append(acl_id)
        finally:
            for acl_id in ids:
                QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
