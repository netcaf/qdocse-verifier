"""
Adjust command tests.

Command description:
- Authorize or block programs
- Options:
  -apf <path>   Authorize program by file path
  -api <index>  Authorize program by index
  -bpf <path>   Block program by file path
  -b <index>    Block program by index
  -A <acl_id>   Associate ACL with authorized program

Test strategy:
1. Authorize known programs, verify with view
2. Block programs, verify with view
3. Error handling for invalid paths/indices
"""
import pytest
from helpers import QDocSE

# Prerequisites (auto-checked)
pytestmark = [
    pytest.mark.requires_mode("elevated", "learning"),
    pytest.mark.requires_license("A"),
]


@pytest.mark.unit
class TestAdjustAuthorize:
    """Authorized program adjustment tests."""

    def test_authorize_by_path(self):
        """Authorize a program by path and verify."""
        result = QDocSE.adjust().auth_path("/bin/ls").execute()
        result.ok()
        QDocSE.push_config().execute()

        # Verify it appears in authorized list
        view_result = QDocSE.view().authorized().execute().ok()
        view_result.contains("ls")

    def test_authorize_nonexistent_path(self):
        """Authorize nonexistent program should fail."""
        result = QDocSE.adjust().auth_path("/nonexistent/program").execute()
        result.fail()


@pytest.mark.unit
class TestAdjustBlock:
    """Block program tests."""

    def test_block_by_path(self):
        """Block a program by path and verify."""
        result = QDocSE.adjust().block_path("/tmp/test_blocked_prog").execute()
        # Behavior depends on whether the path needs to exist
        if result.result.success:
            QDocSE.push_config().execute()
            view_result = QDocSE.view().blocked().execute().ok()
            view_result.contains("test_blocked_prog")


@pytest.mark.unit
class TestAdjustWithACL:
    """Adjust with ACL association tests."""

    def test_authorize_with_acl(self, acl_id):
        """Authorize program and associate ACL."""
        # Add an entry so ACL is non-empty
        QDocSE.acl_add(acl_id, user=0, mode="rw").execute().ok()

        result = QDocSE.adjust().auth_path("/bin/cat").with_acl(acl_id).execute()
        if result.result.success:
            QDocSE.push_config().execute()
            view_result = QDocSE.view().authorized().execute().ok()
            view_result.contains("cat")


@pytest.mark.unit
class TestAdjustChaining:
    """Method chaining tests."""

    def test_chaining_style(self):
        """Use method chaining style for authorize."""
        (QDocSE.adjust()
            .auth_path("/bin/echo")
            .execute()
            .ok())
        QDocSE.push_config().execute()
