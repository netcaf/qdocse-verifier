"""Adjust command tests"""
import pytest
from helpers import QDocSE

# Prerequisites (auto-checked)
pytestmark = [
    pytest.mark.requires_mode("elevated", "learning"),
    pytest.mark.requires_license("A"),
]


@pytest.mark.unit
class TestAdjust:
    """Authorized program adjustment tests."""
    
    def test_authorize_by_path(self):
        """Authorize by path."""
        QDocSE.adjust().auth_path("/bin/ls").execute()
    
    def test_block_by_path(self):
        """Block by path."""
        QDocSE.adjust().block_path("/tmp/malware").execute()