"""ACL Denied Access Scenarios"""
import pytest
import os
from pathlib import Path
from helpers import QDocSE
from conftest import apply_acl


class TestDeniedByEmptyACL:
    """Empty ACL denies all by default"""

    def test_empty_acl_denies_read(self, protected_dir, empty_acl):
        apply_acl(protected_dir, empty_acl)

        with pytest.raises(PermissionError):
            Path(protected_dir, "test.txt").read_text()

    def test_empty_acl_denies_write(self, protected_dir, empty_acl):
        apply_acl(protected_dir, empty_acl)

        with pytest.raises(PermissionError):
            Path(protected_dir, "new.txt").write_text("fail")


class TestDeniedByExplicitDeny:
    """Explicit Deny entry denies access"""

    def test_explicit_deny_blocks_read(self, protected_dir, deny_acl):
        apply_acl(protected_dir, deny_acl)

        with pytest.raises(PermissionError):
            Path(protected_dir, "test.txt").read_text()

    def test_explicit_deny_blocks_write(self, protected_dir, deny_acl):
        apply_acl(protected_dir, deny_acl)

        with pytest.raises(PermissionError):
            Path(protected_dir, "test.txt").write_text("fail")


class TestDeniedByNoMatch:
    """Denied when no matching entry"""

    def test_other_user_only_denies_current(self, protected_dir, request):
        """ACL only allows other user"""
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=65534, mode="rw").execute()  # nobody

        try:
            apply_acl(protected_dir, acl_id)
            with pytest.raises(PermissionError):
                Path(protected_dir, "test.txt").read_text()
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
