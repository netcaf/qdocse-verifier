"""
acl_create command tests.

Key points (PDF p73-74):
- Creates empty ACL with new ID
- IDs are never reused after destruction
- Active modes: Elevated, Learning
- License type: A
"""
import pytest
from helpers import QDocSE


def cleanup_acl(acl_id: int) -> None:
    """Destroy ACL and commit changes."""
    QDocSE.acl_destroy(acl_id, force=True).execute()
    QDocSE.push_config().execute()


@pytest.mark.unit
class TestACLCreateBasic:
    """Basic acl_create functionality."""

    def test_create_returns_valid_id(self):
        """Create succeeds with valid positive integer ID."""
        result = QDocSE.acl_create().execute().ok("ACL creation should succeed")
        acl_id = result.parse()["acl_id"]

        assert acl_id is not None, "Should return ACL ID"
        assert isinstance(acl_id, int), f"ACL ID should be int, got {type(acl_id)}"
        assert acl_id > 0, f"ACL ID should be positive, got {acl_id}"

        cleanup_acl(acl_id)

    def test_create_multiple_returns_unique_ids(self):
        """Multiple creates return unique, incrementing IDs."""
        ids = []
        try:
            for _ in range(3):
                result = QDocSE.acl_create().execute().ok()
                ids.append(result.parse()["acl_id"])

            assert len(set(ids)) == 3, f"IDs should be unique, got {ids}"
            for i in range(1, len(ids)):
                assert ids[i] > ids[i-1], f"IDs should be increasing: {ids}"
        finally:
            for acl_id in ids:
                QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()


@pytest.mark.unit
class TestACLCreateVerifyWithList:
    """Verify acl_create with acl_list."""

    def test_created_acl_visible_in_list(self):
        """New ACL appears in acl_list output."""
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]

        try:
            QDocSE.acl_list(acl_id).execute().ok().contains(f"ACL ID {acl_id}")
        finally:
            cleanup_acl(acl_id)

    def test_new_acl_is_empty_with_deny_default(self):
        """New ACL is empty and defaults to Deny all."""
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]

        try:
            QDocSE.acl_list(acl_id).execute().ok().contains("No entries (Deny)")
        finally:
            cleanup_acl(acl_id)

    def test_list_all_shows_new_acl(self):
        """acl_list (all) includes newly created ACL."""
        before_count = QDocSE.acl_list().execute().ok().result.stdout.count("ACL ID")

        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]

        try:
            after = QDocSE.acl_list().execute().ok()
            after_count = after.result.stdout.count("ACL ID")
            assert after_count == before_count + 1
            after.contains(f"ACL ID {acl_id}")
        finally:
            cleanup_acl(acl_id)


@pytest.mark.unit
class TestACLCreatePendingConfiguration:
    """Test pending configuration behavior with push_config."""

    def test_pending_after_add_entry(self):
        """Adding entry shows 'Pending configuration' message."""
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]

        try:
            QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
            QDocSE.acl_list(acl_id).execute().ok().contains("Pending configuration")
        finally:
            cleanup_acl(acl_id)

    def test_push_config_clears_pending(self):
        """push_config commits changes and clears pending state."""
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]

        try:
            QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
            assert "Pending configuration" in QDocSE.acl_list(acl_id).execute().ok().result.stdout

            QDocSE.push_config().execute().ok()
            assert "Pending configuration" not in QDocSE.acl_list(acl_id).execute().ok().result.stdout
        finally:
            cleanup_acl(acl_id)


@pytest.mark.unit
class TestACLCreateIdLifecycle:
    """ACL ID lifecycle: IDs are never reused after destruction."""

    def test_destroyed_id_never_reused(self):
        """Destroyed ACL ID is never reused."""
        result1 = QDocSE.acl_create().execute().ok()
        id1 = result1.parse()["acl_id"]

        QDocSE.acl_destroy(id1, force=True).execute().ok()
        QDocSE.push_config().execute()

        list_result = QDocSE.acl_list(id1).execute()
        acl_gone = (
            list_result.result.failed or
            f"ACL ID {id1}" not in list_result.result.stdout or
            "not a valid ACL ID" in list_result.result.stderr.lower()
        )
        assert acl_gone, f"ACL {id1} should not exist after destroy"

        result2 = QDocSE.acl_create().execute().ok()
        id2 = result2.parse()["acl_id"]

        try:
            assert id2 != id1, f"ID {id1} was reused"
            assert id2 > id1, f"New ID should be greater: {id2} <= {id1}"
        finally:
            cleanup_acl(id2)

    def test_multiple_destroy_create_cycles_maintain_uniqueness(self):
        """Create-destroy cycles never reuse IDs."""
        used_ids = set()

        for _ in range(3):
            result = QDocSE.acl_create().execute().ok()
            acl_id = result.parse()["acl_id"]

            assert acl_id not in used_ids, f"ID {acl_id} was reused from {used_ids}"
            used_ids.add(acl_id)

            QDocSE.acl_destroy(acl_id, force=True).execute().ok()

        QDocSE.push_config().execute()
        assert len(used_ids) == 3

    def test_remove_vs_destroy_difference(self):
        """acl_remove removes entries; acl_destroy deletes entire ACL."""
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]

        try:
            QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
            QDocSE.acl_remove(acl_id, all=True).execute().ok()

            # ACL still exists (just empty)
            result = QDocSE.acl_list(acl_id).execute().ok()
            result.contains(f"ACL ID {acl_id}")
            result.contains("No entries")

            # Now destroy
            QDocSE.acl_destroy(acl_id).execute().ok()
            QDocSE.push_config().execute()

            # ACL no longer exists
            list_after = QDocSE.acl_list(acl_id).execute()
            assert list_after.result.failed or f"ACL ID {acl_id}" not in list_after.result.stdout
        except AssertionError:
            cleanup_acl(acl_id)
            raise


@pytest.mark.unit
class TestACLCreateWithDestroyBehavior:
    """acl_destroy behavior tests."""

    def test_destroy_empty_acl_succeeds(self):
        """Destroy empty ACL succeeds without -f."""
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]

        QDocSE.acl_destroy(acl_id).execute().ok()
        QDocSE.push_config().execute()

        list_result = QDocSE.acl_list(acl_id).execute()
        assert list_result.result.failed or f"ACL ID {acl_id}" not in list_result.result.stdout

    def test_destroy_non_empty_acl_requires_force(self):
        """Destroy non-empty ACL fails without -f."""
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]

        try:
            QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()

            destroy_result = QDocSE.acl_destroy(acl_id).execute()
            assert destroy_result.result.failed or "not empty" in destroy_result.result.stderr.lower()

            QDocSE.acl_list(acl_id).execute().ok().contains(f"ACL ID {acl_id}")
        finally:
            cleanup_acl(acl_id)

    def test_destroy_non_empty_acl_with_force_succeeds(self):
        """Destroy non-empty ACL succeeds with -f."""
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=1, mode="w").execute().ok()

        QDocSE.acl_destroy(acl_id, force=True).execute().ok()
        QDocSE.push_config().execute()

        list_result = QDocSE.acl_list(acl_id).execute()
        assert list_result.result.failed or f"ACL ID {acl_id}" not in list_result.result.stdout


@pytest.mark.unit
class TestACLCreateErrorHandling:
    """Error handling tests."""

    def test_create_in_de_elevated_mode_fails(self):
        """acl_create fails in De-elevated mode."""
        pytest.skip("Requires De-elevated mode setup")

    def test_create_without_license_fails(self):
        """acl_create fails without valid license."""
        pytest.skip("Requires license management")


@pytest.mark.unit
class TestACLCreateIntegration:
    """Integration with other ACL commands."""

    def test_create_add_list_workflow(self):
        """Complete workflow: create -> add -> list -> push_config."""
        create_result = QDocSE.acl_create().execute().ok()
        acl_id = create_result.parse()["acl_id"]

        try:
            QDocSE.acl_list(acl_id).execute().ok().contains("No entries")
            QDocSE.acl_add(acl_id, user=0, mode="rw").execute().ok()

            list_result = QDocSE.acl_list(acl_id).execute().ok()
            list_result.contains("Entry:")
            list_result.contains("Allow")
            list_result.contains("Pending configuration")

            QDocSE.push_config().execute().ok()
            assert "Pending configuration" not in QDocSE.acl_list(acl_id).execute().ok().result.stdout
        finally:
            cleanup_acl(acl_id)

    def test_create_multiple_acls_independent(self):
        """Multiple ACLs are independent of each other."""
        ids = []

        try:
            for _ in range(3):
                result = QDocSE.acl_create().execute().ok()
                ids.append(result.parse()["acl_id"])

            QDocSE.acl_add(ids[0], user=0, mode="r").execute().ok()
            QDocSE.acl_add(ids[1], user=1, mode="w").execute().ok()
            QDocSE.acl_add(ids[2], user=2, mode="x").execute().ok()

            for acl_id in ids:
                result = QDocSE.acl_list(acl_id).execute().ok()
                assert result.result.stdout.count("Entry:") == 1
        finally:
            for acl_id in ids:
                QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
