"""ACL fixtures with auto-cleanup."""
import pytest
from helpers import QDocSE
from helpers.system import get_valid_uids, get_valid_gids


def _cleanup_acl(acl_id):
    """Destroy ACL and commit changes."""
    QDocSE.acl_destroy(acl_id, force=True).execute()
    QDocSE.push_config().execute()


# =============================================================================
# System User/Group Fixtures
# =============================================================================

@pytest.fixture
def valid_uids():
    """
    Provide list of valid UIDs that exist on the system.
    
    Returns at least 10 UIDs, or skips test if not enough users exist.
    """
    uids = get_valid_uids()
    if len(uids) < 10:
        pytest.skip(f"Need at least 10 users, only {len(uids)} found on system")
    return uids


@pytest.fixture
def valid_gids():
    """
    Provide list of valid GIDs that exist on the system.
    
    Returns at least 10 GIDs, or skips test if not enough groups exist.
    """
    gids = get_valid_gids()
    if len(gids) < 10:
        pytest.skip(f"Need at least 10 groups, only {len(gids)} found on system")
    return gids


@pytest.fixture
def some_valid_uids():
    """
    Provide list of valid UIDs (at least 3 required).
    
    Use this when you need some valid UIDs but don't require exactly 10.
    """
    uids = get_valid_uids()
    if len(uids) < 3:
        pytest.skip(f"Need at least 3 users, only {len(uids)} found on system")
    return uids


@pytest.fixture
def some_valid_gids():
    """
    Provide list of valid GIDs (at least 3 required).
    
    Use this when you need some valid GIDs but don't require exactly 10.
    """
    gids = get_valid_gids()
    if len(gids) < 3:
        pytest.skip(f"Need at least 3 groups, only {len(gids)} found on system")
    return gids


# =============================================================================
# ACL Fixtures
# =============================================================================


@pytest.fixture
def acl_id(request):
    """Create empty ACL, auto-cleanup after test."""
    result = QDocSE.acl_create().execute()
    if result.result.failed:
        pytest.skip(f"Cannot create ACL: {result.result.stderr}")

    aid = result.parse().get("acl_id")
    if aid is None:
        pytest.fail(f"Failed to parse ACL ID: {result.result.stdout}")

    request.addfinalizer(lambda: _cleanup_acl(aid))
    return aid


@pytest.fixture
def acl_with_entries(acl_id, some_valid_uids):
    """ACL with 3 read entries using valid system UIDs."""
    for uid in some_valid_uids[:3]:
        QDocSE.acl_add(acl_id, user=uid, mode="r").execute().ok()
    return acl_id


@pytest.fixture
def user_acl_with_allow_deny(request, some_valid_uids):
    """ACL with allow/deny entries using valid system UIDs."""
    result = QDocSE.acl_create().execute()
    if result.result.failed:
        pytest.skip(f"Cannot create ACL: {result.result.stderr}")

    acl_id = result.parse().get("acl_id")
    if acl_id is None:
        pytest.fail("Failed to parse ACL ID")

    # Use first 3 valid UIDs: allow rwx, allow rw, deny rw
    uids = some_valid_uids[:3]
    QDocSE.acl_add(acl_id, allow=True, user=uids[0], mode="rwx").execute().ok()
    QDocSE.acl_add(acl_id, allow=True, user=uids[1], mode="rw").execute().ok()
    QDocSE.acl_add(acl_id, allow=False, user=uids[2], mode="rw").execute().ok()

    request.addfinalizer(lambda: _cleanup_acl(acl_id))
    return acl_id


@pytest.fixture
def program_acl(request, some_valid_uids):
    """ACL for program access control (with user entry using valid UID)."""
    result = QDocSE.acl_create().execute()
    if result.result.failed:
        pytest.skip(f"Cannot create ACL: {result.result.stderr}")

    acl_id = result.parse().get("acl_id")
    if acl_id is None:
        pytest.fail("Failed to parse ACL ID")

    QDocSE.acl_add(acl_id, allow=True, user=some_valid_uids[0], mode="rwx").execute().ok()

    request.addfinalizer(lambda: _cleanup_acl(acl_id))
    return acl_id


@pytest.fixture
def multiple_acls(request, some_valid_uids):
    """Create 3 ACLs, each with one user entry using valid UIDs."""
    acl_ids = []
    uids = some_valid_uids[:3]

    def cleanup():
        for aid in acl_ids:
            QDocSE.acl_destroy(aid, force=True).execute()
        QDocSE.push_config().execute()

    for i, uid in enumerate(uids):
        result = QDocSE.acl_create().execute()
        if result.result.failed:
            cleanup()
            pytest.skip(f"Cannot create ACL: {result.result.stderr}")

        acl_id = result.parse().get("acl_id")
        if acl_id is None:
            cleanup()
            pytest.fail("Failed to parse ACL ID")

        acl_ids.append(acl_id)
        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute().ok()

    request.addfinalizer(cleanup)
    return acl_ids


@pytest.fixture
def empty_acl(request):
    """Empty ACL (denies all by default)."""
    result = QDocSE.acl_create().execute()
    if result.result.failed:
        pytest.skip(f"Cannot create ACL: {result.result.stderr}")

    acl_id = result.parse().get("acl_id")
    if acl_id is None:
        pytest.fail("Failed to parse ACL ID")

    request.addfinalizer(lambda: _cleanup_acl(acl_id))
    return acl_id


@pytest.fixture
def acl_with_time_window(request, some_valid_uids):
    """ACL with time-restricted entry (09:00-18:00) using valid UID."""
    result = QDocSE.acl_create().execute()
    if result.result.failed:
        pytest.skip(f"Cannot create ACL: {result.result.stderr}")

    acl_id = result.parse().get("acl_id")
    if acl_id is None:
        pytest.fail("Failed to parse ACL ID")

    QDocSE.acl_add(
        acl_id, allow=True, user=some_valid_uids[0], mode="rwx",
        time_start="09:00", time_end="18:00"
    ).execute().ok()

    request.addfinalizer(lambda: _cleanup_acl(acl_id))
    return acl_id
