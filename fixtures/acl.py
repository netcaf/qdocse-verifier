"""ACL fixtures – cleanup is handled by the session-level purge_stale_acls fixture."""
import pytest
from helpers import QDocSE
from helpers.system import get_valid_uids, get_valid_gids


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
def acl_id():
    """Create empty ACL. Cleanup deferred to next session's pre-run purge."""
    result = QDocSE.acl_create().execute()
    if result.result.failed:
        pytest.skip(f"Cannot create ACL: {result.result.stderr}")

    aid = result.parse().get("acl_id")
    if aid is None:
        pytest.fail(f"Failed to parse ACL ID: {result.result.stdout}")

    return aid


@pytest.fixture
def acl_with_entries(acl_id, some_valid_uids):
    """ACL with 3 read entries using valid system UIDs."""
    for uid in some_valid_uids[:3]:
        QDocSE.acl_add(acl_id, user=uid, mode="r").execute().ok()
    return acl_id


@pytest.fixture
def user_acl_with_allow_deny(some_valid_uids):
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

    return acl_id


@pytest.fixture
def program_acl():
    """ACL with a program entry for program access control.

    Per PDF: An ACL used with the -P option of acl_file must contain program
    entries (not user/group entries). The program index comes from the view
    command's authorized program list.

    Skips if no authorized programs exist on the system.
    """
    # Query authorized programs to get a valid program index
    view_result = QDocSE.view().authorized().execute()
    if view_result.result.failed:
        pytest.skip(f"Cannot query authorized programs: {view_result.result.stderr}")

    programs = view_result.parse().get("authorized", [])
    if not programs:
        pytest.skip("No authorized programs on system — cannot create program ACL")

    result = QDocSE.acl_create().execute()
    if result.result.failed:
        pytest.skip(f"Cannot create ACL: {result.result.stderr}")

    acl_id = result.parse().get("acl_id")
    if acl_id is None:
        pytest.fail("Failed to parse ACL ID")

    # Add program entry using the first authorized program index (1-based)
    QDocSE.acl_add(acl_id, allow=True).program(1).mode("rwx").execute().ok()

    return acl_id


@pytest.fixture
def multiple_acls(some_valid_uids):
    """Create 3 ACLs, each with one user entry using valid UIDs."""
    acl_ids = []
    uids = some_valid_uids[:3]

    for uid in uids:
        result = QDocSE.acl_create().execute()
        if result.result.failed:
            pytest.skip(f"Cannot create ACL: {result.result.stderr}")

        acl_id = result.parse().get("acl_id")
        if acl_id is None:
            pytest.fail("Failed to parse ACL ID")

        acl_ids.append(acl_id)
        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute().ok()

    return acl_ids


@pytest.fixture
def empty_acl():
    """Empty ACL (denies all by default)."""
    result = QDocSE.acl_create().execute()
    if result.result.failed:
        pytest.skip(f"Cannot create ACL: {result.result.stderr}")

    acl_id = result.parse().get("acl_id")
    if acl_id is None:
        pytest.fail("Failed to parse ACL ID")

    return acl_id


@pytest.fixture
def acl_with_time_window(some_valid_uids):
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

    return acl_id
