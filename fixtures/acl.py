"""ACL fixtures with auto-cleanup."""
import pytest
from helpers import QDocSE


def _cleanup_acl(acl_id):
    """Destroy ACL and commit changes."""
    QDocSE.acl_destroy(acl_id, force=True).execute()
    QDocSE.push_config().execute()


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
def acl_with_entries(acl_id):
    """ACL with 3 read entries (user 0, 1, 2)."""
    for uid in [0, 1, 2]:
        QDocSE.acl_add(acl_id, user=uid, mode="r").execute().ok()
    return acl_id


@pytest.fixture
def user_acl_with_allow_deny(request):
    """ACL with allow/deny entries: root(rwx), user1000(rw), nobody(deny rw)."""
    result = QDocSE.acl_create().execute()
    if result.result.failed:
        pytest.skip(f"Cannot create ACL: {result.result.stderr}")

    acl_id = result.parse().get("acl_id")
    if acl_id is None:
        pytest.fail("Failed to parse ACL ID")

    QDocSE.acl_add(acl_id, allow=True, user=0, mode="rwx").execute().ok()
    QDocSE.acl_add(acl_id, allow=True, user=1000, mode="rw").execute().ok()
    QDocSE.acl_add(acl_id, allow=False, user=65534, mode="rw").execute().ok()

    request.addfinalizer(lambda: _cleanup_acl(acl_id))
    return acl_id


@pytest.fixture
def program_acl(request):
    """ACL for program access control (placeholder with user entry)."""
    result = QDocSE.acl_create().execute()
    if result.result.failed:
        pytest.skip(f"Cannot create ACL: {result.result.stderr}")

    acl_id = result.parse().get("acl_id")
    if acl_id is None:
        pytest.fail("Failed to parse ACL ID")

    QDocSE.acl_add(acl_id, allow=True, user=0, mode="rwx").execute().ok()

    request.addfinalizer(lambda: _cleanup_acl(acl_id))
    return acl_id


@pytest.fixture
def multiple_acls(request):
    """Create 3 ACLs, each with one user entry."""
    acl_ids = []

    def cleanup():
        for aid in acl_ids:
            QDocSE.acl_destroy(aid, force=True).execute()
        QDocSE.push_config().execute()

    for i in range(3):
        result = QDocSE.acl_create().execute()
        if result.result.failed:
            cleanup()
            pytest.skip(f"Cannot create ACL: {result.result.stderr}")

        acl_id = result.parse().get("acl_id")
        if acl_id is None:
            cleanup()
            pytest.fail("Failed to parse ACL ID")

        acl_ids.append(acl_id)
        QDocSE.acl_add(acl_id, allow=True, user=i, mode="r").execute().ok()

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
def acl_with_time_window(request):
    """ACL with time-restricted entry (09:00-18:00)."""
    result = QDocSE.acl_create().execute()
    if result.result.failed:
        pytest.skip(f"Cannot create ACL: {result.result.stderr}")

    acl_id = result.parse().get("acl_id")
    if acl_id is None:
        pytest.fail("Failed to parse ACL ID")

    QDocSE.acl_add(
        acl_id, allow=True, user=0, mode="rwx",
        time_start="09:00", time_end="18:00"
    ).execute().ok()

    request.addfinalizer(lambda: _cleanup_acl(acl_id))
    return acl_id
