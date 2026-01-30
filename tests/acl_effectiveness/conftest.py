"""ACL Effectiveness Tests - Shared Fixtures

ACL cleanup is handled by the session-level purge_stale_acls fixture.
Post-test state is preserved for manual inspection on failure.
"""
import pytest
import os
import tempfile
import shutil
from pathlib import Path
from helpers import QDocSE


# =============================================================================
# Directory Fixtures
# =============================================================================

@pytest.fixture
def temp_dir(request):
    """Temporary test directory"""
    dir_path = tempfile.mkdtemp(prefix="acl_test_")
    request.addfinalizer(lambda: shutil.rmtree(dir_path, ignore_errors=True))
    return dir_path


@pytest.fixture
def protected_dir(temp_dir, request):
    """Protected directory (not encrypted)"""
    Path(temp_dir, "test.txt").write_text("test content")
    QDocSE.protect(temp_dir, encrypt=False).execute()
    QDocSE.push_config().execute()
    request.addfinalizer(lambda: QDocSE.unprotect(temp_dir).execute())
    return temp_dir


@pytest.fixture
def encrypted_dir(temp_dir, request):
    """Protected and encrypted directory"""
    Path(temp_dir, "secret.txt").write_text("secret content")
    QDocSE.protect(temp_dir, encrypt=True).execute()
    QDocSE.push_config().execute()
    request.addfinalizer(lambda: QDocSE.unprotect(temp_dir).execute())
    return temp_dir


# =============================================================================
# ACL Fixtures
# =============================================================================

@pytest.fixture
def empty_acl():
    """Empty ACL (default deny)"""
    result = QDocSE.acl_create().execute().ok()
    return result.parse()["acl_id"]


@pytest.fixture
def allow_r_acl():
    """Allow read"""
    result = QDocSE.acl_create().execute().ok()
    acl_id = result.parse()["acl_id"]
    QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="r").execute()
    return acl_id


@pytest.fixture
def allow_w_acl():
    """Allow write"""
    result = QDocSE.acl_create().execute().ok()
    acl_id = result.parse()["acl_id"]
    QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="w").execute()
    return acl_id


@pytest.fixture
def allow_rw_acl():
    """Allow read and write"""
    result = QDocSE.acl_create().execute().ok()
    acl_id = result.parse()["acl_id"]
    QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw").execute()
    return acl_id


@pytest.fixture
def allow_rwx_acl():
    """Allow all permissions"""
    result = QDocSE.acl_create().execute().ok()
    acl_id = result.parse()["acl_id"]
    QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rwx").execute()
    return acl_id


@pytest.fixture
def deny_acl():
    """Deny current user"""
    result = QDocSE.acl_create().execute().ok()
    acl_id = result.parse()["acl_id"]
    QDocSE.acl_add(acl_id, allow=False, user=os.getuid(), mode="rwx").execute()
    return acl_id


# =============================================================================
# Helper Functions
# =============================================================================

def apply_acl(directory, acl_id):
    """Apply ACL to directory"""
    QDocSE.acl_file(directory, user_acl=acl_id).execute().ok()
    QDocSE.push_config().execute().ok()
