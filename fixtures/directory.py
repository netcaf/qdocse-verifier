"""Directory fixtures with auto-cleanup."""
import pytest
from helpers import QDocSE


@pytest.fixture
def temp_dir(tmp_path):
    """Basic temp directory with file1.txt and file2.txt."""
    d = tmp_path / "test_data"
    d.mkdir()
    (d / "file1.txt").write_text("content1")
    (d / "file2.txt").write_text("content2")
    return str(d)


@pytest.fixture
def test_dir_with_files(tmp_path):
    """Directory with multiple file types for glob pattern testing."""
    d = tmp_path / "test_files"
    d.mkdir()

    (d / "doc1.txt").write_text("text file 1")
    (d / "doc2.txt").write_text("text file 2")
    (d / "data1.doc").write_text("doc file 1")
    (d / "data2.doc").write_text("doc file 2")
    (d / "config.cfg").write_text("config file")
    (d / "script.sh").write_text("#!/bin/bash\necho hello")
    (d / "readme.md").write_text("# Readme")

    sub = d / "subdir"
    sub.mkdir()
    (sub / "sub1.txt").write_text("sub text 1")
    (sub / "sub2.doc").write_text("sub doc 1")

    return str(d)


@pytest.fixture
def protected_dir(tmp_path, request):
    """Protected directory (no encryption). Requires Elevated/Learning mode."""
    d = tmp_path / "protected_test"
    d.mkdir()
    (d / "secret.txt").write_text("secret content")
    (d / "data.dat").write_text("important data")

    dir_path = str(d)
    protect_result = QDocSE.protect(dir_path, encrypt=False).execute()
    if protect_result.result.failed:
        pytest.skip(f"Cannot protect directory: {protect_result.result.stderr}")

    request.addfinalizer(lambda: QDocSE.unprotect(dir_path).execute())
    return dir_path


@pytest.fixture
def encrypted_dir(tmp_path, request):
    """Protected and encrypted directory (TDE)."""
    d = tmp_path / "encrypted_test"
    d.mkdir()
    (d / "encrypted.txt").write_text("encrypted content")

    dir_path = str(d)
    protect_result = QDocSE.protect(dir_path, encrypt=True).execute()
    if protect_result.result.failed:
        pytest.skip(f"Cannot encrypt directory: {protect_result.result.stderr}")

    QDocSE.push_config().execute()
    request.addfinalizer(lambda: QDocSE.unprotect(dir_path).execute())
    return dir_path


@pytest.fixture
def nested_dir_structure(tmp_path):
    """Nested directory structure for recursive testing."""
    root = tmp_path / "nested"
    root.mkdir()
    (root / "level1_file.txt").write_text("level 1")

    dir1 = root / "dir1"
    dir1.mkdir()
    (dir1 / "level2_file.txt").write_text("level 2 in dir1")

    dir1_1 = dir1 / "dir1_1"
    dir1_1.mkdir()
    (dir1_1 / "level3_file.txt").write_text("level 3")

    dir2 = root / "dir2"
    dir2.mkdir()
    (dir2 / "level2_file2.txt").write_text("level 2 in dir2")

    return str(root)


@pytest.fixture
def large_file_dir(tmp_path):
    """Directory with 1MB file for performance testing."""
    d = tmp_path / "large_files"
    d.mkdir()
    (d / "large_file.bin").write_bytes(b"x" * (1024 * 1024))
    (d / "small_file.txt").write_text("small content")
    return str(d)


@pytest.fixture
def sensitive_files_dir(tmp_path):
    """Directory with common sensitive file types."""
    d = tmp_path / "sensitive"
    d.mkdir()

    (d / "password.txt").write_text("admin:password123")
    (d / "config.ini").write_text("[database]\nhost=localhost\npassword=secret")
    (d / "secret.key").write_text("-----BEGIN PRIVATE KEY-----\nfake_key\n-----END PRIVATE KEY-----")
    (d / "database.db").write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)
    (d / "credentials.json").write_text('{"api_key": "sk-123456", "secret": "abcdef"}')

    return str(d)


@pytest.fixture
def protected_dir_with_acl(tmp_path, request, acl_id):
    """Protected directory with associated ACL."""
    d = tmp_path / "protected_with_acl"
    d.mkdir()
    (d / "protected.txt").write_text("protected content")

    dir_path = str(d)

    protect_result = QDocSE.protect(dir_path, encrypt=False).execute()
    if protect_result.result.failed:
        pytest.skip(f"Cannot protect directory: {protect_result.result.stderr}")

    acl_file_result = QDocSE.acl_file(dir_path, user_acl=acl_id).execute()
    if acl_file_result.result.failed:
        QDocSE.unprotect(dir_path).execute()
        pytest.skip(f"Cannot associate ACL: {acl_file_result.result.stderr}")

    QDocSE.push_config().execute()

    request.addfinalizer(lambda: QDocSE.unprotect(dir_path).execute())
    return {"dir_path": dir_path, "acl_id": acl_id}


@pytest.fixture
def protected_test_dir(request):
    """Protected directory for integration tests."""
    import tempfile
    import shutil
    from pathlib import Path

    test_dir = tempfile.mkdtemp(prefix="qdocse_test_")

    test_files = {
        "public.txt": "This is a public file",
        "sensitive.txt": "This is sensitive data",
        "data.csv": "id,name,value\n1,test,100",
    }
    for name, content in test_files.items():
        Path(test_dir, name).write_text(content)

    protect_result = QDocSE.protect(test_dir, encrypt=False).execute()
    if protect_result.result.failed:
        shutil.rmtree(test_dir, ignore_errors=True)
        pytest.skip(f"Cannot protect directory: {protect_result.result.stderr}")

    def cleanup():
        QDocSE.unprotect(test_dir).execute()
        shutil.rmtree(test_dir, ignore_errors=True)

    request.addfinalizer(cleanup)
    return test_dir


@pytest.fixture
def encrypted_test_dir(request):
    """Encrypted directory for TDE integration tests."""
    import tempfile
    import shutil
    from pathlib import Path

    test_dir = tempfile.mkdtemp(prefix="qdocse_enc_test_")
    Path(test_dir, "encrypted.txt").write_text("This data should be encrypted at rest")

    protect_result = QDocSE.protect(test_dir, encrypt=True).execute()
    if protect_result.result.failed:
        shutil.rmtree(test_dir, ignore_errors=True)
        pytest.skip(f"Cannot protect with encryption: {protect_result.result.stderr}")

    QDocSE.push_config().execute()

    def cleanup():
        QDocSE.unprotect(test_dir).execute()
        shutil.rmtree(test_dir, ignore_errors=True)

    request.addfinalizer(cleanup)
    return test_dir
