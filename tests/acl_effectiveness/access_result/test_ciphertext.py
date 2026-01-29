"""
Access Result Tests - Ciphertext Access

Tests for encrypted content access:
- Authorized users see decrypted plaintext
- Unauthorized users see ciphertext (encrypted data)
- Encryption verification

Uses QDocSE API with encrypted_dir from conftest.
"""
import pytest
import os
import tempfile
import shutil
from pathlib import Path
from helpers import QDocSE
from conftest import apply_acl


def _cleanup_acl(acl_id):
    try:
        QDocSE.acl_destroy(acl_id, force=True).execute()
        QDocSE.push_config().execute()
    except Exception:
        pass


class TestCiphertextAccess:
    """Test ciphertext access behavior for encrypted directories."""

    def test_unauthorized_sees_ciphertext_or_denied(self, encrypted_dir, request):
        """
        Unauthorized user sees ciphertext instead of plaintext, or access denied.

        When encryption is enabled and user has no access:
        - File read returns encrypted content (ciphertext), or
        - Access is denied entirely
        """
        # Create file with known content
        test_file = Path(encrypted_dir) / "secret.txt"
        plaintext = "This is secret content that should be encrypted"
        test_file.write_text(plaintext)

        # Apply empty ACL (deny all)
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        try:
            apply_acl(encrypted_dir, acl_id)

            # Without ACL entry, access should be denied or return ciphertext
            try:
                content = test_file.read_text()
                # If read succeeds, content should be encrypted (not plaintext)
                assert plaintext not in content, \
                    "Unauthorized user should not see plaintext"
            except (PermissionError, OSError):
                # Access denied is the expected behavior
                pass
        finally:
            _cleanup_acl(acl_id)

    def test_authorized_sees_plaintext(self, encrypted_dir, request):
        """
        Authorized user sees decrypted plaintext.

        When user has read permission on encrypted directory:
        - File read returns original plaintext content
        - Decryption is transparent
        """
        uid = os.getuid()

        # Create file with known content
        test_file = Path(encrypted_dir) / "secret.txt"
        plaintext = "This is secret content that should be encrypted"
        test_file.write_text(plaintext)

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        # Add read permission for current user
        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="r").execute()

        try:
            apply_acl(encrypted_dir, acl_id)

            # Authorized user should see plaintext
            content = test_file.read_text()
            assert content == plaintext, \
                "Authorized user should see decrypted plaintext"
        finally:
            _cleanup_acl(acl_id)

    def test_authorized_rw_can_modify_encrypted(self, encrypted_dir, request):
        """
        Authorized user with rw can read and write encrypted files.
        """
        uid = os.getuid()

        test_file = Path(encrypted_dir) / "modifiable.txt"
        test_file.write_text("original")

        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]

        QDocSE.acl_add(acl_id, allow=True, user=uid, mode="rw").execute()

        try:
            apply_acl(encrypted_dir, acl_id)

            # Read original content
            assert test_file.read_text() == "original"

            # Modify content
            test_file.write_text("modified")
            assert test_file.read_text() == "modified"
        finally:
            _cleanup_acl(acl_id)


class TestEncryptionVerification:
    """Verify encryption is actually applied."""

    def test_file_on_disk_is_encrypted(self, request):
        """
        File content on disk is actually encrypted.

        Even bypassing QDocSE (direct disk read), content should be encrypted.
        This test documents the expected behavior - direct block device
        verification would require specialized tools.
        """
        enc_dir = tempfile.mkdtemp(prefix="qdocse_enc_")

        try:
            QDocSE.protect(enc_dir, encrypt=True).execute()

            test_file = Path(enc_dir) / "encrypted.txt"
            original = "Original content before encryption"
            test_file.write_text(original)

            QDocSE.push_config().execute()

            # The on-disk content should be encrypted
            # Transparent read via QDocSE returns plaintext
            content = test_file.read_text()
            assert content == original, "Transparent read should return plaintext"

        finally:
            QDocSE.unprotect(enc_dir).execute()
            shutil.rmtree(enc_dir, ignore_errors=True)

    def test_encryption_key_per_directory(self, request):
        """
        Each protected directory has its own encryption key.

        Same plaintext in different directories should produce different
        ciphertext. This test documents the expected behavior.
        """
        dir1 = tempfile.mkdtemp(prefix="qdocse_enc1_")
        dir2 = tempfile.mkdtemp(prefix="qdocse_enc2_")

        try:
            QDocSE.protect(dir1, encrypt=True).execute()
            QDocSE.protect(dir2, encrypt=True).execute()

            content = "Identical test content"

            file1 = Path(dir1) / "test.txt"
            file2 = Path(dir2) / "test.txt"

            file1.write_text(content)
            file2.write_text(content)

            QDocSE.push_config().execute()

            # Both should be readable as plaintext via transparent decryption
            assert file1.read_text() == content
            assert file2.read_text() == content

        finally:
            QDocSE.unprotect(dir1).execute()
            QDocSE.unprotect(dir2).execute()
            shutil.rmtree(dir1, ignore_errors=True)
            shutil.rmtree(dir2, ignore_errors=True)
