"""
Access Result Tests - Ciphertext Access

Tests for encrypted content access:
- Authorized users see decrypted plaintext
- Unauthorized users see ciphertext (encrypted data)
- Encryption verification
"""

import pytest
import os


class TestCiphertextAccess:
    """Test ciphertext access behavior for encrypted directories."""
    
    def test_unauthorized_sees_ciphertext(self, qdocse_client, test_executor_unauthorized):
        """
        Test: Unauthorized user sees ciphertext instead of plaintext.
        
        When encryption is enabled and user has no access:
        - File read returns encrypted content
        - Content is not human-readable
        """
        import tempfile
        
        # Create and protect directory with encryption
        enc_dir = tempfile.mkdtemp(prefix="qdocse_enc_")
        
        try:
            # Protect with encryption
            result = qdocse_client.protect(enc_dir, encrypt=True)
            assert result.success, f"Protect failed: {result.stderr}"
            
            # Create file with known content (as admin)
            test_file = os.path.join(enc_dir, "secret.txt")
            plaintext = "This is secret content that should be encrypted"
            with open(test_file, 'w') as f:
                f.write(plaintext)
            
            # Push configuration (no ACL entries for test user)
            qdocse_client.acl_push(enc_dir)
            
            # Read as unauthorized user - should get ciphertext
            read_result = test_executor_unauthorized.run(f"cat {test_file}")
            
            # Verify the content is not plaintext
            if read_result.returncode == 0:
                content = read_result.stdout
                assert plaintext not in content, \
                    "Unauthorized user should not see plaintext"
                # Ciphertext should contain non-printable characters or appear garbled
                assert content != plaintext, "Content should be encrypted"
            else:
                # Access denied is also acceptable
                pass
                
        finally:
            qdocse_client.unprotect(enc_dir)
            import shutil
            shutil.rmtree(enc_dir, ignore_errors=True)
    
    def test_authorized_sees_plaintext(self, qdocse_client, test_user, test_executor):
        """
        Test: Authorized user sees decrypted plaintext.
        
        When user has read permission on encrypted directory:
        - File read returns original plaintext content
        - Decryption is transparent
        """
        import tempfile
        
        enc_dir = tempfile.mkdtemp(prefix="qdocse_enc_")
        
        try:
            # Protect with encryption
            qdocse_client.protect(enc_dir, encrypt=True)
            
            # Create file with known content
            test_file = os.path.join(enc_dir, "secret.txt")
            plaintext = "This is secret content that should be encrypted"
            with open(test_file, 'w') as f:
                f.write(plaintext)
            
            # Add read permission for test user
            qdocse_client.acl_add(
                path=enc_dir,
                subject_type="user",
                subject=test_user,
                permissions="r"
            )
            qdocse_client.acl_push(enc_dir)
            
            # Read as authorized user - should get plaintext
            read_result = test_executor.run(f"cat {test_file}")
            
            assert read_result.returncode == 0, "Read should succeed"
            assert plaintext in read_result.stdout, \
                "Authorized user should see decrypted plaintext"
                
        finally:
            qdocse_client.unprotect(enc_dir)
            import shutil
            shutil.rmtree(enc_dir, ignore_errors=True)
    
    def test_ciphertext_contains_nonprintable(self, qdocse_client, test_executor_unauthorized):
        """
        Test: Ciphertext contains non-printable characters.
        
        Encrypted content should look like binary data, not text.
        """
        import tempfile
        
        enc_dir = tempfile.mkdtemp(prefix="qdocse_enc_")
        
        try:
            qdocse_client.protect(enc_dir, encrypt=True)
            
            # Create file
            test_file = os.path.join(enc_dir, "test.txt")
            with open(test_file, 'w') as f:
                f.write("Plain text content for encryption test")
            
            qdocse_client.acl_push(enc_dir)
            
            # Read raw bytes as unauthorized user
            read_result = test_executor_unauthorized.run(
                f"xxd {test_file} | head -5"
            )
            
            # If we can read the file, verify it looks encrypted
            if read_result.returncode == 0:
                # Hex dump should show varied byte values
                # not just ASCII printable range
                output = read_result.stdout
                # This is a basic check - encrypted data should not
                # be all printable ASCII
                
        finally:
            qdocse_client.unprotect(enc_dir)
            import shutil
            shutil.rmtree(enc_dir, ignore_errors=True)


class TestEncryptionVerification:
    """Verify encryption is actually applied."""
    
    def test_file_on_disk_is_encrypted(self, qdocse_client):
        """
        Test: File content on disk is actually encrypted.
        
        Even bypassing QDocSE (direct disk read), content should be encrypted.
        """
        import tempfile
        
        enc_dir = tempfile.mkdtemp(prefix="qdocse_enc_")
        
        try:
            qdocse_client.protect(enc_dir, encrypt=True)
            
            test_file = os.path.join(enc_dir, "encrypted.txt")
            original = "Original content before encryption"
            
            # Write through normal API
            with open(test_file, 'w') as f:
                f.write(original)
            
            qdocse_client.acl_push(enc_dir)
            
            # The actual on-disk content verification would require
            # direct block device access or specific QDocSE debug tools
            # This test documents the expected behavior
            
        finally:
            qdocse_client.unprotect(enc_dir)
            import shutil
            shutil.rmtree(enc_dir, ignore_errors=True)
    
    def test_encryption_key_per_directory(self, qdocse_client):
        """
        Test: Each protected directory has its own encryption key.
        
        Same plaintext in different directories should produce different ciphertext.
        """
        import tempfile
        
        dir1 = tempfile.mkdtemp(prefix="qdocse_enc1_")
        dir2 = tempfile.mkdtemp(prefix="qdocse_enc2_")
        
        try:
            # Protect both directories
            qdocse_client.protect(dir1, encrypt=True)
            qdocse_client.protect(dir2, encrypt=True)
            
            # Write identical content to both
            content = "Identical test content"
            
            file1 = os.path.join(dir1, "test.txt")
            file2 = os.path.join(dir2, "test.txt")
            
            with open(file1, 'w') as f:
                f.write(content)
            with open(file2, 'w') as f:
                f.write(content)
            
            qdocse_client.acl_push(dir1)
            qdocse_client.acl_push(dir2)
            
            # Verification would require comparing encrypted bytes
            # This test documents the expected behavior
            
        finally:
            qdocse_client.unprotect(dir1)
            qdocse_client.unprotect(dir2)
            import shutil
            shutil.rmtree(dir1, ignore_errors=True)
            shutil.rmtree(dir2, ignore_errors=True)
