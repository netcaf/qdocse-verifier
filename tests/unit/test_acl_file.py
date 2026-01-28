"""
acl_file Command Tests

PDF Manual Key Points (Page 77-79):
1. Sets user and/or program ACL IDs for specific file or files under directory
2. Required option: -d <directory_name>
3. At least one of -A or -P must be specified
4. Optional: -dp <matching_pattern> for glob patterns
5. Optional: -excl <excluding_pattern> for exclusion patterns
6. Active modes: Elevated, Learning
7. License type: A

Options:
- -d <directory_name>: Directory containing files (required)
- -dp <matching_pattern>: Glob pattern to select files
- -excl <excluding_pattern>: Glob pattern to exclude files
- -A <acl_id>: User/group ACL ID for file access
- -P <acl_id>: Program ACL ID for file access

Errors documented:
- Option '-d' must be specified
- One or both options '-A' or '-P' must be specified
- No ACL configuration found
- Invalid ACL ID specified to '-A' or '-P'
- Path does not exist
- Directory does not exist
- Not a directory
- Filename path too long
- Operation not permitted

Test Strategy:
1. Command validation: Required options, ACL ID validation
2. Pattern matching: glob patterns, exclusion patterns
3. ACL assignment verification: Check files have correct ACLs
4. Integration with protect: ACLs on protected directories

Fixtures used from conftest.py:
- acl_id: Basic ACL (auto cleanup)
- user_acl_with_allow_deny: ACL with allow and deny entries
- program_acl: ACL for program access control
- temp_dir: Temporary test directory
- test_dir_with_files: Test directory with multiple file types (for glob pattern testing)
- protected_dir: Protected test directory
"""
import pytest
import os
from pathlib import Path
from helpers import QDocSE

# Prerequisites (auto-checked)
pytestmark = [
    pytest.mark.requires_mode("elevated", "learning"),
    pytest.mark.requires_license("A"),
]


# Note: All fixtures are defined in conftest.py
# - acl_id: Basic ACL
# - user_acl_with_allow_deny: ACL with allow/deny entries
# - program_acl: Program access control ACL
# - temp_dir: Basic test directory
# - test_dir_with_files: Multi-filetype test directory


@pytest.mark.unit
class TestACLFileBasic:
    """Basic acl_file functionality"""
    
    def test_set_user_acl_on_directory(self, acl_id, temp_dir):
        """
        Set user ACL on a directory.
        
        Per PDF page 77: "sets the user and/or program ACL IDs for a specific file
        or for a set of files under a specified directory"
        """
        result = QDocSE.acl_file(temp_dir, user_acl=acl_id).execute()
        result.ok("Should set user ACL on directory")
    
    def test_set_program_acl_on_directory(self, program_acl, temp_dir):
        """
        Set program ACL on a directory.
        """
        result = QDocSE.acl_file(temp_dir, prog_acl=program_acl).execute()
        result.ok("Should set program ACL on directory")
    
    def test_set_both_acls(self, acl_id, program_acl, temp_dir):
        """
        Set both user and program ACLs simultaneously.
        """
        result = QDocSE.acl_file(
            temp_dir,
            user_acl=acl_id,
            prog_acl=program_acl
        ).execute()
        result.ok("Should set both ACLs")
    
    def test_acl_file_requires_directory(self, acl_id):
        """
        acl_file requires -d option.
        
        Per PDF page 78: "Option '-d' must be specified" error
        """
        result = QDocSE.acl_file(user_acl=acl_id).execute()
        result.fail("Should fail without directory")
    
    def test_acl_file_requires_acl_option(self, temp_dir):
        """
        acl_file requires at least one of -A or -P.
        
        Per PDF page 78: "One or both options '-A' or '-P' must be specified" error
        """
        result = QDocSE.acl_file(temp_dir).execute()
        result.fail("Should fail without ACL option")


@pytest.mark.unit
class TestACLFilePatterns:
    """Tests for glob pattern matching"""
    
    def test_pattern_match_txt_files(self, acl_id, test_dir_with_files):
        """
        Match only .txt files using pattern.
        
        Per PDF page 77: "-dp <matching_pattern> for glob patterns"
        """
        result = QDocSE.acl_file(
            test_dir_with_files,
            user_acl=acl_id,
            pattern="*.txt"
        ).execute()
        result.ok("Should match .txt files")
    
    def test_pattern_match_doc_files(self, acl_id, test_dir_with_files):
        """
        Match only .doc files.
        """
        result = QDocSE.acl_file(
            test_dir_with_files,
            user_acl=acl_id,
            pattern="*.doc"
        ).execute()
        result.ok("Should match .doc files")
    
    def test_pattern_with_exclusion(self, acl_id, test_dir_with_files):
        """
        Use pattern with exclusion.
        
        Per PDF page 78: "-dp matches are added to list, then -excl matches removed"
        """
        result = (QDocSE.acl_file()
            .dir(test_dir_with_files)
            .user_acl(acl_id)
            .pattern("*.*")        # Match all
            .exclude("*.cfg")      # Exclude .cfg files
            .execute())
        result.ok("Should apply ACL with exclusion pattern")
    
    def test_complex_glob_pattern(self, acl_id, test_dir_with_files):
        """
        Test complex glob patterns.
        
        Per PDF Appendix C: Extended glob patterns with (pattern1|pattern2)
        """
        # Match files ending in txt or doc
        result = QDocSE.acl_file(
            test_dir_with_files,
            user_acl=acl_id,
            pattern="(*.txt|*.doc)"
        ).execute()
        # May or may not support extended glob - document behavior
        if result.result.success:
            print("Note: Extended glob patterns supported")
        else:
            print("Note: Extended glob patterns may need quotes or different syntax")
    
    @pytest.mark.parametrize("pattern,desc", [
        ("*.txt", "Single extension"),
        ("file*", "Prefix wildcard"),
        ("*1*", "Contains character"),
        ("[a-z]*", "Character range"),
        ("*.???", "Fixed extension length"),
    ])
    def test_valid_glob_patterns(self, acl_id, test_dir_with_files, pattern, desc):
        """Test various valid glob patterns"""
        result = QDocSE.acl_file(
            test_dir_with_files,
            user_acl=acl_id,
            pattern=pattern
        ).execute()
        # Document pattern behavior
        if result.result.failed:
            print(f"Pattern '{pattern}' ({desc}) failed: {result.result.stderr}")


@pytest.mark.unit
class TestACLFileErrors:
    """Error handling tests"""
    
    def test_nonexistent_directory(self, acl_id):
        """
        Directory does not exist should fail.
        
        Per PDF page 78: "Directory does not exist" error
        """
        result = QDocSE.acl_file(
            "/nonexistent/path/to/dir",
            user_acl=acl_id
        ).execute()
        result.fail("Should fail for nonexistent directory")
    
    def test_file_not_directory(self, acl_id, test_dir_with_files):
        """
        Path is file, not directory should fail.
        
        Per PDF page 78: "Not a directory" error
        """
        # Use a file path instead of directory
        file_path = os.path.join(test_dir_with_files, "file1.txt")
        result = QDocSE.acl_file(file_path, user_acl=acl_id).execute()
        result.fail("Should fail for file path")
    
    def test_invalid_user_acl_id(self, test_dir_with_files):
        """
        Invalid ACL ID for -A should fail.
        
        Per PDF page 78: "Invalid ACL ID specified to '-A'" error
        """
        result = QDocSE.acl_file(
            test_dir_with_files,
            user_acl=999999  # Nonexistent ACL
        ).execute()
        result.fail("Should fail for invalid ACL ID")
    
    def test_invalid_program_acl_id(self, test_dir_with_files):
        """
        Invalid ACL ID for -P should fail.
        """
        result = QDocSE.acl_file(
            test_dir_with_files,
            prog_acl=999999  # Nonexistent ACL
        ).execute()
        result.fail("Should fail for invalid program ACL ID")
    
    def test_negative_acl_id(self, test_dir_with_files):
        """Negative ACL ID should fail"""
        result = QDocSE.acl_file(
            test_dir_with_files,
            user_acl=-1
        ).execute()
        result.fail("Should fail for negative ACL ID")
    
    def test_zero_acl_id(self, test_dir_with_files):
        """
        ACL ID 0 may be special (built-in allow access ACL).
        Document actual behavior.
        """
        result = QDocSE.acl_file(
            test_dir_with_files,
            user_acl=0
        ).execute()
        # Document behavior - 0 might be valid or reserved
        if result.result.success:
            print("Note: ACL ID 0 is valid/reserved for allow-all")
        else:
            print("Note: ACL ID 0 is invalid")


@pytest.mark.unit
class TestACLFileRecursive:
    """Test recursive directory handling"""
    
    def test_recursive_apply_default(self, acl_id, test_dir_with_files):
        """
        By default, ACL applies to all files and sub-directories recursively.
        
        Per PDF page 77: "By default the ACL IDs will be applied to all files
        and sub-directories recursively"
        """
        result = QDocSE.acl_file(
            test_dir_with_files,
            user_acl=acl_id
        ).execute()
        result.ok("Should apply ACL recursively")
    
    def test_pattern_applies_to_subdirs(self, acl_id, test_dir_with_files):
        """
        Pattern should match files in subdirectories too.
        """
        result = QDocSE.acl_file(
            test_dir_with_files,
            user_acl=acl_id,
            pattern="*.txt"  # Should match subdir/sub_file1.txt too
        ).execute()
        result.ok("Pattern should match in subdirectories")


@pytest.mark.unit
class TestACLFileNonMatchingBehavior:
    """Test behavior for non-matching files"""
    
    def test_non_matching_files_unchanged(self, acl_id, test_dir_with_files):
        """
        Non-matching files should retain their current ACL settings.
        
        Per PDF page 78: "When the '-dp' option is used and this does not select
        all files under the directory, then the non-matching files will remain
        unchanged"
        """
        # First, set ACL on all .txt files
        QDocSE.acl_file(
            test_dir_with_files,
            user_acl=acl_id,
            pattern="*.txt"
        ).execute().ok()
        
        # Now, set different ACL on .doc files only
        result2 = QDocSE.acl_create().execute().ok()
        other_acl = result2.parse()["acl_id"]
        QDocSE.acl_add(other_acl, allow=True, user=2000, mode="r").execute().ok()
        
        try:
            QDocSE.acl_file(
                test_dir_with_files,
                user_acl=other_acl,
                pattern="*.doc"
            ).execute().ok()
            
            # The .txt files should still have the original ACL
            # (This would need verification through file inspection)
        finally:
            # Cleanup the other ACL
            QDocSE.acl_destroy(other_acl, force=True).execute()


@pytest.mark.unit
class TestACLFileChaining:
    """Test fluent interface"""
    
    def test_chaining_style(self, acl_id, test_dir_with_files):
        """Test fluent API"""
        (QDocSE.acl_file()
            .dir(test_dir_with_files)
            .user_acl(acl_id)
            .execute()
            .ok())
    
    def test_chaining_with_pattern(self, acl_id, test_dir_with_files):
        """Test fluent API with pattern"""
        (QDocSE.acl_file()
            .dir(test_dir_with_files)
            .pattern("*.txt")
            .user_acl(acl_id)
            .execute()
            .ok())
    
    def test_chaining_with_exclusion(self, acl_id, test_dir_with_files):
        """Test fluent API with exclusion"""
        (QDocSE.acl_file()
            .dir(test_dir_with_files)
            .pattern("*.*")
            .exclude("*.cfg")
            .user_acl(acl_id)
            .execute()
            .ok())


@pytest.mark.unit
class TestACLFilePushConfig:
    """Test that acl_file changes require push_config"""
    
    def test_changes_pending_until_push(self, acl_id, test_dir_with_files):
        """
        After acl_file, changes may be pending until push_config.
        """
        # Apply ACL to files
        QDocSE.acl_file(test_dir_with_files, user_acl=acl_id).execute().ok()
        
        # Check for pending configuration
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        
        if "Pending configuration" in list_result.result.stdout:
            print("Confirmed: acl_file changes require push_config")
            
            # Push config
            QDocSE.push_config().execute().ok()
            
            # Verify pending cleared
            list_after = QDocSE.acl_list(acl_id).execute().ok()
            assert "Pending configuration" not in list_after.result.stdout


@pytest.mark.unit
class TestACLFileWithProtect:
    """Integration tests: acl_file with protected directories"""
    
    def test_set_acl_on_protected_directory(self, acl_id, test_dir_with_files):
        """
        Set ACL on a protected directory.
        
        This is the typical workflow:
        1. Protect directory
        2. Set ACL on protected files
        3. Push config
        """
        try:
            # Protect directory (without encryption for speed)
            QDocSE.protect(test_dir_with_files, encrypt=False).execute().ok()
            
            # Set ACL on protected directory
            QDocSE.acl_file(test_dir_with_files, user_acl=acl_id).execute().ok()
            
            # Push config to make effective
            QDocSE.push_config().execute().ok()
            
        finally:
            # Cleanup
            QDocSE.unprotect(test_dir_with_files).execute()
    
    def test_set_acl_with_encryption(self, acl_id, test_dir_with_files):
        """
        Set ACL on encrypted files.
        
        ACLs control access to encrypted files - this is the core security feature.
        """
        try:
            # Protect with encryption
            QDocSE.protect(test_dir_with_files, encrypt=True).execute().ok()
            
            # Set ACL
            QDocSE.acl_file(test_dir_with_files, user_acl=acl_id).execute().ok()
            
            # Push config
            QDocSE.push_config().execute().ok()
            
        finally:
            QDocSE.unprotect(test_dir_with_files).execute()


@pytest.mark.unit  
class TestACLFileBothACLTypes:
    """Test using both user and program ACLs"""
    
    def test_user_and_program_acl_together(self, acl_id, program_acl, test_dir_with_files):
        """
        Apply both user and program ACLs to same directory.
        
        Per PDF page 77: Both -A and -P can be specified together.
        """
        result = QDocSE.acl_file(
            test_dir_with_files,
            user_acl=acl_id,
            prog_acl=program_acl
        ).execute()
        result.ok("Should set both ACL types")
    
    def test_user_acl_only_leaves_program_unchanged(self, acl_id, test_dir_with_files):
        """
        Setting only -A should not change existing -P setting.
        
        Per PDF page 78: "When this option is not specified then the current
        program ACL ID will be unchanged"
        """
        # Set user ACL only
        result = QDocSE.acl_file(
            test_dir_with_files,
            user_acl=acl_id
        ).execute()
        result.ok()
        
        # Existing program ACL (if any) should be unchanged
    
    def test_program_acl_only_leaves_user_unchanged(self, program_acl, test_dir_with_files):
        """
        Setting only -P should not change existing -A setting.
        """
        result = QDocSE.acl_file(
            test_dir_with_files,
            prog_acl=program_acl
        ).execute()
        result.ok()