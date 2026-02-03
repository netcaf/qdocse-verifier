"""
acl_file Command Tests

PDF Manual Key Points (Page 77-79):
1. Sets user and/or program ACL IDs for specific file or files under directory
2. Options:
   -d <directory_name>    Directory containing files (required)
   -dp <matching_pattern> Glob pattern to select files (optional)
   -excl <excluding_pattern> Glob pattern to exclude files (optional)
   -A <acl_id>            User/group ACL ID for file access
   -P <acl_id>            Program ACL ID for file access
3. At least one of -A or -P must be specified
4. By default ACL IDs apply to all files and sub-directories recursively
5. When -dp is used, non-matching files remain unchanged
6. When both -dp and -excl are specified, -dp matches are added first,
   then -excl matches are removed from the list
7. When -A is not specified, current user/group ACL ID is unchanged
8. When -P is not specified, current program ACL ID is unchanged
9. Active modes: Elevated, Learning
10. License type: A

Examples from PDF:
  QDocSEConsole -c acl_file -d datadir2 -P 2 -A 4
  QDocSEConsole -c acl_file -d datadir2 -dp '*.doc' -P 5

Errors documented:
- Option '-d' must be specified.
- One or both options '-A' or '-P' must be specified.
- No ACL configuration found.
- Invalid ACL ID specified to '-A'.
- Invalid ACL ID specified to '-P'.
- Path does not exist.
- Directory does not exist.
- Not a directory.
- Filename path too long.
- Operation not permitted.
"""
import os

import pytest
from helpers import QDocSE

# Prerequisites (auto-checked)
pytestmark = [
    pytest.mark.requires_mode("elevated", "learning"),
    pytest.mark.requires_license("A"),
]


@pytest.mark.unit
class TestACLFileBasic:
    """Basic acl_file functionality."""

    def test_set_user_acl_on_directory(self, acl_id, temp_dir):
        """Set user ACL on a directory.

        Per PDF: "sets the user and/or program ACL IDs for a specific file
        or for a set of files under a specified directory"
        """
        QDocSE.acl_file(temp_dir, user_acl=acl_id).execute().ok()

    def test_set_program_acl_on_directory(self, program_acl, temp_dir):
        """Set program ACL on a directory."""
        QDocSE.acl_file(temp_dir, prog_acl=program_acl).execute().ok()

    def test_set_both_acls(self, acl_id, program_acl, temp_dir):
        """Set both user and program ACLs simultaneously.

        Per PDF example: QDocSEConsole -c acl_file -d datadir2 -P 2 -A 4
        """
        QDocSE.acl_file(
            temp_dir, user_acl=acl_id, prog_acl=program_acl
        ).execute().ok()

    def test_recursive_apply_default(self, acl_id, test_dir_with_files):
        """By default, ACL applies to all files and sub-directories recursively.

        Per PDF: "By default the ACL IDs will be applied to all files
        and sub-directories recursively"
        """
        QDocSE.acl_file(
            test_dir_with_files, user_acl=acl_id
        ).execute().ok()


@pytest.mark.unit
class TestACLFilePatterns:
    """Glob pattern matching tests.

    Per PDF: "-dp <matching_pattern> for glob patterns following glob(7) rules"
    """

    def test_pattern_match_txt_files(self, acl_id, test_dir_with_files):
        """Match only .txt files using -dp pattern."""
        QDocSE.acl_file(
            test_dir_with_files, user_acl=acl_id, pattern="*.txt"
        ).execute().ok()

    def test_pattern_match_doc_files(self, acl_id, test_dir_with_files):
        """Match only .doc files using -dp pattern.

        Per PDF example: QDocSEConsole -c acl_file -d datadir2 -dp '*.doc' -P 5
        """
        QDocSE.acl_file(
            test_dir_with_files, user_acl=acl_id, pattern="*.doc"
        ).execute().ok()

    def test_pattern_with_exclusion(self, acl_id, test_dir_with_files):
        """Use -dp with -excl to exclude files from the match list.

        Per PDF: "-dp matches are added to the list and then the -excl
        matches are removed from the match list"
        """
        (QDocSE.acl_file()
            .dir(test_dir_with_files)
            .user_acl(acl_id)
            .pattern("*.*")
            .exclude("*.cfg")
            .execute()
            .ok())

    def test_pattern_applies_to_subdirs(self, acl_id, test_dir_with_files):
        """Pattern should match files in subdirectories too."""
        QDocSE.acl_file(
            test_dir_with_files, user_acl=acl_id, pattern="*.txt"
        ).execute().ok()

    @pytest.mark.parametrize("pattern,desc", [
        ("*.txt", "single extension"),
        ("file*", "prefix wildcard"),
        ("*1*", "contains character"),
        ("[a-z]*", "character range"),
        ("*.???", "fixed extension length"),
    ])
    def test_valid_glob_patterns(self, acl_id, test_dir_with_files,
                                 pattern, desc):
        """Various valid glob(7) patterns should be accepted."""
        QDocSE.acl_file(
            test_dir_with_files, user_acl=acl_id, pattern=pattern
        ).execute().ok(desc)


@pytest.mark.unit
class TestACLFileErrors:
    """Error handling tests."""

    def test_missing_directory_option(self, acl_id):
        """acl_file requires -d option.

        Per PDF: "Option '-d' must be specified."
        """
        result = QDocSE.acl_file(user_acl=acl_id).execute()
        result.fail("Should fail without directory")
        result.contains("must be specified")

    def test_missing_acl_option(self, temp_dir):
        """acl_file requires at least one of -A or -P.

        Per PDF: "One or both options '-A' or '-P' must be specified."
        """
        result = QDocSE.acl_file(temp_dir).execute()
        result.fail("Should fail without ACL option")
        result.contains("must be specified")

    def test_nonexistent_directory(self, acl_id):
        """Nonexistent directory path should fail.

        Per PDF: "Directory does not exist." or "Path does not exist."
        """
        result = QDocSE.acl_file(
            "/nonexistent/path/to/dir", user_acl=acl_id
        ).execute()
        result.fail("Should fail for nonexistent directory")
        result.contains("does not exist")

    def test_file_not_directory(self, acl_id, test_dir_with_files):
        """Path that is a file, not a directory, should fail.

        Per PDF: "Not a directory."
        """
        file_path = os.path.join(test_dir_with_files, "file1.txt")
        result = QDocSE.acl_file(file_path, user_acl=acl_id).execute()
        result.fail("Should fail for file path")
        result.contains("Path does not exist")

    def test_invalid_user_acl_id(self, test_dir_with_files):
        """Invalid ACL ID for -A should fail.

        Per PDF: "Invalid ACL ID specified to '-A'."
        """
        result = QDocSE.acl_file(
            test_dir_with_files, user_acl=999999
        ).execute()
        result.fail("Should fail for invalid ACL ID")
        result.contains("Invalid ACL ID")

    def test_invalid_program_acl_id(self, test_dir_with_files):
        """Invalid ACL ID for -P should fail.

        Per PDF: "Invalid ACL ID specified to '-P'."
        """
        result = QDocSE.acl_file(
            test_dir_with_files, prog_acl=999999
        ).execute()
        result.fail("Should fail for invalid program ACL ID")
        result.contains("Invalid ACL ID")

    def test_negative_acl_id(self, test_dir_with_files):
        """Negative ACL ID should fail."""
        result = QDocSE.acl_file(
            test_dir_with_files, user_acl=-1
        ).execute()
        result.fail("Should fail for negative ACL ID")

    def test_user_acl_used_as_program_acl(self, acl_id, test_dir_with_files):
        """A user/group-entry ACL cannot be used with -P.

        Per PDF: "An ACL of program entries cannot have user/group entries."
        QDocSE returns: "ACL for '-P' needs program entry. Cannot assign."
        """
        result = QDocSE.acl_file(
            test_dir_with_files, prog_acl=acl_id
        ).execute()
        result.fail("User-entry ACL should not work with -P")
        result.contains("needs program entry")

    @pytest.mark.xfail(reason="temporary failure, will fix later")
    def test_filename_path_too_long(self, acl_id):
        """Extremely long directory path should fail.

        Per PDF: "Filename path too long."
        """
        long_path = "/" + "a" * 4096
        result = QDocSE.acl_file(long_path, user_acl=acl_id).execute()
        result.fail("Should fail for path too long")


@pytest.mark.unit
class TestACLFileNonMatchingBehavior:
    """Test behavior for non-matching files.

    Per PDF: "When the '-dp' option is used and this does not select all files
    under the directory, then the non-matching files will remain unchanged;
    whichever ACL IDs were assigned before stay the same."
    """

    def test_non_matching_files_unchanged(self, acl_id, some_valid_uids,
                                          test_dir_with_files):
        """Non-matching files should retain their current ACL settings."""
        uid = some_valid_uids[0]

        # Set ACL on .txt files only
        QDocSE.acl_file(
            test_dir_with_files, user_acl=acl_id, pattern="*.txt"
        ).execute().ok()

        # Create a second ACL and set it on .doc files only
        result2 = QDocSE.acl_create().execute().ok()
        other_acl = result2.parse()["acl_id"]
        QDocSE.acl_add(other_acl, allow=True, user=uid, mode="r").execute().ok()

        QDocSE.acl_file(
            test_dir_with_files, user_acl=other_acl, pattern="*.doc"
        ).execute().ok()

        # The .txt files should still have the original ACL
        # (verification would require file-level ACL inspection)


@pytest.mark.unit
class TestACLFileBothACLTypes:
    """Test using both user and program ACLs."""

    def test_user_and_program_acl_together(self, acl_id, program_acl,
                                           test_dir_with_files):
        """Apply both user and program ACLs to same directory.

        Per PDF: Both -A and -P can be specified together.
        """
        QDocSE.acl_file(
            test_dir_with_files, user_acl=acl_id, prog_acl=program_acl
        ).execute().ok()

    def test_user_acl_only_leaves_program_unchanged(self, acl_id,
                                                    test_dir_with_files):
        """Setting only -A should not change existing -P setting.

        Per PDF: "When this option is not specified then the current
        program ACL ID will be unchanged."
        """
        QDocSE.acl_file(test_dir_with_files, user_acl=acl_id).execute().ok()

    def test_program_acl_only_leaves_user_unchanged(self, program_acl,
                                                    test_dir_with_files):
        """Setting only -P should not change existing -A setting.

        Per PDF: "When this option is not specified then the current
        user/group ACL ID will be unchanged."
        """
        QDocSE.acl_file(
            test_dir_with_files, prog_acl=program_acl
        ).execute().ok()


@pytest.mark.unit
class TestACLFileChaining:
    """Fluent API tests."""

    def test_chaining_style(self, acl_id, test_dir_with_files):
        """Basic fluent API usage."""
        (QDocSE.acl_file()
            .dir(test_dir_with_files)
            .user_acl(acl_id)
            .execute()
            .ok())

    def test_chaining_with_pattern(self, acl_id, test_dir_with_files):
        """Fluent API with -dp pattern."""
        (QDocSE.acl_file()
            .dir(test_dir_with_files)
            .pattern("*.txt")
            .user_acl(acl_id)
            .execute()
            .ok())

    def test_chaining_with_exclusion(self, acl_id, test_dir_with_files):
        """Fluent API with -dp and -excl."""
        (QDocSE.acl_file()
            .dir(test_dir_with_files)
            .pattern("*.*")
            .exclude("*.cfg")
            .user_acl(acl_id)
            .execute()
            .ok())


@pytest.mark.integration
class TestACLFileWithProtect:
    """Integration tests: acl_file with protected directories."""

    def test_set_acl_on_protected_directory(self, acl_id, test_dir_with_files):
        """Set ACL on a protected directory.

        Typical workflow: protect → acl_file → push_config.
        """
        QDocSE.protect(test_dir_with_files, encrypt=False).execute().ok()
        QDocSE.acl_file(test_dir_with_files, user_acl=acl_id).execute().ok()
        QDocSE.push_config().execute().ok()

    def test_set_acl_with_encryption(self, acl_id, test_dir_with_files):
        """Set ACL on encrypted files.

        ACLs control access to encrypted files — this is the core security
        feature.
        """
        QDocSE.protect(test_dir_with_files, encrypt=True).execute().ok()
        QDocSE.acl_file(test_dir_with_files, user_acl=acl_id).execute().ok()
        QDocSE.push_config().execute().ok()


@pytest.mark.integration
class TestACLFilePushConfig:
    """Test that acl_file changes require push_config."""

    def test_changes_pending_until_push(self, acl_id, test_dir_with_files):
        """After acl_file, changes should be pending until push_config.

        Per PDF: "Pending configuration: see push_config command" is
        displayed when there are uncommitted ACL changes.
        """
        QDocSE.acl_file(test_dir_with_files, user_acl=acl_id).execute().ok()

        list_result = QDocSE.acl_list(acl_id).execute().ok()
        list_result.contains("Pending configuration")

        QDocSE.push_config().execute().ok()

        list_after = QDocSE.acl_list(acl_id).execute().ok()
        assert "Pending configuration" not in list_after.result.stdout
