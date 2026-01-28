"""QDocSE Verifier Fixtures Package."""

from fixtures.acl import (
    acl_id,
    acl_with_entries,
    user_acl_with_allow_deny,
    program_acl,
    multiple_acls,
    empty_acl,
    acl_with_time_window,
)

from fixtures.directory import (
    temp_dir,
    test_dir_with_files,
    protected_dir,
    encrypted_dir,
    nested_dir_structure,
    large_file_dir,
    sensitive_files_dir,
    protected_dir_with_acl,
    protected_test_dir,
    encrypted_test_dir,
)

from fixtures.session import (
    target_config,
    setup_executor,
    session_cleanup,
    module_cleanup,
    clean_state,
    elevated_mode,
    learning_mode,
)

__all__ = [
    # ACL
    "acl_id", "acl_with_entries", "user_acl_with_allow_deny",
    "program_acl", "multiple_acls", "empty_acl", "acl_with_time_window",
    # Directory
    "temp_dir", "test_dir_with_files", "protected_dir", "encrypted_dir",
    "nested_dir_structure", "large_file_dir", "sensitive_files_dir",
    "protected_dir_with_acl", "protected_test_dir", "encrypted_test_dir",
    # Session
    "target_config", "setup_executor", "session_cleanup",
    "module_cleanup", "clean_state", "elevated_mode", "learning_mode",
]
