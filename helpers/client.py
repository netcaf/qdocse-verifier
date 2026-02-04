"""QDocSE client - main API entry point."""
from typing import Optional, Union

from .commands import (
    ACLCreate, ACLList, ACLAdd, ACLRemove, ACLEdit, ACLFile, ACLProgram,
    ACLDestroy, PushConfig, ACLExport, ACLImport, SetMode,
    Adjust, View, Protect, Unprotect, Encrypt, Unencrypt, ShowMode, List
)
from .executor import LocalExecutor, SSHExecutor, set_executor


class QDocSE:
    """QDocSEConsole test client with fluent API."""

    # Executor configuration
    @staticmethod
    def use_local() -> None:
        """Use local command executor."""
        set_executor(LocalExecutor())

    @staticmethod
    def use_ssh(
        host: str,
        *,
        user: str = "root",
        port: int = 22,
        key_file: Optional[str] = None,
        password: Optional[str] = None,
    ) -> None:
        """Use SSH executor for remote commands."""
        set_executor(SSHExecutor(host, user, port, key_file, password))

    # ACL Commands
    @staticmethod
    def acl_create() -> ACLCreate:
        return ACLCreate()

    @staticmethod
    def acl_list(acl_id: Optional[int] = None) -> ACLList:
        return ACLList(acl_id)

    @staticmethod
    def acl_add(
        acl_id: Optional[int] = None,
        *,
        allow: bool = True,
        user: Optional[Union[str, int]] = None,
        group: Optional[Union[str, int]] = None,
        mode: Optional[str] = None,
        time_start: Optional[str] = None,
        time_end: Optional[str] = None,
    ) -> ACLAdd:
        return ACLAdd(
            acl_id, allow=allow, user=user, group=group, mode=mode,
            time_start=time_start, time_end=time_end
        )

    @staticmethod
    def acl_remove(
        acl_id: Optional[int] = None,
        *,
        entry: Optional[int] = None,
        program: Optional[int] = None,
        all: bool = False,
    ) -> ACLRemove:
        return ACLRemove(acl_id, entry=entry, program=program, all=all)

    @staticmethod
    def acl_edit(
        acl_id: Optional[int] = None,
        *,
        entry: Optional[int] = None,
        position: Optional[Union[int, str]] = None,
    ) -> ACLEdit:
        return ACLEdit(acl_id, entry=entry, position=position)

    @staticmethod
    def acl_file(
        directory: Optional[str] = None,
        *,
        user_acl: Optional[int] = None,
        prog_acl: Optional[int] = None,
        pattern: Optional[str] = None,
    ) -> ACLFile:
        return ACLFile(directory, user_acl=user_acl, prog_acl=prog_acl, pattern=pattern)

    @staticmethod
    def acl_program(
        acl_id: Optional[int] = None,
        *,
        program: Optional[int] = None,
    ) -> ACLProgram:
        return ACLProgram(acl_id, program=program)

    @staticmethod
    def acl_destroy(acl_id: Optional[int] = None, *, force: bool = False) -> ACLDestroy:
        """Destroy entire ACL table. Use force=True if ACL has entries."""
        return ACLDestroy(acl_id, force=force)

    @staticmethod
    def push_config() -> PushConfig:
        """Commit ACL configuration changes to QDocSE system."""
        return PushConfig()

    @staticmethod
    def acl_export(filename: Optional[str] = None) -> ACLExport:
        """Export ACL configuration to file."""
        return ACLExport(filename)

    @staticmethod
    def acl_import(filename: Optional[str] = None) -> ACLImport:
        """Import ACL configuration from file (overwrites existing)."""
        return ACLImport(filename)

    # System Commands
    @staticmethod
    def adjust() -> Adjust:
        return Adjust()

    @staticmethod
    def view() -> View:
        return View()

    @staticmethod
    def protect(directory: Optional[str] = None, *, encrypt: Optional[bool] = None) -> Protect:
        return Protect(directory, encrypt=encrypt)

    @staticmethod
    def unprotect(directory: Optional[str] = None) -> Unprotect:
        return Unprotect(directory)

    @staticmethod
    def encrypt(directory: Optional[str] = None, *, encrypt_new_only: bool = False) -> Encrypt:
        """Encrypt files. Use encrypt_new_only=True for -N flag."""
        return Encrypt(directory, encrypt_new_only=encrypt_new_only)

    @staticmethod
    def unencrypt(directory: Optional[str] = None) -> Unencrypt:
        """Decrypt encrypted files."""
        return Unencrypt(directory)

    @staticmethod
    def show_mode() -> ShowMode:
        """Show current QDocSE operating mode."""
        return ShowMode()

    @staticmethod
    def set_mode(mode: str) -> SetMode:
        """Set QDocSE operating mode (elevated/learning/normal)."""
        return SetMode(mode)

    @staticmethod
    def list_config() -> List:
        """List protected directories and configuration."""
        return List()
