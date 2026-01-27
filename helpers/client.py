"""QDocSE Client Entry"""

from typing import Optional, Union

from .commands import (
    ACLCreate, ACLList, ACLAdd, ACLRemove, ACLEdit, ACLFile, ACLProgram,
    ACLDestroy, PushConfig,
    Adjust, View, Protect, Unprotect
)
from .executor import LocalExecutor, SSHExecutor, set_executor


class QDocSE:
    """
    QDocSEConsole Test Client
    
    Usage:
        QDocSE.use_ssh("192.168.1.100")
        QDocSE.acl_add(1, user=0, mode="r").execute().ok()
    """

    # Executor configuration
    @staticmethod
    def use_local() -> None:
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
        """
        Set SSH executor for remote commands.

        Args:
            host: Remote host address
            user: SSH user, defaults to "root"
            port: SSH port, defaults to 22
            key_file: Optional path to private key
            password: Optional password
        """
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
    ) -> ACLAdd:
        return ACLAdd(acl_id, allow=allow, user=user, group=group, mode=mode)

    @staticmethod
    def acl_remove(
        acl_id: Optional[int] = None,
        *,
        entry: Optional[int] = None,
        all: bool = False,
    ) -> ACLRemove:
        return ACLRemove(acl_id, entry=entry, all=all)

    @staticmethod
    def acl_edit(
        acl_id: Optional[int] = None,
        *,
        entry: Optional[int] = None,
        position: Optional[int] = None,
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
        """
        Destroy/delete an entire ACL table.
        
        Args:
            acl_id: The ACL ID to destroy
            force: If True, destroy even if ACL has entries
            
        Note:
            - This DELETES the entire ACL table (not just entries)
            - Use acl_remove() to remove entries from an ACL
            - ACL IDs are never reused after destruction
        """
        return ACLDestroy(acl_id, force=force)

    @staticmethod
    def push_config() -> PushConfig:
        """
        Commit ACL configuration changes to the QDocSE system.
        
        Note:
            - ACL changes are NOT effective until push_config is called
            - Review changes with acl_list() before pushing
        """
        return PushConfig()

    # Other Commands
    @staticmethod
    def adjust() -> Adjust:
        return Adjust()

    @staticmethod
    def view() -> View:
        return View()

    @staticmethod
    def protect(
        directory: Optional[str] = None,
        *,
        encrypt: Optional[bool] = None,
    ) -> Protect:
        return Protect(directory, encrypt=encrypt)

    @staticmethod
    def unprotect(directory: Optional[str] = None) -> Unprotect:
        return Unprotect(directory)
