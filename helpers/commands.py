"""QDocSEConsole Command Wrappers"""
import re
import logging
from typing import Any, Dict, List, Optional, TypeVar, Union
from pathlib import Path

from .executor import get_executor
from .result import ExecResult

logger = logging.getLogger(__name__)
T = TypeVar("T", bound="Command")


class Command:
    """Base command class"""

    EXECUTABLE = "QDocSEConsole"

    def __init__(self, cmd: str):
        self.cmd = cmd
        self.args: List[str] = []
        self._result: Optional[ExecResult] = None

    def build(self) -> List[str]:
        return [self.EXECUTABLE, "-c", self.cmd] + self.args

    def execute(self: T, timeout: int = 30) -> T:
        self._result = get_executor().run(self.build(), timeout)
        logger.info(self._result)
        return self

    @property
    def result(self) -> ExecResult:
        if self._result is None:
            raise RuntimeError("Call execute() first")
        return self._result

    def parse(self) -> Dict[str, Any]:
        return {"raw": self.result.stdout, "success": self.result.success}

    # Assertion helpers
    def ok(self: T, msg: str = "") -> T:
        self.result.raise_on_error(msg)
        return self

    def fail(self: T, msg: str = "") -> T:
        if self.result.success:
            raise AssertionError(f"Expected FAIL but got SUCCESS: {self}\n{msg}")
        return self

    def contains(self: T, text: str) -> T:
        if text not in (self.result.stdout + self.result.stderr):
            raise AssertionError(f"'{text}' not in output")
        return self

    # Argument helpers
    def _flag(self: T, f: str) -> T:
        self.args.append(f)
        return self

    def _opt(self: T, o: str, v: Any) -> T:
        self.args.extend([o, str(v)])
        return self

    def __str__(self) -> str:
        return " ".join(self.build())


# =============================================================================
# ACL Commands
# =============================================================================

class ACLCreate(Command):
    def __init__(self):
        super().__init__("acl_create")

    def parse(self) -> Dict[str, Any]:
        m = re.search(r"(\d+)", self.result.stdout)
        return {"acl_id": int(m.group(1)) if m else None, "success": self.result.success}


class ACLList(Command):
    """List ACLs"""
    def __init__(self, acl_id: Optional[int] = None):
        super().__init__("acl_list")
        if acl_id is not None:
            self._opt("-i", acl_id)

    def acl_id(self, id: int):
        return self._opt("-i", id)


class ACLAdd(Command):
    def __init__(
        self,
        acl_id: Optional[int] = None,
        *,
        allow: bool = True,
        user: Optional[Union[str, int]] = None,
        group: Optional[Union[str, int]] = None,
        mode: Optional[str] = None,
    ):
        super().__init__("acl_add")
        if acl_id is not None:
            self._opt("-i", acl_id)
        self._flag("-a" if allow else "-d")
        if user is not None:
            self._opt("-u", user)
        if group is not None:
            self._opt("-g", group)
        if mode:
            self._opt("-m", mode)

    # Fluent interface
    def acl_id(self, id: int): return self._opt("-i", id)
    def allow(self): return self._flag("-a")
    def deny(self): return self._flag("-d")
    def user(self, u: Union[str, int]): return self._opt("-u", u)
    def group(self, g: Union[str, int]): return self._opt("-g", g)
    def program(self, idx: int): return self._opt("-p", idx)
    def mode(self, m: str): return self._opt("-m", m)
    def time(self, spec: str): return self._opt("-t", spec)
    def backup(self): return self._flag("-b")
    def limited(self): return self._flag("-l")


class ACLRemove(Command):
    def __init__(
        self,
        acl_id: Optional[int] = None,
        *,
        entry: Optional[int] = None,
        all: bool = False,
    ):
        super().__init__("acl_remove")
        if acl_id is not None:
            self._opt("-i", acl_id)
        if entry is not None:
            self._opt("-e", entry)
        if all:
            self._flag("-A")

    def acl_id(self, id: int): return self._opt("-i", id)
    def entry(self, n: int): return self._opt("-e", n)
    def all(self): return self._flag("-A")
    def allow(self): return self._flag("-a")
    def deny(self): return self._flag("-d")
    def user(self, u: str): return self._opt("-u", u)
    def group(self, g: str): return self._opt("-g", g)


class ACLEdit(Command):
    def __init__(
        self,
        acl_id: Optional[int] = None,
        *,
        entry: Optional[int] = None,
        position: Optional[int] = None,
    ):
        super().__init__("acl_edit")
        if acl_id is not None:
            self._opt("-i", acl_id)
        if entry is not None:
            self._opt("-e", entry)
        if position is not None:
            self._opt("-p", position)

    def acl_id(self, id: int): return self._opt("-i", id)
    def entry(self, pos: int): return self._opt("-e", pos)
    def position(self, pos: int): return self._opt("-p", pos)


class ACLFile(Command):
    def __init__(
        self,
        directory: Optional[str] = None,
        *,
        user_acl: Optional[int] = None,
        prog_acl: Optional[int] = None,
        pattern: Optional[str] = None,
    ):
        super().__init__("acl_file")
        if directory:
            self._opt("-d", directory)
        if user_acl is not None:
            self._opt("-A", user_acl)
        if prog_acl is not None:
            self._opt("-P", prog_acl)
        if pattern:
            self._opt("-dp", pattern)

    def dir(self, path: str): return self._opt("-d", path)
    def pattern(self, p: str): return self._opt("-dp", p)
    def exclude(self, p: str): return self._opt("-excl", p)
    def user_acl(self, id: int): return self._opt("-A", id)
    def prog_acl(self, id: int): return self._opt("-P", id)


class ACLProgram(Command):
    def __init__(self, acl_id: Optional[int] = None, *, program: Optional[int] = None):
        super().__init__("acl_program")
        if acl_id is not None:
            self._opt("-A", acl_id)
        if program is not None:
            self._opt("-p", program)

    def acl_id(self, id: int): return self._opt("-A", id)
    def program(self, idx: int): return self._opt("-p", idx)


class ACLDestroy(Command):
    """
    Destroy/delete an entire ACL table.
    
    Per PDF page 74:
    - Destroys the specified ACL entirely when there are no entries
    - Use -f to force destruction even if ACL has entries
    - Different from acl_remove which only removes entries from ACL
    
    Options:
        -i <acl_id>  Required. The ACL ID to destroy.
        -f           Force destruction even if ACL has entries.
    """
    def __init__(self, acl_id: Optional[int] = None, *, force: bool = False):
        super().__init__("acl_destroy")
        if acl_id is not None:
            self._opt("-i", acl_id)
        if force:
            self._flag("-f")

    def acl_id(self, id: int): return self._opt("-i", id)
    def force(self): return self._flag("-f")


class PushConfig(Command):
    """
    Commit ACL configuration changes to the QDocSE system.
    
    Per PDF page 118:
    - Commits changes for authorized programs, shared libraries, and ACL configuration
    - Should review changes with acl_list, view, and view_monitored before push_config
    - Changes are not effective until push_config is executed
    """
    def __init__(self):
        super().__init__("push_config")


# =============================================================================
# Other commands
# =============================================================================

class Adjust(Command):
    def __init__(self):
        super().__init__("adjust")

    def auth_index(self, idx: int): return self._opt("-api", idx)
    def auth_path(self, path: str): return self._opt("-apf", path)
    def block_index(self, idx: int): return self._opt("-b", idx)
    def block_path(self, path: str): return self._opt("-bpf", path)
    def with_acl(self, id: int): return self._opt("-A", id)


class View(Command):
    def __init__(self):
        super().__init__("view")

    def authorized(self): return self._flag("-a")
    def blocked(self): return self._flag("-b")
    def license(self): return self._flag("-l")
    def watchpoints(self): return self._flag("-w")

    def parse(self) -> Dict[str, Any]:
        programs = []
        for line in self.result.stdout.splitlines():
            if line.strip().startswith("("):
                parts = line.split()
                if len(parts) >= 2:
                    programs.append(parts[1])
        return {"programs": programs, "success": self.result.success}


class Protect(Command):
    def __init__(self, directory: Optional[str] = None, *, encrypt: Optional[bool] = None):
        super().__init__("protect")
        if directory:
            self._opt("-d", directory)
        if encrypt is not None:
            self._opt("-e", "yes" if encrypt else "no")

    def dir(self, path: str): return self._opt("-d", path)
    def pattern(self, p: str): return self._opt("-dp", p)
    def exclude(self, p: str): return self._opt("-excl", p)
    def encrypt(self, yes: bool = True): return self._opt("-e", "yes" if yes else "no")
    def swap(self): return self._flag("-s")
    def background(self): return self._flag("-B")
    def threads(self, n: int): return self._opt("-t", n)


class Unprotect(Command):
    def __init__(self, directory: Optional[str] = None):
        super().__init__("unprotect")
        if directory:
            self._opt("-d", directory)

    def dir(self, path: str): return self._opt("-d", path)
    def pattern(self, p: str): return self._opt("-dp", p)
    def exclude(self, p: str): return self._opt("-excl", p)
    def background(self): return self._flag("-B")
