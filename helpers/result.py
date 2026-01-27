"""执行结果"""
from dataclasses import dataclass


class CommandError(Exception):
    """命令执行错误"""
    pass


@dataclass
class ExecResult:
    """命令执行结果"""
    command: str
    stdout: str
    stderr: str
    returncode: int
    
    @property
    def success(self) -> bool:
        return self.returncode == 0
    
    @property
    def failed(self) -> bool:
        return not self.success
    
    def raise_on_error(self, msg: str = "") -> "ExecResult":
        """失败时抛出异常"""
        if self.failed:
            error = (
                f"Command failed (exit={self.returncode})\n"
                f"Command: {self.command}\n"
                f"Stdout: {self.stdout[:300] or '(empty)'}\n"
                f"Stderr: {self.stderr[:300] or '(empty)'}"
            )
            if msg:
                error = f"{msg}\n{error}"
            raise CommandError(error)
        return self
    
    def __str__(self) -> str:
        status = "✓" if self.success else "✗"
        return f"[{status}] {self.command} -> {self.returncode}"
