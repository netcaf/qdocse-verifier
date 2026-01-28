"""Command execution result."""
from dataclasses import dataclass


class CommandError(Exception):
    """Command execution failed."""
    pass


@dataclass
class ExecResult:
    """Command execution result with success/failure helpers."""
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
        """Raise CommandError if command failed."""
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
