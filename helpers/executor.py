"""Command executors for local and SSH execution."""
import subprocess
import logging
from abc import ABC, abstractmethod
from typing import Optional

from .result import ExecResult

logger = logging.getLogger(__name__)


class Executor(ABC):
    """Base executor interface."""

    @abstractmethod
    def run(self, cmd: list[str], timeout: int = 30) -> ExecResult:
        pass

    def close(self) -> None:
        pass


class LocalExecutor(Executor):
    """Execute commands locally via subprocess."""

    def run(self, cmd: list[str], timeout: int = 30) -> ExecResult:
        cmd_str = " ".join(cmd)
        logger.debug(f"[Local] {cmd_str}")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return ExecResult(cmd_str, r.stdout.strip(), r.stderr.strip(), r.returncode)
        except subprocess.TimeoutExpired:
            return ExecResult(cmd_str, "", "Timeout", -1)
        except FileNotFoundError:
            return ExecResult(cmd_str, "", f"Command not found: {cmd[0]}", -2)


class SSHExecutor(Executor):
    """Execute commands remotely via SSH."""

    def __init__(
        self,
        host: str,
        user: str = "root",
        port: int = 22,
        key_file: Optional[str] = None,
        password: Optional[str] = None,
    ):
        import paramiko
        self.host = host
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        kwargs = {"hostname": host, "username": user, "port": port}
        if key_file:
            kwargs["key_filename"] = key_file
        if password:
            kwargs["password"] = password

        logger.info(f"[SSH] Connecting {user}@{host}")
        self.client.connect(**kwargs)

    def run(self, cmd: list[str], timeout: int = 30) -> ExecResult:
        cmd_str = " ".join(cmd)
        logger.debug(f"[SSH] {cmd_str}")
        try:
            _, stdout, stderr = self.client.exec_command(cmd_str, timeout=timeout)
            code = stdout.channel.recv_exit_status()
            return ExecResult(
                cmd_str,
                stdout.read().decode().strip(),
                stderr.read().decode().strip(),
                code,
            )
        except Exception as e:
            return ExecResult(cmd_str, "", str(e), -1)

    def close(self) -> None:
        self.client.close()


# Global executor instance
_executor: Optional[Executor] = None


def get_executor() -> Executor:
    """Get current executor (default: LocalExecutor)."""
    global _executor
    if _executor is None:
        _executor = LocalExecutor()
    return _executor


def set_executor(executor: Executor) -> None:
    """Set global executor, closing previous if exists."""
    global _executor
    if _executor:
        _executor.close()
    _executor = executor
