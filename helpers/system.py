"""
System utilities for QDocSE testing.

Provides functions to query system users, groups, and other OS-level
information needed for testing. Supports both local and remote (SSH) execution.
"""
import logging
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

from .executor import get_executor

logger = logging.getLogger(__name__)


@dataclass
class UserInfo:
    """System user information."""
    uid: int
    name: str
    gid: int
    home: str
    shell: str

    def __str__(self) -> str:
        return f"{self.name}({self.uid})"


@dataclass
class GroupInfo:
    """System group information."""
    gid: int
    name: str
    members: list[str]

    def __str__(self) -> str:
        return f"{self.name}({self.gid})"


class SystemInfo:
    """
    Query system user and group information.
    
    Works with both local and SSH executors by parsing /etc/passwd and /etc/group.
    Results are cached per instance for performance.
    """

    def __init__(self):
        self._users: Optional[list[UserInfo]] = None
        self._groups: Optional[list[GroupInfo]] = None

    def _load_users(self) -> list[UserInfo]:
        """Load users from /etc/passwd."""
        if self._users is not None:
            return self._users

        result = get_executor().run(["cat", "/etc/passwd"])
        users = []

        if result.success:
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) >= 7:
                    try:
                        users.append(UserInfo(
                            uid=int(parts[2]),
                            name=parts[0],
                            gid=int(parts[3]),
                            home=parts[5],
                            shell=parts[6],
                        ))
                    except (ValueError, IndexError) as e:
                        logger.debug(f"Skip invalid passwd line: {line} ({e})")

        self._users = users
        logger.info(f"Loaded {len(users)} users from system")
        return users

    def _load_groups(self) -> list[GroupInfo]:
        """Load groups from /etc/group."""
        if self._groups is not None:
            return self._groups

        result = get_executor().run(["cat", "/etc/group"])
        groups = []

        if result.success:
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) >= 4:
                    try:
                        members = parts[3].split(",") if parts[3] else []
                        groups.append(GroupInfo(
                            gid=int(parts[2]),
                            name=parts[0],
                            members=members,
                        ))
                    except (ValueError, IndexError) as e:
                        logger.debug(f"Skip invalid group line: {line} ({e})")

        self._groups = groups
        logger.info(f"Loaded {len(groups)} groups from system")
        return groups

    def get_users(self) -> list[UserInfo]:
        """Get all system users."""
        return self._load_users()

    def get_groups(self) -> list[GroupInfo]:
        """Get all system groups."""
        return self._load_groups()

    def get_uids(self, count: Optional[int] = None) -> list[int]:
        """
        Get list of valid UIDs from system.
        
        Args:
            count: Maximum number of UIDs to return. None for all.
            
        Returns:
            List of UIDs sorted by value.
        """
        uids = sorted(u.uid for u in self.get_users())
        return uids[:count] if count else uids

    def get_gids(self, count: Optional[int] = None) -> list[int]:
        """
        Get list of valid GIDs from system.
        
        Args:
            count: Maximum number of GIDs to return. None for all.
            
        Returns:
            List of GIDs sorted by value.
        """
        gids = sorted(g.gid for g in self.get_groups())
        return gids[:count] if count else gids

    def get_usernames(self, count: Optional[int] = None) -> list[str]:
        """
        Get list of usernames from system.
        
        Args:
            count: Maximum number of usernames to return. None for all.
            
        Returns:
            List of usernames sorted alphabetically.
        """
        names = sorted(u.name for u in self.get_users())
        return names[:count] if count else names

    def get_groupnames(self, count: Optional[int] = None) -> list[str]:
        """
        Get list of group names from system.
        
        Args:
            count: Maximum number of names to return. None for all.
            
        Returns:
            List of group names sorted alphabetically.
        """
        names = sorted(g.name for g in self.get_groups())
        return names[:count] if count else names

    def get_user_by_uid(self, uid: int) -> Optional[UserInfo]:
        """Get user info by UID."""
        for u in self.get_users():
            if u.uid == uid:
                return u
        return None

    def get_user_by_name(self, name: str) -> Optional[UserInfo]:
        """Get user info by username."""
        for u in self.get_users():
            if u.name == name:
                return u
        return None

    def get_group_by_gid(self, gid: int) -> Optional[GroupInfo]:
        """Get group info by GID."""
        for g in self.get_groups():
            if g.gid == gid:
                return g
        return None

    def get_group_by_name(self, name: str) -> Optional[GroupInfo]:
        """Get group info by name."""
        for g in self.get_groups():
            if g.name == name:
                return g
        return None

    def uid_exists(self, uid: int) -> bool:
        """Check if UID exists on system."""
        return self.get_user_by_uid(uid) is not None

    def gid_exists(self, gid: int) -> bool:
        """Check if GID exists on system."""
        return self.get_group_by_gid(gid) is not None

    def get_regular_users(self, min_uid: int = 1000, max_uid: int = 60000) -> list[UserInfo]:
        """
        Get regular (non-system) users.
        
        Args:
            min_uid: Minimum UID (default 1000 for most Linux systems)
            max_uid: Maximum UID (default 60000)
            
        Returns:
            List of regular users.
        """
        return [u for u in self.get_users() if min_uid <= u.uid <= max_uid]

    def get_system_users(self, max_uid: int = 999) -> list[UserInfo]:
        """
        Get system users (typically UID < 1000).
        
        Args:
            max_uid: Maximum UID for system users (default 999)
            
        Returns:
            List of system users.
        """
        return [u for u in self.get_users() if u.uid <= max_uid]

    def clear_cache(self) -> None:
        """Clear cached user/group data. Call after system changes."""
        self._users = None
        self._groups = None


# Global instance for convenience
_system_info: Optional[SystemInfo] = None


def get_system_info() -> SystemInfo:
    """Get global SystemInfo instance."""
    global _system_info
    if _system_info is None:
        _system_info = SystemInfo()
    return _system_info


def reset_system_info() -> None:
    """Reset global SystemInfo instance (clears cache)."""
    global _system_info
    _system_info = None


# Convenience functions using global instance
def get_valid_uids(count: Optional[int] = None) -> list[int]:
    """Get list of valid UIDs from system."""
    return get_system_info().get_uids(count)


def get_valid_gids(count: Optional[int] = None) -> list[int]:
    """Get list of valid GIDs from system."""
    return get_system_info().get_gids(count)


def get_valid_usernames(count: Optional[int] = None) -> list[str]:
    """Get list of valid usernames from system."""
    return get_system_info().get_usernames(count)


def get_valid_groupnames(count: Optional[int] = None) -> list[str]:
    """Get list of valid group names from system."""
    return get_system_info().get_groupnames(count)
