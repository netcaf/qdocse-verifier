"""
QDocSE state checking.
"""
from dataclasses import dataclass, field
from typing import Optional, Set
from .executor import get_executor

_cached_state = None


@dataclass
class QDocSEState:
    """QDocSE system state."""
    installed: bool = False
    mode: Optional[str] = None
    license_types: Set[str] = field(default_factory=set)
    error: Optional[str] = None


def get_qdocse_state(refresh: bool = False) -> QDocSEState:
    """Get QDocSE state (cached)."""
    global _cached_state
    
    if _cached_state and not refresh:
        return _cached_state
    
    state = QDocSEState()
    executor = get_executor()
    
    # Check installation
    result = executor.run(["QDocSEConsole", "-c", "version"], timeout=10)
    if not result.success:
        state.error = "QDocSEConsole not installed"
        _cached_state = state
        return state
    state.installed = True
    
    # Check mode
    result = executor.run(["QDocSEConsole", "-c", "show_mode"], timeout=10)
    if result.success:
        out = result.stdout.lower()
        if "learning" in out:
            state.mode = "learning"
        elif "de-elevated" in out or "normal" in out:
            state.mode = "de-elevated"
        elif "elevated" in out:
            state.mode = "elevated"
        elif "unlicensed" in out:
            state.mode = "unlicensed"
    
    # Get available commands to infer license
    result = executor.run(["QDocSEConsole", "-c", "commands"], timeout=10)
    if result.success:
        cmds = result.stdout
        if any(c in cmds for c in ['acl_create', 'protect', 'adjust']):
            state.license_types.add('A')
        if 'audit' in cmds:
            state.license_types.add('C')
        if 'add_integrity_check' in cmds:
            state.license_types.add('D')
        if 'add_monitored' in cmds:
            state.license_types.add('E')
    
    _cached_state = state
    return state
