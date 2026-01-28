"""
pytest configuration - automatic prerequisite checking.

Usage:
    # Run tests - checks happen automatically
    pytest tests/ -v
    
    # Mark tests with requirements
    @pytest.mark.requires_mode("elevated", "learning")
    @pytest.mark.requires_license("A")
    def test_acl_create():
        pass

    # No marker = no requirements, always runs
    def test_show_mode():
        pass
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(__file__))

pytest_plugins = [
    "fixtures.acl",
    "fixtures.directory",
    "fixtures.session",
]


def pytest_addoption(parser):
    group = parser.getgroup("qdocse")
    group.addoption("--target", default="local", choices=["local", "ssh"])
    group.addoption("--host", default=None)
    group.addoption("--user", default=None)
    group.addoption("--password", default=None)
    group.addoption("--key-file", default=None)
    group.addoption("--port", default=None, type=int)


def pytest_configure(config):
    """Register markers."""
    config.addinivalue_line("markers", "requires_mode(*modes): require QDocSE mode")
    config.addinivalue_line("markers", "requires_license(*types): require license type")


def pytest_runtest_setup(item):
    """
    Auto-check prerequisites before each test.
    
    Only checks tests with markers. No marker = no check.
    """
    from helpers.state import get_qdocse_state
    
    mode_marker = item.get_closest_marker("requires_mode")
    license_marker = item.get_closest_marker("requires_license")
    
    # No marker, no check, just run
    if not mode_marker and not license_marker:
        return
    
    # Has marker, check state
    state = get_qdocse_state()
    
    if not state.installed:
        pytest.skip(f"QDocSE not installed: {state.error}")
    
    if mode_marker:
        required = mode_marker.args
        if state.mode not in required:
            pytest.skip(f"Requires mode {required}, current: {state.mode}")
    
    if license_marker:
        required = set(license_marker.args)
        if not (state.license_types & required):
            pytest.skip(f"Requires license {license_marker.args}, have: {state.license_types or 'none'}")


def pytest_report_header(config):
    """Show QDocSE state in test report header."""
    try:
        from helpers.state import get_qdocse_state
        state = get_qdocse_state()
        
        if state.installed:
            return [
                f"QDocSE Mode: {state.mode}",
                f"QDocSE License: {', '.join(sorted(state.license_types)) if state.license_types else 'none'}",
            ]
        else:
            return [f"QDocSE: NOT INSTALLED ({state.error})"]
    except:
        return []


@pytest.fixture(scope="session")
def qdocse_state():
    """Provide QDocSE state to tests."""
    from helpers.state import get_qdocse_state
    return get_qdocse_state()
