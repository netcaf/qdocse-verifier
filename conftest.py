"""
pytest configuration for QDocSE testing.

Config priority (high to low):
1. CLI: --host, --user, --password, --key-file
2. Env: TARGET_HOST, TARGET_USER, SSH_PASSWORD, SSH_KEY_FILE
3. File: config/target.yaml
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

pytest_plugins = [
    "fixtures.acl",
    "fixtures.directory",
    "fixtures.session",
]


def pytest_addoption(parser):
    """Add CLI options for target configuration."""
    group = parser.getgroup("qdocse")
    group.addoption("--target", default="local", choices=["local", "ssh"])
    group.addoption("--host", default=None, help="SSH host")
    group.addoption("--user", default=None, help="SSH user")
    group.addoption("--password", default=None, help="SSH password")
    group.addoption("--key-file", default=None, help="SSH key file")
    group.addoption("--port", default=None, type=int, help="SSH port")


def pytest_report_header(config):
    """Show target info in test report header."""
    target = config.getoption("--target")
    host = config.getoption("--host") or os.environ.get("TARGET_HOST")
    return [f"Target: {target}" + (f" ({host})" if host else " (localhost)")]
