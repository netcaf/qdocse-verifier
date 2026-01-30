"""Session-level fixtures for test configuration and cleanup."""
import re
import os
import logging
import pytest
from helpers import QDocSE

logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def target_config(request):
    """Get target config: CLI > env > file > defaults."""
    from pathlib import Path

    config = {
        "host": None,
        "user": "root",
        "password": None,
        "key_file": None,
        "port": 22,
    }

    # Load from config file
    config_file = Path(__file__).parent.parent / "config" / "target.yaml"
    if config_file.exists():
        try:
            import yaml
            with open(config_file) as f:
                file_config = yaml.safe_load(f) or {}
                config.update({k: v for k, v in file_config.items() if v is not None})
        except ImportError:
            pass

    # Override from environment
    env_mapping = {
        "host": "TARGET_HOST",
        "user": "TARGET_USER",
        "password": "SSH_PASSWORD",
        "key_file": "SSH_KEY_FILE",
        "port": "SSH_PORT",
    }
    for key, env_var in env_mapping.items():
        if env_val := os.environ.get(env_var):
            config[key] = int(env_val) if key == "port" else env_val

    # Override from CLI
    cli_mapping = {
        "host": "--host",
        "user": "--user",
        "password": "--password",
        "key_file": "--key-file",
        "port": "--port",
    }
    for key, opt in cli_mapping.items():
        if (cli_val := request.config.getoption(opt)) is not None:
            config[key] = cli_val

    if request.config.getoption("--target") == "ssh":
        config["_ssh_mode"] = True

    return config


@pytest.fixture(scope="session", autouse=True)
def setup_executor(target_config):
    """Setup command executor based on config (SSH or local)."""
    cfg = target_config

    if cfg.get("host"):
        QDocSE.use_ssh(
            host=cfg["host"],
            user=cfg["user"],
            port=cfg["port"],
            key_file=cfg["key_file"],
            password=cfg["password"],
        )
        print(f"\n[Executor] SSH: {cfg['user']}@{cfg['host']}:{cfg['port']}")
    elif cfg.get("_ssh_mode"):
        pytest.exit("SSH mode requires --host or TARGET_HOST")
    else:
        QDocSE.use_local()
        print("\n[Executor] Local")

    yield
    QDocSE.use_local()


@pytest.fixture(scope="session", autouse=True)
def purge_stale_acls(setup_executor):
    """Purge all existing ACLs before test session starts.

    This ensures a clean slate regardless of how previous runs ended
    (crash, interrupt, failed cleanup, etc.).  Post-test state is
    deliberately preserved so failures can be inspected manually via
    ``QDocSEConsole -c acl_list``.
    """
    try:
        result = QDocSE.acl_list().execute()
        if result.result.success:
            acl_ids = [int(m) for m in re.findall(r"ACL ID (\d+)", result.result.stdout)]
            destroyed = 0
            for aid in acl_ids:
                try:
                    QDocSE.acl_destroy(aid, force=True).execute()
                    destroyed += 1
                except Exception:
                    logger.warning("Failed to destroy ACL ID %s", aid)
            if destroyed:
                QDocSE.push_config().execute()
                logger.info("[Pre-run purge] Destroyed %d stale ACL(s)", destroyed)
            else:
                logger.info("[Pre-run purge] No stale ACLs found")
    except Exception as e:
        logger.warning("[Pre-run purge] Could not list ACLs: %s", e)
    yield


@pytest.fixture(scope="module")
def module_cleanup():
    """Module-level cleanup: push_config after each module."""
    yield
    try:
        QDocSE.push_config().execute()
    except Exception:
        pass


@pytest.fixture
def clean_state():
    """Ensure clean state before and after test."""
    QDocSE.push_config().execute()
    yield
    QDocSE.push_config().execute()


def _get_current_mode():
    """Parse current QDocSE mode from show_mode output."""
    result = QDocSE.show_mode().execute()
    if result.result.success:
        output = result.result.stdout.lower()
        if "learning" in output:
            return "learning"
        if "elevated" in output:
            return "elevated"
        if "normal" in output or "de-elevated" in output:
            return "normal"
    return None


@pytest.fixture
def elevated_mode(request):
    """Ensure QDocSE is in Elevated mode, restore original after test."""
    original_mode = _get_current_mode()

    if original_mode != "elevated":
        set_result = QDocSE.set_mode("elevated").execute()
        if set_result.result.failed:
            pytest.skip(f"Cannot switch to Elevated mode: {set_result.result.stderr}")
        QDocSE.push_config().execute()

    yield original_mode

    if original_mode and original_mode != "elevated":
        QDocSE.set_mode(original_mode).execute()
        QDocSE.push_config().execute()


@pytest.fixture
def learning_mode(request):
    """Ensure QDocSE is in Learning mode, restore original after test."""
    original_mode = _get_current_mode()

    if original_mode != "learning":
        set_result = QDocSE.set_mode("learning").execute()
        if set_result.result.failed:
            pytest.skip(f"Cannot switch to Learning mode: {set_result.result.stderr}")
        QDocSE.push_config().execute()

    yield original_mode

    if original_mode and original_mode != "learning":
        QDocSE.set_mode(original_mode).execute()
        QDocSE.push_config().execute()
