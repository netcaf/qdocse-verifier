"""
pytest 配置和 fixtures

目标配置优先级 (从高到低):
1. 命令行参数: --host, --user, --password, --key-file
2. 环境变量: TARGET_HOST, TARGET_USER, SSH_PASSWORD, SSH_KEY_FILE
3. 配置文件: config/target.yaml
"""
import os
import sys
from pathlib import Path

import pytest

# 让 helpers 可以被导入
sys.path.insert(0, os.path.dirname(__file__))

from helpers import QDocSE


# =============================================================================
# 配置加载
# =============================================================================

def load_target_config():
    """从配置文件加载目标配置"""
    config_file = Path(__file__).parent / "config" / "target.yaml"
    if config_file.exists():
        try:
            import yaml
            with open(config_file) as f:
                return yaml.safe_load(f) or {}
        except ImportError:
            pass
    return {}


# =============================================================================
# CLI 选项
# =============================================================================

def pytest_addoption(parser):
    group = parser.getgroup("qdocse")
    group.addoption("--target", default="local", choices=["local", "ssh"])
    group.addoption("--host", default=None, help="SSH host")
    group.addoption("--user", default=None, help="SSH user")
    group.addoption("--password", default=None, help="SSH password")
    group.addoption("--key-file", default=None, help="SSH key file")
    group.addoption("--port", default=None, type=int, help="SSH port")


def pytest_report_header(config):
    target = config.getoption("--target")
    host = config.getoption("--host") or os.environ.get("TARGET_HOST")
    return [f"Target: {target}" + (f" ({host})" if host else " (localhost)")]


# =============================================================================
# 执行器设置
# =============================================================================

@pytest.fixture(scope="session")
def target_config(request):
    """
    获取目标配置，按优先级合并:
    命令行 > 环境变量 > 配置文件 > 默认值
    """
    # 默认值
    config = {
        "host": None,
        "user": "root",
        "password": None,
        "key_file": None,
        "port": 22,
    }
    
    # 配置文件 (最低优先级)
    file_config = load_target_config()
    if file_config:
        config.update({k: v for k, v in file_config.items() if v is not None})
    
    # 环境变量
    env_mapping = {
        "host": "TARGET_HOST",
        "user": "TARGET_USER", 
        "password": "SSH_PASSWORD",
        "key_file": "SSH_KEY_FILE",
        "port": "SSH_PORT",
    }
    for key, env_var in env_mapping.items():
        env_val = os.environ.get(env_var)
        if env_val:
            config[key] = int(env_val) if key == "port" else env_val
    
    # 命令行参数 (最高优先级)
    cli_mapping = {
        "host": "--host",
        "user": "--user",
        "password": "--password",
        "key_file": "--key-file",
        "port": "--port",
    }
    for key, opt in cli_mapping.items():
        cli_val = request.config.getoption(opt)
        if cli_val is not None:
            config[key] = cli_val
    
    # 如果指定了 --target=ssh 但没有 host，标记一下
    if request.config.getoption("--target") == "ssh":
        config["_ssh_mode"] = True
    
    return config


@pytest.fixture(scope="session", autouse=True)
def setup_executor(target_config):
    """根据配置设置执行器"""
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


# =============================================================================
# 常用 Fixtures
# =============================================================================

@pytest.fixture
def acl_id(request):
    """
    创建临时 ACL，测试后自动清理
    
    Note:
        使用 acl_destroy 删除整个 ACL 表（不只是条目）
        acl_destroy -f 强制删除（即使有条目）
        必须调用 push_config 提交更改，否则会残留 "Pending configuration"
    """
    result = QDocSE.acl_create().execute()
    
    if result.result.failed:
        pytest.skip(f"Cannot create ACL: {result.result.stderr}")
    
    aid = result.parse().get("acl_id")
    if aid is None:
        pytest.fail(f"Failed to parse ACL ID: {result.result.stdout}")
    
    def cleanup():
        # 使用 acl_destroy -f 删除整个 ACL 表（而不是 acl_remove）
        QDocSE.acl_destroy(aid, force=True).execute()
        # 必须 push_config 提交更改，否则会残留 "Pending configuration"
        QDocSE.push_config().execute()
    
    request.addfinalizer(cleanup)
    return aid


@pytest.fixture
def acl_with_entries(acl_id):
    """带有 3 个条目的 ACL"""
    for uid in [0, 1, 2]:
        QDocSE.acl_add(acl_id, user=uid, mode="r").execute().ok()
    return acl_id


@pytest.fixture
def temp_dir(tmp_path):
    """临时测试目录"""
    d = tmp_path / "test_data"
    d.mkdir()
    (d / "file1.txt").write_text("content1")
    (d / "file2.txt").write_text("content2")
    return str(d)


@pytest.fixture(scope="session", autouse=True)
def session_cleanup():
    """
    Session 级别的安全清理。
    
    确保所有测试结束后：
    1. 没有残留的 "Pending configuration"
    2. 系统状态干净
    
    这是一个 safety net，即使个别测试清理失败，
    session 结束时也会尝试 push_config。
    """
    yield
    
    # Session 结束时，确保没有 pending configuration
    try:
        result = QDocSE.push_config().execute()
        if result.result.success:
            print("\n[Session Cleanup] push_config executed successfully")
    except Exception as e:
        print(f"\n[Session Cleanup] push_config failed: {e}")
