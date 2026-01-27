# QDocSE Console 测试套件

针对 `QDocSEConsole` 命令行工具的自动化测试。

## 项目结构

```
qdocse-test/
├── pyproject.toml          # pytest 配置
├── conftest.py             # fixtures + CLI options
│
├── helpers/                # 测试辅助库
│   ├── __init__.py
│   ├── executor.py         # 命令执行器 (Local/SSH)
│   ├── commands.py         # QDocSE 命令封装
│   └── result.py           # 执行结果
│
├── tests/                  # 测试用例
│   ├── unit/               # 单元测试 (单个命令)
│   │   ├── test_acl_add.py
│   │   ├── test_acl_create.py
│   │   └── ...
│   └── integration/        # 集成测试 (端到端流程)
│       └── test_workflows.py
│
├── config/                 # 配置文件
│   └── target.yaml.example # 目标服务器配置示例
└── reports/                # 测试报告
```

## 目标配置

三种方式配置测试目标，优先级从高到低：

### 方式1: 命令行参数 (最高优先级)
```bash
pytest --host=192.168.1.100 --user=root --password=mypass
pytest --host=192.168.1.100 --user=root --key-file=~/.ssh/id_rsa
pytest --host=192.168.1.100 --port=2222 --user=admin
```

### 方式2: 环境变量
```bash
export TARGET_HOST=192.168.1.100
export TARGET_USER=root
export SSH_PASSWORD=mypass
# 或
export SSH_KEY_FILE=~/.ssh/id_rsa

pytest
```

### 方式3: 配置文件 (推荐日常使用)
```bash
# 复制示例配置
cp config/target.yaml.example config/target.yaml

# 编辑填入实际值
vim config/target.yaml
```

```yaml
# config/target.yaml
host: 192.168.1.100
user: root
port: 22
password: your_password
# 或 key_file: ~/.ssh/id_rsa
```

然后直接运行:
```bash
pytest
```

## 运行测试

```bash
# 本地执行 (不连接远程)
pytest

# 远程执行 (使用配置文件)
pytest

# 远程执行 (命令行指定)
pytest --host=192.168.1.100 --user=root --password=xxx

# 仅单元测试
pytest tests/unit/ -m unit

# 仅运行某个测试文件
pytest tests/unit/test_acl_create.py

# 生成 HTML 报告
pytest --html=reports/report.html
```

## 示例

```python
from helpers import QDocSE

# 创建 ACL 并添加条目
result = QDocSE.acl_create().execute()
acl_id = result.parse()["acl_id"]

QDocSE.acl_add(acl_id, user=0, mode="rw").execute().ok()

# 验证
QDocSE.acl_list(acl_id).execute().ok().contains("Entry:")
```
