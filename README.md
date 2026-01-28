# QDocSE Verifier

Automated testing framework for QDocSEConsole commands.

## Quick Start

```bash
# Install dependencies
pip install pytest paramiko pyyaml

# Run tests locally
pytest tests/

# Run tests against remote target
pytest tests/ --target=ssh --host=192.168.1.100 --user=root
```

## Configuration

Priority: CLI > Environment > config/target.yaml > Defaults

### CLI Options
```
--target    local|ssh (default: local)
--host      SSH host address
--user      SSH username (default: root)
--password  SSH password
--key-file  SSH private key path
--port      SSH port (default: 22)
```

### Environment Variables
```
TARGET_HOST, TARGET_USER, SSH_PASSWORD, SSH_KEY_FILE, SSH_PORT
```

## Project Structure

```
├── conftest.py           # pytest config
├── fixtures/             # Test fixtures
│   ├── acl.py            # ACL fixtures
│   ├── directory.py      # Directory fixtures
│   └── session.py        # Session fixtures
├── helpers/              # Command wrappers
│   ├── client.py         # QDocSE API
│   ├── commands.py       # Command classes
│   ├── executor.py       # Local/SSH executors
│   └── result.py         # Result class
└── tests/
    ├── unit/             # Unit tests
    └── integration/      # Integration tests
```

## Usage

```python
from helpers import QDocSE

# Create ACL
result = QDocSE.acl_create().execute()
acl_id = result.parse()["acl_id"]

# Add entry
QDocSE.acl_add(acl_id, user=0, mode="rw").execute().ok()

# Commit changes
QDocSE.push_config().execute()

# Cleanup
QDocSE.acl_destroy(acl_id, force=True).execute()
QDocSE.push_config().execute()
```

## Fixtures

### ACL
- `acl_id` - Empty ACL with auto-cleanup
- `acl_with_entries` - ACL with 3 read entries
- `user_acl_with_allow_deny` - ACL with allow/deny rules
- `empty_acl` - Empty ACL (denies all)
- `acl_with_time_window` - ACL with time restrictions

### Directory
- `temp_dir` - Basic temp directory
- `test_dir_with_files` - Multiple file types
- `protected_dir` - Protected (no encryption)
- `encrypted_dir` - Protected with TDE
- `nested_dir_structure` - Nested directories

### Session
- `target_config` - Target configuration
- `clean_state` - Ensure clean state
- `elevated_mode` - Ensure Elevated mode
- `learning_mode` - Ensure Learning mode
