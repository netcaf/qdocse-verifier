# AI Context – QDocSE Verifier

## 1. Overall Goal

Review and improve the **qdocse-verifier** project — an automated pytest-based test framework for verifying the **ACL (Access Control List) feature** introduced in **QDocSE 3.2.0**. Work has progressed through three phases: (1) understanding the project, (2) fixing ACL cleanup strategy, and (3) reviewing/strengthening individual unit test files against the PDF user guide specification.

---

## 2. Files Read (with roles)

### Documentation
- **`docs/QDocSE-User-Guide-3_2_0.md`** — Official QDocSE 3.2.0 user guide. Defines all ACL commands (`acl_add`, `acl_create`, `acl_destroy`, `acl_edit`, `acl_export`, `acl_file`, `acl_import`, `acl_list`, `acl_program`, `acl_remove`), their options, output formats, error messages, and behavioral rules (e.g., entry order determines allow/deny, ACL IDs are never reused, user/group and program entries cannot be mixed in a single ACL). Key output format: `ACL ID <n>:` lines in `acl_list` output; entries shown as `"User: <uid>"`.
- **`tests/acl_effectiveness/README.md`** — ACL effectiveness test organization (in Chinese).
- **`README.md`** — Quick start guide, CLI options, project structure overview.

### Configuration
- **`conftest.py`** (root) — pytest plugin registration, CLI option parsing (`--target`, `--host`, `--user`, etc.), auto-prerequisite checking via markers (`@pytest.mark.requires_mode()`, `@pytest.mark.requires_license()`), test report header with QDocSE state.
- **`pyproject.toml`** — Project metadata (`qdocse-test` v1.0.0), Python >= 3.9, pytest markers for `unit`, `integration`, `slow`.
- **`config/default.yaml`**, **`config/example.yaml`**, **`config/target.yaml.example`** — Executor config (local vs SSH).

### Core Helpers (`helpers/`)
- **`helpers/__init__.py`** — Exports: `QDocSE`, `Executor`, `LocalExecutor`, `SSHExecutor`, `ExecResult`, `CommandError`.
- **`helpers/client.py`** (155 lines) — `QDocSE` class: main API entry point with static methods for all commands. Executor config via `use_local()` / `use_ssh()`.
- **`helpers/commands.py`** (417 lines) — All command wrapper classes with fluent builder API. ACL commands: `ACLCreate`, `ACLList`, `ACLAdd`, `ACLRemove`, `ACLEdit`, `ACLFile`, `ACLProgram`, `ACLDestroy`, `ACLExport`, `ACLImport`, `PushConfig`. System commands: `Adjust`, `View`, `Protect`, `Unprotect`, `Encrypt`, `Unencrypt`, `ShowMode`, `SetMode`, `List`.
- **`helpers/executor.py`** (100 lines) — Abstract `Executor`, `LocalExecutor` (subprocess), `SSHExecutor` (paramiko).
- **`helpers/result.py`** (43 lines) — `ExecResult` dataclass, `CommandError` exception.
- **`helpers/state.py`** (66 lines) — `QDocSEState` dataclass, `get_qdocse_state()` with caching.
- **`helpers/system.py`** (276 lines) — `UserInfo`, `GroupInfo`, `SystemInfo` for querying `/etc/passwd` and `/etc/group`.

### Fixtures (`fixtures/`)
- **`fixtures/session.py`** — Session-level fixtures: `target_config`, `setup_executor`, `purge_stale_acls`, `module_cleanup`, `clean_state`, `elevated_mode`, `learning_mode`.
- **`fixtures/acl.py`** — ACL fixtures: `acl_id`, `acl_with_entries`, `user_acl_with_allow_deny`, `program_acl`, `multiple_acls`, `empty_acl`, `acl_with_time_window`. Plus system fixtures: `valid_uids`, `valid_gids`, `some_valid_uids`, `some_valid_gids`.
- **`fixtures/directory.py`** (196 lines) — Directory fixtures: `temp_dir`, `test_dir_with_files`, `protected_dir`, `encrypted_dir`, `nested_dir_structure`, `large_file_dir`, `sensitive_files_dir`, `protected_dir_with_acl`.

### Tests (`tests/`)
- **`tests/unit/`** (11 files) — Individual ACL command tests (`test_acl_create.py`, `test_acl_add.py`, `test_acl_destroy.py`, `test_acl_edit.py`, `test_acl_export_import.py`, `test_acl_file.py`, `test_acl_list.py`, `test_acl_program.py`, `test_acl_remove.py`), plus `test_basic.py`, `test_adjust.py`.
- **`tests/integration/`** (2 files) — `test_acl_access_control.py`, `test_workflows.py`.
- **`tests/acl_effectiveness/`** (31 files) — Organized by dimension: `access_modes/`, `access_result/`, `entry_order/`, `file_lifecycle/`, `time_rules/`, `subjects/`, `object_types/`, `encryption/`, `persistence/`, `special_cases/`.
- **`tests/acl_effectiveness/conftest.py`** — Effectiveness-specific fixtures: `temp_dir`, `protected_dir`, `encrypted_dir`, `empty_acl`, `allow_r_acl`, `allow_w_acl`, `allow_rw_acl`, `allow_rwx_acl`, `deny_acl`, `apply_acl()` helper.

### Other
- **`clean.sh`** — Cleans Python caches, IDE files, and `.git` directory. Does NOT clean QDocSE ACL state.

---

## 3. Codebase Understanding

### Architecture (4 layers)
```
Configuration (conftest.py, config/)
  └─ CLI parsing, prerequisite checks, executor selection
Execution (helpers/)
  └─ QDocSE fluent API → Command builders → Executors (local/SSH) → ExecResult
Fixtures (fixtures/)
  └─ ACL, directory, session fixtures with auto-setup
Tests (tests/)
  └─ 44 test files: unit (11), integration (2), acl_effectiveness (31)
```

### Key patterns
- **Fluent API**: `QDocSE.acl_add(acl_id, user=0, mode="rw").execute().ok().contains("text")`
- **Builder pattern**: `cmd.acl_id(1).user(1000).mode("rw").execute()`
- **Result chaining**: `.ok()`, `.fail()`, `.contains()`, `.parse()`
- **Prerequisite gating**: Auto-skip tests based on mode (elevated/learning) and license (A/C/D/E)
- **Dual executor**: Same tests run locally or over SSH

### QDocSE ACL rules (from user guide)
- All ACL commands require **License A** and **Elevated or Learning mode**
- ACL IDs are **never reused** after destruction
- Entry order determines allow/deny (**first-match semantics**, default deny)
- ACL evaluation: UID/GID match → mode match → time match; if UID matches but mode/time fails → Deny immediately; if UID doesn't match → skip to next entry; if all entries exhausted → Deny
- Mode matching asymmetry: Allow requires exact/subset match; Deny triggers on any overlap
- An ACL cannot mix user/group entries with program entries
- `push_config` must be called to commit ACL changes to the system
- `acl_list` output format: `ACL ID <n>:` per ACL, `Entry: <n>` per entry, `User: <uid>` per user entry, `"No entries (Deny)"` for empty ACLs

---

## 4. Decisions Made

1. **Pre-run purge instead of post-test cleanup** — The `purge_stale_acls` session fixture destroys all existing ACLs at the start of each `pytest` invocation. Rationale: post-test `addfinalizer` cleanup is unreliable (fails on crash/interrupt/kill), and preserving post-test state allows manual inspection of failures via `QDocSEConsole -c acl_list`.

2. **Removed all `addfinalizer` cleanup** from ACL fixtures in both `fixtures/acl.py` and `tests/acl_effectiveness/conftest.py`. The `_cleanup_acl()` helper functions were also removed.

3. **Explicit fixture dependency** — `purge_stale_acls` depends on `setup_executor` to ensure the command executor is ready before purging.

4. **Only assert spec-supported behavior** — Remove `assert id2 > id1` over-assertions; the doc says IDs are "never reused" but does not guarantee monotonic ordering.

5. **Use `some_valid_uids` fixture instead of hardcoded UIDs** — Hardcoded UIDs (0, 1, 2, 100, 200, 300) may not exist on all systems. Tests should use system-queried UIDs from fixtures.

6. **Match `"User: <uid>"` pattern for entry order verification** — Bare `stdout.find(str(uid))` is ambiguous (matches inside ACL IDs, entry numbers, etc.). Use `f"User: {uid}"` from the `acl_list` output format.

---

## 5. Files Reviewed & Modified

### `test_acl_destroy.py` — Reviewed and fixed (commit `42e18ce`)
**Changes made:**
- Removed `cleanup_acl` helper and all `try/finally` blocks (rely on session purge)
- Replaced loose `or`-chain assertion with `.fail()` + `.contains("not empty")`
- Added `.contains("is not a valid ACL ID")` to all error tests
- Added `.contains("Missing required")` to missing-option test
- Removed `assert id2 > id1` over-assertion (kept only `id2 != id1`)
- Added UID count guard (`assert len(test_uids) >= 10`)

**Remaining gaps:**
- "No ACL configuration file found" error untested (environment-dependent)

### `test_acl_create.py` — Reviewed, NOT yet fixed
**Issues identified:**
1. Inline `cleanup_acl` helper and `try/finally` blocks throughout
2. Over-assertion: `assert id2 > id1` in multiple places
3. Hardcoded UIDs 0, 1, 2 instead of `some_valid_uids` fixture
4. Loose assertion in `test_destroy_non_empty_acl_requires_force`
5. `except AssertionError` cleanup is fragile (non-assertion errors leak ACLs)
6. Loose assertion in `test_acl_zero_is_builtin_allow`
7. `TestACLCreateWithDestroyBehavior` duplicates `test_acl_destroy.py` coverage
8. Two permanently-skipped placeholder tests should be implemented or removed

### `test_acl_edit.py` — Reviewed and fixed (commit `446616c`)
**Changes made:**
- Updated docstring with all 8 position keywords, 7 documented errors, PDF examples
- Replaced hardcoded UIDs 100/200/300 with `some_valid_uids` fixture
- Added `_get_entry_order` helper using `"User: <uid>"` pattern
- Added tests for all 8 position keywords: `up`, `down`, `top`, `bottom`, `first`, `last`, `begin`, `end`
- Added 3 missing-option tests (`-e`, `-i`, `-p`) with `"Missing required"` checks
- Added boundary tests: move first entry up, move last entry down (verify `"No change"` message)
- Renamed `TestACLEditSamePosition` → `TestACLEditNoChange` with 3 no-change scenarios
- Strengthened all error tests with `.contains()` and descriptive `.fail()` messages
- Added post-condition verification to chaining test

**Remaining gaps:**
- "No ACL configuration file found" error untested (environment-dependent)
- "Error with acl_edit" — generic error, unclear trigger

---

## 6. Open Questions / Unresolved Issues

- **`test_acl_create.py` needs fixes** — Reviewed but changes not yet implemented (see section 5 above).
- **Other unit test files not yet reviewed**: `test_acl_list.py`, `test_acl_add.py` (partially reviewed in earlier commits), `test_acl_remove.py`, `test_acl_export_import.py`, `test_acl_file.py`, `test_acl_program.py`.
- **Directory/protection fixtures**: `fixtures/directory.py` and `tests/acl_effectiveness/conftest.py` still use `addfinalizer` for `unprotect` and `shutil.rmtree`. Whether to apply the same pre-run purge strategy to protected directories is undecided.
- **ACL ID 0**: The purge logic does not skip ID 0 explicitly — `acl_destroy` for ID 0 should fail gracefully (the `try/except` handles this).
- **"No ACL configuration file found" error**: Documented for multiple commands but untested everywhere. Requires a specific environment state that may not be safely reproducible.

---

## 7. Commit History (recent)

| Commit | Description |
|---|---|
| `446616c` | Rewrite acl_edit tests for full spec coverage and valid UIDs |
| `42e18ce` | Strengthen acl_destroy tests and remove inline cleanup |
| `018a793` | Add subject uniqueness tests and use valid UIDs in multi-entry test |
| `df86650` | Fix acl_add test assertions to match acl_list output format |
| `f799deb` | Expand TestACLAddTime with comprehensive time option coverage |
| `4ddefcc` | Strengthen acl_add test assertions to verify actual output |
| `74a87df` | Replace post-test ACL cleanup with pre-run purge |

---

## 8. Next Steps

- Implement fixes for `test_acl_create.py` (reviewed, issues documented above)
- Review remaining unit test files against the user guide spec: `test_acl_remove.py`, `test_acl_list.py`, `test_acl_export_import.py`, `test_acl_file.py`, `test_acl_program.py`
- Run the full test suite on a system with QDocSE installed to validate changes
- Consider whether `clean.sh` should include a QDocSE ACL purge step for manual use
