# ACL 生效测试 (ACL Effectiveness Tests)

测试ACL规则是否真正生效，即配置的ACL能否正确控制文件访问。

## 目录结构

```
acl_effectiveness/
├── access_result/        # 访问结果维度（明文/密文/拒绝）
├── file_lifecycle/       # 文件生命周期（增删改查）
├── time_rules/           # 时间规则
├── subjects/             # ACL主体（用户/组/程序）
├── entry_order/          # 条目顺序（Allow/Deny）
├── access_modes/         # 访问模式（r/w/x）
├── object_types/         # 对象类型（文件/目录）
├── encryption/           # 加密状态
├── persistence/          # 配置持久化
└── special_cases/        # 特殊场景
```

## 运行测试

```bash
# 运行所有生效测试
pytest tests/acl_effectiveness/ -v

# 运行特定维度
pytest tests/acl_effectiveness/time_rules/ -v

# 运行特定文件
pytest tests/acl_effectiveness/access_result/test_plaintext.py -v
```
