"""
acl_list 命令测试

命令说明:
- 列出所有 ACL 或指定 ACL 的条目
- 参数: -i <acl_id> 可选，指定要显示的 ACL

输出格式:
- "ACL ID <n>: No entries (Deny)" - 空 ACL
- "ACL ID <n>: Entry: <m> ..." - 有条目的 ACL
- "Pending configuration: See push_config command." - 有未推送的配置

验证策略:
1. 基本验证: 退出码 + 输出格式
2. 结合 acl_create/acl_add 验证列表内容正确
"""
import pytest
from helpers import QDocSE


def cleanup_acl(acl_id: int) -> None:
    """
    Standard cleanup for ACL tests.
    
    1. Destroy ACL table (with force to handle non-empty ACLs)
    2. Push config to commit changes and clear "Pending configuration"
    
    Note: acl_remove only removes ENTRIES, not the ACL table itself!
    """
    QDocSE.acl_destroy(acl_id, force=True).execute()
    QDocSE.push_config().execute()


@pytest.mark.unit
class TestACLListBasic:
    """基本功能测试"""
    
    def test_list_all(self):
        """列出所有 ACL"""
        # 先创建一个 ACL 确保有内容
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        try:
            # 列出所有
            list_result = QDocSE.acl_list().execute().ok()
            list_result.contains(f"ACL ID {acl_id}")
        finally:
            # 清理: 使用 acl_destroy (不是 acl_remove!)
            cleanup_acl(acl_id)
    
    def test_list_specific_acl(self):
        """列出指定 ACL"""
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        try:
            # 只列出这个 ACL
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            list_result.contains(f"ACL ID {acl_id}")
        finally:
            # 清理: 使用 acl_destroy (不是 acl_remove!)
            cleanup_acl(acl_id)
    
    def test_empty_acl_shows_no_entries(self):
        """空 ACL 显示 No entries (Deny)"""
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        try:
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            list_result.contains("No entries (Deny)")
        finally:
            # 清理: 使用 acl_destroy (不是 acl_remove!)
            cleanup_acl(acl_id)


@pytest.mark.unit
class TestACLListWithEntries:
    """有条目时的列表测试"""
    
    def test_list_shows_entries(self, acl_id):
        """添加条目后应显示条目信息"""
        # 添加一个条目
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        
        # 验证列表
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        list_result.contains("Entry:")
        list_result.contains("Allow")  # 默认是 Allow
    
    def test_list_shows_multiple_entries(self, acl_id):
        """多个条目应该都显示"""
        # 添加多个条目
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=1, mode="rw").execute().ok()
        QDocSE.acl_add(acl_id, allow=False, user=2, mode="w").execute().ok()
        
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        
        # 应该有 Allow 和 Deny 条目
        list_result.contains("Allow")
        list_result.contains("Deny")
    
    def test_list_shows_entry_numbers(self, acl_id):
        """条目应该有编号"""
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=1, mode="w").execute().ok()
        
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        
        # 条目编号从 1 开始
        list_result.contains("Entry: 1")
        list_result.contains("Entry: 2")


@pytest.mark.unit
class TestACLListPendingConfig:
    """未推送配置的提示测试"""
    
    def test_shows_pending_message(self, acl_id):
        """修改后应显示 pending 提示"""
        # 添加条目（产生未推送的配置）
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        list_result.contains("Pending configuration")


@pytest.mark.unit
class TestACLListErrors:
    """错误处理测试"""
    
    def test_nonexistent_acl(self):
        """查询不存在的 ACL"""
        result = QDocSE.acl_list(999999).execute()
        # 根据实际行为决定是 fail() 还是检查特定错误信息
        # 这里假设会失败
        result.fail()
    
    def test_negative_acl_id(self):
        """负数 ACL ID"""
        result = QDocSE.acl_list(-1).execute()
        result.fail()
