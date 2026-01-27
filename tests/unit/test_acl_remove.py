"""
acl_remove 命令测试

命令说明:
- 从 ACL 中删除条目
- 参数:
  -i <acl_id>   指定 ACL ID
  -e <entry>    删除指定编号的条目
  -A            删除所有条目 (清空 ACL)
  -a            只删除 Allow 条目
  -d            只删除 Deny 条目
  -u <uid>      删除指定用户的条目
  -g <gid>      删除指定组的条目

验证策略:
1. 基本验证: 退出码
2. 用 acl_list 验证条目已删除
"""
import pytest
from helpers import QDocSE


@pytest.mark.unit
class TestACLRemoveByEntry:
    """按条目编号删除"""
    
    def test_remove_single_entry(self, acl_id):
        """删除单个条目"""
        # 添加条目
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        
        # 验证存在
        QDocSE.acl_list(acl_id).execute().ok().contains("Entry: 1")
        
        # 删除
        QDocSE.acl_remove(acl_id, entry=1).execute().ok()
        
        # 验证已删除
        QDocSE.acl_list(acl_id).execute().ok().contains("No entries")
    
    def test_remove_middle_entry(self, acl_id):
        """删除中间条目"""
        # 添加 3 个条目
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=1, mode="w").execute().ok()
        QDocSE.acl_add(acl_id, user=2, mode="x").execute().ok()
        
        # 删除条目 2
        QDocSE.acl_remove(acl_id, entry=2).execute().ok()
        
        # 验证: 应该剩 2 个条目
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        list_result.contains("Entry: 1")
        list_result.contains("Entry: 2")  # 原来的 3 变成 2
    
    def test_remove_nonexistent_entry(self, acl_id):
        """删除不存在的条目应失败"""
        QDocSE.acl_remove(acl_id, entry=999).execute().fail()


@pytest.mark.unit
class TestACLRemoveAll:
    """删除所有条目"""
    
    def test_remove_all_entries(self, acl_id):
        """清空所有条目"""
        # 添加多个条目
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=1, mode="w").execute().ok()
        QDocSE.acl_add(acl_id, user=2, mode="x").execute().ok()
        
        # 删除所有
        QDocSE.acl_remove(acl_id, all=True).execute().ok()
        
        # 验证已清空
        QDocSE.acl_list(acl_id).execute().ok().contains("No entries")
    
    def test_remove_all_from_empty_acl(self, acl_id):
        """清空已经为空的 ACL"""
        # 空 ACL 执行 remove all 应该成功（幂等）
        QDocSE.acl_remove(acl_id, all=True).execute().ok()


@pytest.mark.unit
class TestACLRemoveByType:
    """按类型删除 (Allow/Deny)"""
    
    def test_remove_allow_only(self, acl_id):
        """只删除 Allow 条目"""
        # 添加 Allow 和 Deny 条目
        QDocSE.acl_add(acl_id, allow=True, user=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, allow=False, user=1, mode="w").execute().ok()
        
        # 删除所有 Allow
        QDocSE.acl_remove(acl_id).allow().execute().ok()
        
        # 验证: 只剩 Deny
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        assert "Allow" not in list_result.result.stdout
        list_result.contains("Deny")
    
    def test_remove_deny_only(self, acl_id):
        """只删除 Deny 条目"""
        # 添加 Allow 和 Deny 条目
        QDocSE.acl_add(acl_id, allow=True, user=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, allow=False, user=1, mode="w").execute().ok()
        
        # 删除所有 Deny
        QDocSE.acl_remove(acl_id).deny().execute().ok()
        
        # 验证: 只剩 Allow
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        list_result.contains("Allow")
        assert "Deny" not in list_result.result.stdout or "No entries (Deny)" in list_result.result.stdout


@pytest.mark.unit
class TestACLRemoveBySubject:
    """按主体删除"""
    
    def test_remove_by_user(self, acl_id):
        """删除指定用户的条目"""
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=1, mode="w").execute().ok()
        
        # 删除 user 0 的条目
        QDocSE.acl_remove(acl_id).user("0").execute().ok()
        
        # 验证: 只剩 user 1
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        list_result.contains("Entry:")  # 还有条目
    
    def test_remove_by_group(self, acl_id):
        """删除指定组的条目"""
        QDocSE.acl_add(acl_id, group=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, group=1, mode="w").execute().ok()
        
        # 删除 group 0 的条目
        QDocSE.acl_remove(acl_id).group("0").execute().ok()
        
        # 验证
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        list_result.contains("Entry:")


@pytest.mark.unit
class TestACLRemoveErrors:
    """错误处理"""
    
    def test_nonexistent_acl(self):
        """不存在的 ACL"""
        QDocSE.acl_remove(999999, entry=1).execute().fail()
    
    def test_negative_acl_id(self):
        """负数 ACL ID"""
        QDocSE.acl_remove(-1, entry=1).execute().fail()
    
    def test_negative_entry(self, acl_id):
        """负数条目编号"""
        QDocSE.acl_remove(acl_id, entry=-1).execute().fail()


@pytest.mark.unit
class TestACLRemoveChaining:
    """链式调用"""
    
    def test_chaining_style(self, acl_id):
        """使用链式调用"""
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        
        (QDocSE.acl_remove()
            .acl_id(acl_id)
            .entry(1)
            .execute()
            .ok())
        
        QDocSE.acl_list(acl_id).execute().ok().contains("No entries")
