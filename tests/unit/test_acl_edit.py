"""
acl_edit 命令测试

命令说明:
- 编辑 ACL 条目的顺序
- 参数:
  -i <acl_id>    指定 ACL ID
  -e <entry>     要移动的条目编号
  -p <position>  目标位置 (数字, "first", "last")

验证策略:
1. 基本验证: 退出码
2. 用 acl_list 验证条目顺序变化

注意: ACL 条目顺序很重要，先匹配的规则优先
"""
import pytest
from helpers import QDocSE


@pytest.fixture
def acl_with_three_entries(acl_id):
    """创建有 3 个条目的 ACL，用于测试移动"""
    # 条目 1: user 100
    QDocSE.acl_add(acl_id, user=100, mode="r").execute().ok()
    # 条目 2: user 200
    QDocSE.acl_add(acl_id, user=200, mode="w").execute().ok()
    # 条目 3: user 300
    QDocSE.acl_add(acl_id, user=300, mode="x").execute().ok()
    return acl_id


@pytest.mark.unit
class TestACLEditPosition:
    """条目位置调整测试"""
    
    def test_move_to_first(self, acl_with_three_entries):
        """移动到第一位"""
        acl_id = acl_with_three_entries
        
        # 把条目 3 (user 300) 移到第一位
        QDocSE.acl_edit(acl_id, entry=3, position="first").execute().ok()
        
        # 验证: user 300 现在应该在最前面
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        stdout = list_result.result.stdout
        
        # 300 应该在 100 和 200 之前
        pos_300 = stdout.find("300")
        pos_100 = stdout.find("100")
        pos_200 = stdout.find("200")
        assert pos_300 < pos_100, "Entry 300 should be first"
        assert pos_300 < pos_200, "Entry 300 should be before 200"
    
    def test_move_to_last(self, acl_with_three_entries):
        """移动到最后"""
        acl_id = acl_with_three_entries
        
        # 把条目 1 (user 100) 移到最后
        QDocSE.acl_edit(acl_id, entry=1, position="last").execute().ok()
        
        # 验证: user 100 现在应该在最后
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        stdout = list_result.result.stdout
        
        pos_100 = stdout.find("100")
        pos_200 = stdout.find("200")
        pos_300 = stdout.find("300")
        assert pos_100 > pos_200, "Entry 100 should be after 200"
        assert pos_100 > pos_300, "Entry 100 should be last"
    
    def test_move_to_specific_position(self, acl_with_three_entries):
        """移动到指定位置"""
        acl_id = acl_with_three_entries
        
        # 把条目 3 移到位置 2
        QDocSE.acl_edit(acl_id, entry=3, position=2).execute().ok()
        
        # 验证顺序变为: 100, 300, 200
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        stdout = list_result.result.stdout
        
        pos_100 = stdout.find("100")
        pos_300 = stdout.find("300")
        pos_200 = stdout.find("200")
        assert pos_100 < pos_300 < pos_200, "Order should be 100, 300, 200"


@pytest.mark.unit
class TestACLEditSamePosition:
    """移动到相同位置（无操作）"""
    
    def test_move_to_same_position(self, acl_with_three_entries):
        """移动到当前位置应该成功（幂等）"""
        acl_id = acl_with_three_entries
        
        # 条目 2 移到位置 2
        QDocSE.acl_edit(acl_id, entry=2, position=2).execute().ok()
        
        # 顺序不变
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        stdout = list_result.result.stdout
        
        pos_100 = stdout.find("100")
        pos_200 = stdout.find("200")
        pos_300 = stdout.find("300")
        assert pos_100 < pos_200 < pos_300, "Order should remain unchanged"


@pytest.mark.unit
class TestACLEditErrors:
    """错误处理"""
    
    def test_nonexistent_entry(self, acl_id):
        """移动不存在的条目"""
        QDocSE.acl_edit(acl_id, entry=999, position=1).execute().fail()
    
    def test_invalid_position(self, acl_with_three_entries):
        """无效的目标位置"""
        acl_id = acl_with_three_entries
        QDocSE.acl_edit(acl_id, entry=1, position=999).execute().fail()
    
    def test_negative_entry(self, acl_id):
        """负数条目编号"""
        QDocSE.acl_edit(acl_id, entry=-1, position=1).execute().fail()
    
    def test_negative_position(self, acl_with_three_entries):
        """负数位置"""
        acl_id = acl_with_three_entries
        QDocSE.acl_edit(acl_id, entry=1, position=-1).execute().fail()
    
    def test_nonexistent_acl(self):
        """不存在的 ACL"""
        QDocSE.acl_edit(999999, entry=1, position=1).execute().fail()


@pytest.mark.unit
class TestACLEditChaining:
    """链式调用"""
    
    def test_chaining_style(self, acl_with_three_entries):
        """使用链式调用"""
        acl_id = acl_with_three_entries
        
        (QDocSE.acl_edit()
            .acl_id(acl_id)
            .entry(3)
            .position("first")
            .execute()
            .ok())
