"""
acl_add 命令测试

命令说明:
- 向 ACL 添加条目
- 参数:
  -i <acl_id>   指定 ACL ID
  -a            Allow 条目 (默认)
  -d            Deny 条目
  -u <uid>      用户 UID
  -g <gid>      组 GID
  -m <mode>     权限模式 (r/w/x 组合)
  -t <time>     时间规格
  -p <index>    程序索引
  -b            备份标志
  -l            限制标志

验证策略:
1. 基本验证: 退出码
2. 用 acl_list 验证条目已添加
"""
import pytest
from helpers import QDocSE


@pytest.mark.unit
class TestACLAddBasic:
    """基本添加功能"""
    
    def test_add_user_entry(self, acl_id):
        """添加用户条目"""
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        
        # 验证
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        list_result.contains("Entry:")
    
    def test_add_group_entry(self, acl_id):
        """添加组条目"""
        QDocSE.acl_add(acl_id, group=0, mode="r").execute().ok()
        
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        list_result.contains("Entry:")
    
    def test_add_allow_entry(self, acl_id):
        """添加 Allow 条目"""
        QDocSE.acl_add(acl_id, allow=True, user=0, mode="r").execute().ok()
        
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        list_result.contains("Allow")
    
    def test_add_deny_entry(self, acl_id):
        """添加 Deny 条目"""
        QDocSE.acl_add(acl_id, allow=False, user=0, mode="w").execute().ok()
        
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        list_result.contains("Deny")


@pytest.mark.unit
class TestACLAddModes:
    """权限模式测试"""
    
    @pytest.mark.parametrize("mode", ["r", "w", "x", "rw", "rx", "wx", "rwx"])
    def test_valid_modes(self, acl_id, mode):
        """有效权限模式"""
        QDocSE.acl_add(acl_id, user=0, mode=mode).execute().ok()
        
        # 验证模式出现在列表中
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        # 模式在输出中可能显示为 "r", "rw" 等
        list_result.contains("Entry:")
    
    @pytest.mark.parametrize("mode,desc", [
        ("", "空模式"),
        ("abc", "无效字符"),
        ("rrr", "重复字符"),
        ("rwxrwx", "超长"),
    ])
    def test_invalid_modes(self, acl_id, mode, desc):
        """无效权限模式应失败"""
        QDocSE.acl_add(acl_id, user=0, mode=mode).execute().fail(desc)


@pytest.mark.unit
class TestACLAddSubjects:
    """主体 (用户/组) 测试"""
    
    @pytest.mark.parametrize("uid", [0, 1, 65534])  # root, bin/daemon, nobody
    def test_common_uids(self, acl_id, uid):
        """常见 UID"""
        QDocSE.acl_add(acl_id, user=uid, mode="r").execute().ok()
    
    @pytest.mark.parametrize("gid", [0, 1])  # root, bin/daemon
    def test_common_gids(self, acl_id, gid):
        """常见 GID"""
        QDocSE.acl_add(acl_id, group=gid, mode="r").execute().ok()
    
    def test_user_by_name(self, acl_id):
        """按用户名添加 (如果支持)"""
        # 注意: 需要确认命令是否支持用户名
        QDocSE.acl_add(acl_id, user="root", mode="r").execute().ok()
    
    def test_no_subject_should_fail(self, acl_id):
        """不指定用户或组应失败"""
        # 既没有 -u 也没有 -g
        result = QDocSE.acl_add(acl_id, mode="r").execute()
        result.fail("Must specify user or group")


@pytest.mark.unit
class TestACLAddTime:
    """时间规格测试"""
    
    @pytest.mark.parametrize("spec,desc", [
        ("08:30:00-18:00:00", "每天时间段"),
        ("mon-09:00:00-17:00:00", "单日"),
        ("monwedfri-08:00:00-18:00:00", "多日"),
        ("00:00:00-23:59:59", "全天"),
    ])
    def test_valid_time_specs(self, acl_id, spec, desc):
        """有效时间规格"""
        QDocSE.acl_add(acl_id, user=0, mode="r").time(spec).execute().ok(desc)
    
    @pytest.mark.parametrize("spec,desc", [
        ("25:00:00-18:00:00", "无效小时"),
        ("08:60:00-18:00:00", "无效分钟"),
        ("08:00:60-18:00:00", "无效秒"),
        ("18:00:00-08:00:00", "结束早于开始"),
        ("invalid", "无效格式"),
        ("", "空"),
    ])
    def test_invalid_time_specs(self, acl_id, spec, desc):
        """无效时间规格应失败"""
        QDocSE.acl_add(acl_id, user=0, mode="r").time(spec).execute().fail(desc)


@pytest.mark.unit
class TestACLAddMultiple:
    """多条目测试"""
    
    def test_add_multiple_entries(self, acl_id):
        """添加多个条目"""
        QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=1, mode="w").execute().ok()
        QDocSE.acl_add(acl_id, user=2, mode="x").execute().ok()
        
        # 验证都存在
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        list_result.contains("Entry: 1")
        list_result.contains("Entry: 2")
        list_result.contains("Entry: 3")
    
    def test_entries_order(self, acl_id):
        """条目按添加顺序排列"""
        QDocSE.acl_add(acl_id, user=100, mode="r").execute().ok()
        QDocSE.acl_add(acl_id, user=200, mode="w").execute().ok()
        
        list_result = QDocSE.acl_list(acl_id).execute().ok()
        stdout = list_result.result.stdout
        
        # UID 100 应该在 UID 200 之前
        pos_100 = stdout.find("100")
        pos_200 = stdout.find("200")
        assert pos_100 < pos_200, "Entries should be in add order"


@pytest.mark.unit
class TestACLAddErrors:
    """错误处理测试"""
    
    def test_nonexistent_acl(self):
        """不存在的 ACL ID"""
        QDocSE.acl_add(999999, user=0, mode="r").execute().fail()
    
    def test_negative_acl_id(self):
        """负数 ACL ID"""
        QDocSE.acl_add(-1, user=0, mode="r").execute().fail()
    
    def test_missing_mode(self, acl_id):
        """缺少权限模式"""
        # 只有 user，没有 mode
        result = QDocSE.acl_add(acl_id, user=0).execute()
        result.fail("Mode is required")


@pytest.mark.unit
class TestACLAddChaining:
    """链式调用测试"""
    
    def test_chaining_style(self, acl_id):
        """使用链式调用"""
        (QDocSE.acl_add()
            .acl_id(acl_id)
            .user(0)
            .mode("rw")
            .execute()
            .ok())
        
        QDocSE.acl_list(acl_id).execute().ok().contains("Entry:")
    
    def test_chaining_with_time(self, acl_id):
        """链式调用带时间"""
        (QDocSE.acl_add()
            .acl_id(acl_id)
            .user(0)
            .mode("r")
            .time("09:00:00-17:00:00")
            .execute()
            .ok())

