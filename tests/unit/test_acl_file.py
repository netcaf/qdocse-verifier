"""ACL File 命令测试"""
import pytest
from helpers import QDocSE


@pytest.mark.unit
class TestACLFile:
    """文件 ACL 测试"""
    
    def test_set_user_acl(self, acl_id, temp_dir):
        """设置用户 ACL"""
        QDocSE.acl_file(temp_dir, user_acl=acl_id).execute().ok()
    
    def test_with_pattern(self, acl_id, temp_dir):
        """带文件模式"""
        QDocSE.acl_file(temp_dir, user_acl=acl_id, pattern="*.txt").execute().ok()
    
    def test_invalid_dir(self, acl_id):
        """无效目录应失败"""
        QDocSE.acl_file("/nonexistent/path", user_acl=acl_id).execute().fail()
