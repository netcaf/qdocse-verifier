"""
集成测试 - 端到端工作流

Note:
- 使用 acl_destroy 删除整个 ACL 表（不是 acl_remove）
- acl_remove 只删除条目，不删除表
- ACL 配置更改需要 push_config 才能生效
"""
import pytest
from helpers import QDocSE


@pytest.mark.integration
class TestACLWorkflow:
    """ACL 完整流程测试"""
    
    def test_create_add_list_push_destroy_workflow(self):
        """
        完整 ACL 工作流:
        create -> add -> list -> push_config -> destroy
        """
        # Step 1: 创建 ACL
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        assert acl_id is not None
        
        try:
            # Step 2: 添加条目
            QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
            QDocSE.acl_add(acl_id, user=1, mode="rw").execute().ok()
            QDocSE.acl_add(acl_id, allow=False, user=2, mode="w").execute().ok()
            
            # Step 3: 验证条目
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            list_result.contains("Entry: 1")
            list_result.contains("Entry: 2")
            list_result.contains("Entry: 3")
            list_result.contains("Pending configuration")
            
            # Step 4: 推送配置使其生效
            QDocSE.push_config().execute().ok()
            
            # Step 5: 验证 pending 已清除
            list_after = QDocSE.acl_list(acl_id).execute().ok()
            assert "Pending configuration" not in list_after.result.stdout
        
        finally:
            # Step 6: 清理 - 使用 acl_destroy 删除整个 ACL 表
            QDocSE.acl_destroy(acl_id, force=True).execute()
    
    def test_create_remove_entries_vs_destroy_table(self):
        """
        区分 acl_remove 和 acl_destroy:
        - acl_remove: 删除条目，ACL 表仍存在
        - acl_destroy: 删除整个 ACL 表
        """
        # 创建 ACL
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        try:
            # 添加条目
            QDocSE.acl_add(acl_id, user=0, mode="r").execute().ok()
            
            # 使用 acl_remove -A 删除所有条目
            QDocSE.acl_remove(acl_id, all=True).execute().ok()
            
            # 验证: ACL 表仍然存在，只是为空
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            list_result.contains(f"ACL ID {acl_id}")
            list_result.contains("No entries")
            
            # 现在使用 acl_destroy 删除整个表
            QDocSE.acl_destroy(acl_id).execute().ok()
            
            # 验证: ACL 表不再存在
            list_after = QDocSE.acl_list(acl_id).execute()
            assert list_after.result.failed or \
                   f"ACL ID {acl_id}" not in list_after.result.stdout
        
        except AssertionError:
            # 确保清理
            QDocSE.acl_destroy(acl_id, force=True).execute()
            raise


@pytest.mark.integration
class TestProtectWorkflow:
    """目录保护流程测试"""
    
    def test_protect_unprotect(self, temp_dir, acl_id):
        """保护 -> 设置ACL -> 取消保护"""
        # 保护目录
        QDocSE.protect(temp_dir, encrypt=False).execute().ok()
        
        # 设置 ACL
        QDocSE.acl_file(temp_dir, user_acl=acl_id).execute().ok()
        
        # 取消保护
        QDocSE.unprotect(temp_dir).execute().ok()


@pytest.mark.integration
class TestACLWithProtectWorkflow:
    """ACL 与文件保护集成测试"""
    
    def test_full_protect_acl_workflow(self, temp_dir):
        """
        完整工作流:
        1. 创建 ACL 并添加规则
        2. 保护目录
        3. 将 ACL 应用到目录
        4. push_config 使配置生效
        5. 清理
        """
        # Step 1: 创建并配置 ACL
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        try:
            # 添加 allow 规则
            QDocSE.acl_add(acl_id, user=0, mode="rw").execute().ok()
            
            # Step 2: 保护目录
            QDocSE.protect(temp_dir, encrypt=False).execute().ok()
            
            # Step 3: 将 ACL 应用到目录
            QDocSE.acl_file(temp_dir, user_acl=acl_id).execute().ok()
            
            # Step 4: 推送配置使其生效
            QDocSE.push_config().execute().ok()
            
            # 验证 ACL 已应用
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            assert "Pending configuration" not in list_result.result.stdout
            
        finally:
            # Step 5: 清理
            QDocSE.unprotect(temp_dir).execute()
            QDocSE.acl_destroy(acl_id, force=True).execute()

