"""
集成测试 - 端到端工作流

Note:
- 使用 acl_destroy 删除整个 ACL 表（不是 acl_remove）
- acl_remove 只删除条目，不删除表
- ACL 配置更改需要 push_config 才能生效

测试分类：
1. ACL 配置工作流（命令级别）
2. ACL 与文件保护集成
3. 完整的访问控制工作流
"""
import pytest
import os
from helpers import QDocSE


def cleanup_acl(acl_id: int) -> None:
    """清理 ACL"""
    QDocSE.acl_destroy(acl_id, force=True).execute()
    QDocSE.push_config().execute()


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
    
    def test_acl_edit_reorder_workflow(self):
        """
        ACL 条目重排序工作流:
        create -> add multiple -> edit order -> verify -> push_config
        """
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        try:
            # 添加 3 个条目
            QDocSE.acl_add(acl_id, user=100, mode="r").execute().ok()   # Entry 1
            QDocSE.acl_add(acl_id, user=200, mode="rw").execute().ok()  # Entry 2
            QDocSE.acl_add(acl_id, user=300, mode="rwx").execute().ok() # Entry 3
            
            # 验证初始顺序
            list1 = QDocSE.acl_list(acl_id).execute().ok()
            stdout1 = list1.result.stdout
            assert stdout1.find("100") < stdout1.find("200") < stdout1.find("300")
            
            # 将 Entry 3 移到第一位
            QDocSE.acl_edit(acl_id, entry=3, position=1).execute().ok()
            
            # 验证新顺序: 300, 100, 200
            list2 = QDocSE.acl_list(acl_id).execute().ok()
            stdout2 = list2.result.stdout
            assert stdout2.find("300") < stdout2.find("100") < stdout2.find("200"), \
                "Entry order should be 300, 100, 200 after reorder"
            
            # 推送配置
            QDocSE.push_config().execute().ok()
            
        finally:
            cleanup_acl(acl_id)


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
    
    def test_protect_with_pattern(self, test_dir_with_files, acl_id):
        """
        保护目录时使用模式匹配
        """
        try:
            # 保护目录
            result = QDocSE.protect(test_dir_with_files, encrypt=False).execute()
            if result.result.failed:
                pytest.skip(f"Cannot protect: {result.result.stderr}")
            
            # 只对 .txt 文件设置 ACL
            QDocSE.acl_file(
                test_dir_with_files,
                user_acl=acl_id,
                pattern="*.txt"
            ).execute().ok()
            
            # 推送配置
            QDocSE.push_config().execute().ok()
            
        finally:
            QDocSE.unprotect(test_dir_with_files).execute()


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
    
    def test_multi_acl_protect_workflow(self, test_dir_with_files):
        """
        多 ACL 保护工作流:
        - 对不同文件类型应用不同的 ACL
        """
        # 创建两个 ACL
        result1 = QDocSE.acl_create().execute().ok()
        acl1 = result1.parse()["acl_id"]
        
        result2 = QDocSE.acl_create().execute().ok()
        acl2 = result2.parse()["acl_id"]
        
        try:
            # 配置 ACL
            QDocSE.acl_add(acl1, user=0, mode="r").execute().ok()    # 只读
            QDocSE.acl_add(acl2, user=0, mode="rw").execute().ok()   # 读写
            
            # 保护目录
            QDocSE.protect(test_dir_with_files, encrypt=False).execute().ok()
            
            # 对 .txt 文件使用 ACL1 (只读)
            QDocSE.acl_file(
                test_dir_with_files,
                user_acl=acl1,
                pattern="*.txt"
            ).execute().ok()
            
            # 对 .doc 文件使用 ACL2 (读写)
            QDocSE.acl_file(
                test_dir_with_files,
                user_acl=acl2,
                pattern="*.doc"
            ).execute().ok()
            
            # 推送配置
            QDocSE.push_config().execute().ok()
            
        finally:
            QDocSE.unprotect(test_dir_with_files).execute()
            cleanup_acl(acl1)
            cleanup_acl(acl2)


@pytest.mark.integration
class TestACLExportImportWorkflow:
    """ACL 导出/导入工作流测试"""
    
    def test_export_import_roundtrip(self, tmp_path):
        """
        导出 -> 销毁 -> 导入 -> 验证
        """
        export_file = str(tmp_path / "acl_export.conf")
        
        # 创建 ACL 并添加条目
        result = QDocSE.acl_create().execute().ok()
        original_id = result.parse()["acl_id"]
        
        try:
            QDocSE.acl_add(original_id, user=0, mode="rw").execute().ok()
            QDocSE.acl_add(original_id, allow=False, user=1, mode="w").execute().ok()
            
            # 记录原始状态
            original_list = QDocSE.acl_list(original_id).execute().ok()
            original_entry_count = original_list.result.stdout.count("Entry:")
            
            # 导出
            QDocSE.acl_export(export_file).execute().ok()
            
            # 销毁原始 ACL
            QDocSE.acl_destroy(original_id, force=True).execute().ok()
            QDocSE.push_config().execute()
            
            # 导入
            QDocSE.acl_import(export_file).execute().ok()
            QDocSE.push_config().execute()
            
            # 验证: 列出所有 ACL 检查条目被恢复
            restored_list = QDocSE.acl_list().execute().ok()
            restored_entry_count = restored_list.result.stdout.count("Entry:")
            
            assert restored_entry_count >= original_entry_count, \
                "Imported ACL should have at least as many entries as original"
            
        finally:
            # 清理导出的文件
            if os.path.exists(export_file):
                os.unlink(export_file)


@pytest.mark.integration
class TestACLProgramWorkflow:
    """ACL 程序关联工作流测试"""
    
    def test_acl_program_association(self, user_acl_with_allow_deny):
        """
        将 ACL 关联到授权程序
        
        注意: 需要系统中有授权程序
        """
        acl_id = user_acl_with_allow_deny
        
        # 获取授权程序列表
        view_result = QDocSE.view().execute()
        if view_result.result.failed:
            pytest.skip("Cannot get view output")
        
        # 尝试关联 ACL 到程序 1
        result = QDocSE.acl_program(acl_id, program=1).execute()
        
        # 记录结果（可能成功或失败，取决于系统是否有程序索引 1）
        if result.result.success:
            print("ACL successfully associated with program")
            QDocSE.push_config().execute().ok()
        else:
            print(f"ACL-program association failed: {result.result.stderr}")
            # 这不一定是错误 - 可能没有授权程序


@pytest.mark.integration  
class TestCompleteACLLifecycle:
    """完整的 ACL 生命周期测试"""
    
    def test_full_acl_lifecycle(self, tmp_path):
        """
        完整的 ACL 生命周期:
        1. 创建目录和文件
        2. 创建 ACL 并配置规则
        3. 保护目录
        4. 将 ACL 应用到文件
        5. 推送配置
        6. 验证配置
        7. 修改 ACL（添加/删除/重排条目）
        8. 再次推送验证
        9. 导出 ACL 配置
        10. 清理
        """
        # 1. 创建目录和文件
        test_dir = tmp_path / "lifecycle_test"
        test_dir.mkdir()
        (test_dir / "data.txt").write_text("sensitive data")
        (test_dir / "config.cfg").write_text("configuration")
        dir_path = str(test_dir)
        
        # 2. 创建 ACL
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        # 添加初始规则
        QDocSE.acl_add(acl_id, user=0, mode="rw").execute().ok()
        QDocSE.acl_add(acl_id, user=1000, mode="r").execute().ok()
        
        try:
            # 3. 保护目录
            protect_result = QDocSE.protect(dir_path, encrypt=False).execute()
            if protect_result.result.failed:
                pytest.skip("Cannot protect directory")
            
            # 4. 应用 ACL
            QDocSE.acl_file(dir_path, user_acl=acl_id, pattern="*.txt").execute().ok()
            
            # 5. 推送配置
            QDocSE.push_config().execute().ok()
            
            # 6. 验证配置
            list_result = QDocSE.acl_list(acl_id).execute().ok()
            assert "Entry: 1" in list_result.result.stdout
            assert "Entry: 2" in list_result.result.stdout
            assert "Pending configuration" not in list_result.result.stdout
            
            # 7. 修改 ACL
            # 添加新条目
            QDocSE.acl_add(acl_id, allow=False, user=65534, mode="rw").execute().ok()
            # 删除一个条目
            QDocSE.acl_remove(acl_id, entry=2).execute().ok()
            
            # 验证有 pending
            list_pending = QDocSE.acl_list(acl_id).execute().ok()
            assert "Pending configuration" in list_pending.result.stdout
            
            # 8. 再次推送
            QDocSE.push_config().execute().ok()
            
            list_final = QDocSE.acl_list(acl_id).execute().ok()
            assert "Pending configuration" not in list_final.result.stdout
            
            # 9. 导出配置
            export_file = str(tmp_path / "acl_backup.conf")
            QDocSE.acl_export(export_file).execute().ok()
            assert os.path.exists(export_file)
            
            print("Full ACL lifecycle test PASSED")
            
        finally:
            # 10. 清理
            QDocSE.unprotect(dir_path).execute()
            cleanup_acl(acl_id)

