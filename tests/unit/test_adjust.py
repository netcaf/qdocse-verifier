"""Adjust 命令测试"""
import pytest
from helpers import QDocSE


@pytest.mark.unit
class TestAdjust:
    """授权程序调整测试"""
    
    def test_authorize_by_path(self):
        """按路径授权"""
        QDocSE.adjust().auth_path("/bin/ls").execute()
    
    def test_block_by_path(self):
        """按路径阻止"""
        QDocSE.adjust().block_path("/tmp/malware").execute()
