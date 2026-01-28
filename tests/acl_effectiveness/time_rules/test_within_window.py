"""Within Time Window Access Tests"""
import pytest
import os
from datetime import datetime
from pathlib import Path
from helpers import QDocSE
from conftest import apply_acl


def current_hour():
    return datetime.now().hour


class TestWithinTimeWindow:
    """Access within allowed time window"""
    
    def test_all_day_window(self, protected_dir, request):
        """All day window(00:00-23:59)"""
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw") \
            .time("00:00:00-23:59:59").execute()
        
        try:
            apply_acl(protected_dir, acl_id)
            content = Path(protected_dir, "test.txt").read_text()
            assert content == "test content"
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
    
    def test_current_hour_window(self, protected_dir, request):
        """Window containing current time"""
        hour = current_hour()
        start = max(0, hour - 1)
        end = min(23, hour + 1)
        
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw") \
            .time(f"{start:02d}:00:00-{end:02d}:59:59").execute()
        
        try:
            apply_acl(protected_dir, acl_id)
            content = Path(protected_dir, "test.txt").read_text()
            assert content == "test content"
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
