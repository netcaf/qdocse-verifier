"""Outside Time Window Access Tests"""
import pytest
import os
from datetime import datetime
from pathlib import Path
from helpers import QDocSE
from conftest import apply_acl


def current_hour():
    return datetime.now().hour


class TestOutsideTimeWindow:
    """Access outside allowed time window should be denied"""
    
    def test_future_window_denies(self, protected_dir, request):
        """Time window in future"""
        hour = current_hour()
        start = (hour + 2) % 24
        end = (hour + 3) % 24
        
        if end <= start:
            pytest.skip("Midnight crossing scenario")
        
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw") \
            .time(f"{start:02d}:00:00-{end:02d}:00:00").execute()
        
        try:
            apply_acl(protected_dir, acl_id)
            with pytest.raises(PermissionError):
                Path(protected_dir, "test.txt").read_text()
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
    
    def test_past_window_denies(self, protected_dir, request):
        """Time window in past"""
        hour = current_hour()
        start = (hour - 3) % 24
        end = (hour - 2) % 24
        
        if start >= end or hour < 3:
            pytest.skip("Crosses midnight or insufficient time")
        
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw") \
            .time(f"{start:02d}:00:00-{end:02d}:00:00").execute()
        
        try:
            apply_acl(protected_dir, acl_id)
            with pytest.raises(PermissionError):
                Path(protected_dir, "test.txt").read_text()
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
