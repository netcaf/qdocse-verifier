"""Weekday Rule Tests"""
import pytest
import os
from datetime import datetime
from pathlib import Path
from helpers import QDocSE
from conftest import apply_acl


WEEKDAYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']


def today_weekday():
    return WEEKDAYS[datetime.now().weekday()]


class TestWeekdayAllowed:
    """Access on allowed weekday"""
    
    def test_access_on_today(self, protected_dir, request):
        """Today is allowed"""
        today = today_weekday()
        
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw") \
            .time(f"{today}-00:00:00-23:59:59").execute()
        
        try:
            apply_acl(protected_dir, acl_id)
            content = Path(protected_dir, "test.txt").read_text()
            assert content == "test content"
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()


class TestWeekdayDenied:
    """Access on disallowed weekday should be denied"""
    
    def test_access_denied_other_day(self, protected_dir, request):
        """Other days denied"""
        today_idx = WEEKDAYS.index(today_weekday())
        other_day = WEEKDAYS[(today_idx + 1) % 7]
        
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw") \
            .time(f"{other_day}-00:00:00-23:59:59").execute()
        
        try:
            apply_acl(protected_dir, acl_id)
            with pytest.raises(PermissionError):
                Path(protected_dir, "test.txt").read_text()
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()


class TestMultipleWeekdays:
    """Multiple weekday combination"""
    
    def test_workdays(self, protected_dir, request):
        """Workday rule"""
        today = today_weekday()
        
        if today in ['mon', 'tue', 'wed', 'thu', 'fri']:
            spec = "montuewedthufri-00:00:00-23:59:59"
            should_allow = True
        else:
            spec = "montuewedthufri-00:00:00-23:59:59"
            should_allow = False
        
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw") \
            .time(spec).execute()
        
        try:
            apply_acl(protected_dir, acl_id)
            if should_allow:
                content = Path(protected_dir, "test.txt").read_text()
                assert content == "test content"
            else:
                with pytest.raises(PermissionError):
                    Path(protected_dir, "test.txt").read_text()
        finally:
            QDocSE.acl_destroy(acl_id, force=True).execute()
            QDocSE.push_config().execute()
