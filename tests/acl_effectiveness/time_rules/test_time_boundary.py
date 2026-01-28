"""
Time Boundary Tests

Test time window boundary conditions:
- First second when window starts
- Last second when window ends
- Time window crossing midnight
"""
import pytest
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from helpers import QDocSE


def cleanup(acl_id):
    QDocSE.acl_destroy(acl_id, force=True).execute()
    QDocSE.push_config().execute()


class TestWindowStartBoundary:
    """Time window start boundary"""
    
    @pytest.mark.slow
    def test_access_at_window_start(self, protected_dir):
        """
        Test access at time window start
        
        Need to wait until window start time
        """
        now = datetime.now()
        # Set window starting 1 minute later
        start_time = now + timedelta(minutes=1)
        end_time = now + timedelta(hours=1)
        
        start_str = start_time.strftime("%H:%M:%S")
        end_str = end_time.strftime("%H:%M:%S")
        
        acl_id = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw") \
            .time(f"{start_str}-{end_str}").execute()
        
        try:
            QDocSE.acl_file(protected_dir, user_acl=acl_id).execute()
            QDocSE.push_config().execute()
            
            # Should be denied before window starts
            with pytest.raises(PermissionError):
                Path(protected_dir, "test.txt").read_text()
            
            # Wait until window starts
            wait_seconds = (start_time - datetime.now()).total_seconds() + 2
            if wait_seconds > 0:
                print(f"Wait {wait_seconds:.0f} seconds...")
                time.sleep(wait_seconds)
            
            # Should be allowed after window starts
            content = Path(protected_dir, "test.txt").read_text()
            assert content is not None
            
        finally:
            cleanup(acl_id)


class TestWindowEndBoundary:
    """Time window end boundary"""
    
    @pytest.mark.slow
    def test_access_at_window_end(self, protected_dir):
        """
        Test access near time window end
        """
        now = datetime.now()
        # Set window that started and will end soon
        start_time = now - timedelta(minutes=5)
        end_time = now + timedelta(seconds=30)
        
        start_str = start_time.strftime("%H:%M:%S")
        end_str = end_time.strftime("%H:%M:%S")
        
        acl_id = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw") \
            .time(f"{start_str}-{end_str}").execute()
        
        try:
            QDocSE.acl_file(protected_dir, user_acl=acl_id).execute()
            QDocSE.push_config().execute()
            
            # Should be allowed within window
            content = Path(protected_dir, "test.txt").read_text()
            assert content is not None
            
            # Wait for window to end
            wait_seconds = (end_time - datetime.now()).total_seconds() + 5
            if wait_seconds > 0:
                print(f"Wait {wait_seconds:.0f} seconds...")
                time.sleep(wait_seconds)
            
            # Should be denied after window ends
            with pytest.raises(PermissionError):
                Path(protected_dir, "test.txt").read_text()
                
        finally:
            cleanup(acl_id)


class TestMidnightCrossing:
    """Time window crossing midnight"""
    
    def test_window_crossing_midnight(self, protected_dir):
        """
        Test time window crossing midnight (22:00-02:00)
        
        Note: This test assumes current time is inside or outside window
        """
        now = datetime.now()
        current_hour = now.hour
        
        # Create 22:00-02:00 window
        acl_id = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw") \
            .time("22:00:00-02:00:00").execute()
        
        try:
            QDocSE.acl_file(protected_dir, user_acl=acl_id).execute()
            QDocSE.push_config().execute()
            
            # Determine if currently inside window
            in_window = current_hour >= 22 or current_hour < 2
            
            if in_window:
                content = Path(protected_dir, "test.txt").read_text()
                assert content is not None
            else:
                with pytest.raises(PermissionError):
                    Path(protected_dir, "test.txt").read_text()
                    
        finally:
            cleanup(acl_id)
    
    def test_window_not_crossing_midnight(self, protected_dir):
        """
        Comparison test: normal window not crossing midnight
        """
        now = datetime.now()
        current_hour = now.hour
        
        # Create 09:00-17:00 window
        acl_id = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw") \
            .time("09:00:00-17:00:00").execute()
        
        try:
            QDocSE.acl_file(protected_dir, user_acl=acl_id).execute()
            QDocSE.push_config().execute()
            
            # Determine if currently inside window
            in_window = 9 <= current_hour < 17
            
            if in_window:
                content = Path(protected_dir, "test.txt").read_text()
                assert content is not None
            else:
                with pytest.raises(PermissionError):
                    Path(protected_dir, "test.txt").read_text()
                    
        finally:
            cleanup(acl_id)


class TestSecondPrecision:
    """Second precision test"""
    
    def test_time_precision_seconds(self, protected_dir):
        """
        Test if time rules support second precision
        """
        now = datetime.now()
        
        # Create a 10-second window
        start = now + timedelta(seconds=5)
        end = now + timedelta(seconds=15)
        
        start_str = start.strftime("%H:%M:%S")
        end_str = end.strftime("%H:%M:%S")
        
        acl_id = QDocSE.acl_create().execute().ok().parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw") \
            .time(f"{start_str}-{end_str}").execute()
        
        try:
            QDocSE.acl_file(protected_dir, user_acl=acl_id).execute()
            QDocSE.push_config().execute()
            
            # Record whether test supports second-level precision
            # This is more of a documentation test
            print(f"Time window: {start_str} - {end_str}")
            
        finally:
            cleanup(acl_id)
