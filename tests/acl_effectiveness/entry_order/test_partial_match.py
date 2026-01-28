"""
Partial Match Tests

PDF Page 81 key rules:
"When the UID/GID/index is successful but the mode or time is not successful 
then the entry will Deny."

This means: when subject matches but mode/time doesn't match, it's Deny not skip!
"""
import pytest
import os
from datetime import datetime
from pathlib import Path
from helpers import QDocSE


def cleanup(acl_id):
    QDocSE.acl_destroy(acl_id, force=True).execute()
    QDocSE.push_config().execute()


class TestUserMatchModeNotMatch:
    """
    User matches, but mode does not match
    
    Expected: Deny (not skip to next entry)
    """
    
    def test_user_match_mode_not_match_should_deny(self, protected_dir):
        """
        Scenario:
        - Entry 1: Allow current_user mode=r
        - Entry 2: Allow current_user mode=rw
        - Request: rw
        
        Expected:
        - Entry 1: user matches✓, mode doesn't match (rw is not subset of r) → Deny
        - Will not check Entry 2
        """
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        # Add Allow(r) first, then Add Allow(rw)
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="r").execute()
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw").execute()
        
        try:
            QDocSE.acl_file(protected_dir, user_acl=acl_id).execute()
            QDocSE.push_config().execute()
            
            # Request rw, first entry matches user but mode doesn't match
            # According to PDF, this should Deny, not skip to second entry
            with pytest.raises(PermissionError):
                with open(Path(protected_dir, "test.txt"), 'r+') as f:
                    f.write("test")
        finally:
            cleanup(acl_id)
    
    def test_user_match_mode_subset_should_allow(self, protected_dir):
        """
        Comparison test: should allow when request is subset of mode
        
        - Entry: Allow current_user mode=rw
        - Request: r (is subset of rw)
        - Expected: Allow
        """
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw").execute()
        
        try:
            QDocSE.acl_file(protected_dir, user_acl=acl_id).execute()
            QDocSE.push_config().execute()
            
            content = Path(protected_dir, "test.txt").read_text()
            assert content is not None
        finally:
            cleanup(acl_id)


class TestUserMatchTimeNotMatch:
    """
    User matches, but time does not match
    
    Expected: Deny (not skip to next entry)
    """
    
    def test_user_match_time_not_match_should_deny(self, protected_dir):
        """
        Scenario:
        - Entry 1: Allow current_user, time=future time period
        - Entry 2: Allow current_user, no time limit
        - Current time not in Entry 1's time period
        
        Expected:
        - Entry 1: user matches✓, time doesn't match → Deny
        - Will not check Entry 2
        """
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        # Get future time period
        current_hour = datetime.now().hour
        future_start = (current_hour + 2) % 24
        future_end = (current_hour + 3) % 24
        
        if future_end <= future_start:
            pytest.skip("Midnight crossing scenario")
        
        # Entry 1: has time limit (future time period)
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw") \
            .time(f"{future_start:02d}:00:00-{future_end:02d}:00:00").execute()
        # Entry 2: no time limit
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw").execute()
        
        try:
            QDocSE.acl_file(protected_dir, user_acl=acl_id).execute()
            QDocSE.push_config().execute()
            
            # User matches Entry 1, but time doesn't match
            # According to PDF, should Deny, will not check Entry 2
            with pytest.raises(PermissionError):
                Path(protected_dir, "test.txt").read_text()
        finally:
            cleanup(acl_id)


class TestUserNotMatchSkipsEntry:
    """
    When user does not match, skip to next entry
    
    This contrasts with "partial match means Deny"
    """
    
    def test_other_user_skips_to_next_entry(self, protected_dir):
        """
        Scenario:
        - Entry 1: Allow other_user mode=r
        - Entry 2: Allow current_user mode=rw
        
        Expected:
        - Entry 1: user doesn't match → skip
        - Entry 2: user matches, mode matches → Allow
        """
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        # Entry 1: other user
        QDocSE.acl_add(acl_id, allow=True, user=65534, mode="r").execute()  # nobody
        # Entry 2: current user
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw").execute()
        
        try:
            QDocSE.acl_file(protected_dir, user_acl=acl_id).execute()
            QDocSE.push_config().execute()
            
            # Entry 1 user doesn't match, skip
            # Entry 2 user matches, should Allow
            content = Path(protected_dir, "test.txt").read_text()
            assert content is not None
        finally:
            cleanup(acl_id)


class TestDenyEntryBehavior:
    """Partial match behavior of Deny entry"""
    
    def test_deny_user_match_mode_not_match_behavior(self, protected_dir):
        """
        Deny entry: user matches, mode has no intersection
        
        - Entry: Deny current_user mode=x
        - Request: r
        - Expected: doesn't match Deny(x), because r has no intersection with x
        """
        result = QDocSE.acl_create().execute().ok()
        acl_id = result.parse()["acl_id"]
        
        # Deny(x)
        QDocSE.acl_add(acl_id, allow=False, user=os.getuid(), mode="x").execute()
        # Allow(rw)
        QDocSE.acl_add(acl_id, allow=True, user=os.getuid(), mode="rw").execute()
        
        try:
            QDocSE.acl_file(protected_dir, user_acl=acl_id).execute()
            QDocSE.push_config().execute()
            
            # Request r, Deny(x) mode has no intersection with r
            # Should skip Deny entry, match Allow(rw)
            content = Path(protected_dir, "test.txt").read_text()
            assert content is not None
        finally:
            cleanup(acl_id)
