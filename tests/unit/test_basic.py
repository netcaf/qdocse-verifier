"""
Basic tests - demonstrates different requirement patterns.

- No marker: always runs
- With marker: auto-checked before run
"""
import pytest
from helpers import QDocSE


class TestNoRequirements:
    """Tests without requirements - always run."""
    
    def test_show_mode(self):
        """show_mode works in all modes."""
        result = QDocSE.show_mode().execute()
        assert result.result.success
        assert any(m in result.result.stdout.lower() 
                   for m in ['elevated', 'learning', 'de-elevated', 'unlicensed'])
    
    def test_list_config(self):
        """list command works in all modes."""
        result = QDocSE.list_config().execute()
        assert result.result.returncode == 0 or 'error' not in result.result.stderr.lower()


class TestMixedRequirements:
    """Tests with different requirements."""
    
    def test_always_runs(self):
        """No marker - always runs."""
        assert True
    
    @pytest.mark.requires_mode("elevated", "learning")
    def test_needs_configurable_mode(self):
        """Requires Elevated or Learning mode."""
        result = QDocSE.view().execute()
        assert result.result.success
    
    @pytest.mark.requires_mode("elevated", "learning")
    @pytest.mark.requires_license("A")
    def test_needs_mode_and_license(self):
        """Requires mode + license."""
        result = QDocSE.acl_list().execute()
        assert result.result.success
    
    @pytest.mark.requires_license("A")
    def test_needs_license_a_only(self):
        """Only requires License A (any mode)."""
        pass
    
    @pytest.mark.requires_license("D")
    def test_needs_license_d(self):
        """Requires License D (Data Integrity)."""
        pass


@pytest.mark.requires_mode("elevated")
class TestElevatedOnly:
    """Only runs in Elevated mode (not Learning)."""
    
    def test_elevated_specific(self):
        pass
