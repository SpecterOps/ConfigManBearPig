"""
Unit tests for pipeline orchestration.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.pipeline import get_selected_phases, PipelineOrchestrator, ALL_PHASES


class TestGetSelectedPhases:
    """Tests for phase selection parsing."""

    def test_all_keyword(self):
        phases = get_selected_phases("All")
        assert phases == ALL_PHASES

    def test_empty_string(self):
        phases = get_selected_phases("")
        assert phases == ALL_PHASES

    def test_single_phase(self):
        phases = get_selected_phases("LDAP")
        assert phases == ["LDAP"]

    def test_multiple_phases(self):
        phases = get_selected_phases("LDAP,DNS,AdminService")
        assert "LDAP" in phases
        assert "DNS" in phases
        assert "AdminService" in phases
        assert len(phases) == 3

    def test_case_insensitive(self):
        phases = get_selected_phases("ldap,dns")
        assert "LDAP" in phases
        assert "DNS" in phases

    def test_whitespace_handling(self):
        phases = get_selected_phases("LDAP , DNS , SMB")
        assert "LDAP" in phases
        assert "DNS" in phases
        assert "SMB" in phases


class TestPipelineOrchestrator:
    """Tests for PipelineOrchestrator."""

    def test_once_phase_runs(self):
        pipeline = PipelineOrchestrator(domain="test.local")
        ran = []

        pipeline.register_once_handler("LDAP", lambda: ran.append("LDAP"))
        pipeline.register_once_handler("DNS", lambda: ran.append("DNS"))

        pipeline.run(["LDAP", "DNS"], get_targets=lambda: [])

        assert "LDAP" in ran
        assert "DNS" in ran

    def test_once_phase_order(self):
        pipeline = PipelineOrchestrator(domain="test.local")
        order = []

        pipeline.register_once_handler("LDAP", lambda: order.append("LDAP"))
        pipeline.register_once_handler("DNS", lambda: order.append("DNS"))
        pipeline.register_once_handler("Local", lambda: order.append("Local"))

        pipeline.run(["LDAP", "Local", "DNS"], get_targets=lambda: [])

        assert order == ["LDAP", "Local", "DNS"]

    def test_per_host_phases(self):
        from lib.targets import CollectionTarget

        pipeline = PipelineOrchestrator(domain="test.local")
        calls = []

        target1 = CollectionTarget("host1.test.com")
        target2 = CollectionTarget("host2.test.com")

        pipeline.register_per_host_handler(
            "SMB", lambda t: calls.append(("SMB", t.hostname))
        )

        pipeline.run(["SMB"], get_targets=lambda: [target1, target2])

        assert ("SMB", "host1.test.com") in calls
        assert ("SMB", "host2.test.com") in calls

    def test_failed_phase_continues(self):
        pipeline = PipelineOrchestrator(domain="test.local")
        ran = []

        def failing_handler():
            raise Exception("Test failure")

        pipeline.register_once_handler("LDAP", failing_handler)
        pipeline.register_once_handler("DNS", lambda: ran.append("DNS"))

        pipeline.run(["LDAP", "DNS"], get_targets=lambda: [])

        # DNS should still run despite LDAP failure
        assert "DNS" in ran


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
