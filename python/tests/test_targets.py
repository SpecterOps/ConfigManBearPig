"""
Unit tests for target management.
"""

import pytest
import sys
import os
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.targets import TargetManager, CollectionTarget


class MockADResolver:
    """Mock AD resolver for testing."""

    def __init__(self):
        self._computers = {}

    def add_computer(self, hostname, sid, fqdn=None, sam=None):
        short = hostname.split(".")[0].lower()
        obj = {
            "SID": sid,
            "objectSid": sid,
            "dNSHostName": fqdn or hostname,
            "sAMAccountName": sam or f"{short}$",
        }
        self._computers[short] = obj

    def get_ad_computer(self, hostname):
        short = hostname.split(".")[0].lower().rstrip("$")
        return self._computers.get(short)


class TestTargetManager:
    """Tests for TargetManager."""

    def test_add_device(self):
        resolver = MockADResolver()
        resolver.add_computer("test", "S-1-5-21-123", "test.mayyhem.com")
        tm = TargetManager(resolver)

        target = tm.add_device("test", source="Test")
        assert target is not None
        assert tm.count == 1

    def test_dedup_by_hostname(self):
        resolver = MockADResolver()
        resolver.add_computer("test", "S-1-5-21-123", "test.mayyhem.com")
        tm = TargetManager(resolver)

        tm.add_device("test.mayyhem.com", source="Source1")
        tm.add_device("test.mayyhem.com", source="Source2")
        assert tm.count == 1

    def test_dedup_by_sid(self):
        resolver = MockADResolver()
        resolver.add_computer("test", "S-1-5-21-123", "test.mayyhem.com")
        tm = TargetManager(resolver)

        tm.add_device("test", source="Source1")
        tm.add_device("test.mayyhem.com", source="Source2")
        # Should be one target (FQDN preferred)
        assert tm.count == 1
        target = list(tm.targets.values())[0]
        assert "." in target.hostname  # Should use FQDN

    def test_fqdn_preferred_over_short_name(self):
        resolver = MockADResolver()
        resolver.add_computer("test", "S-1-5-21-123", "test.mayyhem.com")
        tm = TargetManager(resolver)

        tm.add_device("test", source="Short")
        tm.add_device("test.mayyhem.com", source="FQDN")
        assert tm.count == 1
        target = list(tm.targets.values())[0]
        assert target.hostname == "test.mayyhem.com"

    def test_allow_list_filter(self):
        resolver = MockADResolver()
        resolver.add_computer("allowed", "S-1", "allowed.mayyhem.com")
        resolver.add_computer("blocked", "S-2", "blocked.mayyhem.com")

        tm = TargetManager(resolver, allowed_targets={"allowed.mayyhem.com"})

        t1 = tm.add_device("allowed.mayyhem.com", source="Test")
        t2 = tm.add_device("blocked.mayyhem.com", source="Test")

        assert t1 is not None
        assert t2 is None
        assert tm.count == 1

    def test_allow_list_short_name_match(self):
        resolver = MockADResolver()
        resolver.add_computer("test", "S-1", "test.mayyhem.com")

        tm = TargetManager(resolver, allowed_targets={"test"})
        target = tm.add_device("test.mayyhem.com", source="Test")
        assert target is not None

    def test_no_filter_allows_all(self):
        resolver = MockADResolver()
        resolver.add_computer("a", "S-1", "a.m.com")
        resolver.add_computer("b", "S-2", "b.m.com")

        tm = TargetManager(resolver, allowed_targets=None)
        tm.add_device("a.m.com")
        tm.add_device("b.m.com")
        assert tm.count == 2

    def test_mark_collected(self):
        resolver = MockADResolver()
        resolver.add_computer("test", "S-1", "test.m.com")

        tm = TargetManager(resolver)
        tm.add_device("test.m.com")
        assert len(tm.get_uncollected()) == 1

        tm.mark_collected("test.m.com")
        assert len(tm.get_uncollected()) == 0

    def test_collection_target_properties(self):
        ad_obj = {
            "SID": "S-1-5-21-123",
            "dNSHostName": "test.mayyhem.com",
            "sAMAccountName": "TEST$",
        }
        ct = CollectionTarget("test.mayyhem.com", ad_object=ad_obj, source="Test")

        assert ct.sid == "S-1-5-21-123"
        assert ct.fqdn == "test.mayyhem.com"
        assert ct.short_name == "test"
        assert ct.collected is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
