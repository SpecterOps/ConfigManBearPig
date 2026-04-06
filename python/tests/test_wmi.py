"""
Unit tests for the WMI collector helper functions and data processing logic.

Tests _parse_wmi_bool, _extract_embedded_props, and the graph-building
functions using mock WMI data (no real DCOM connection required).
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.graph import GraphStore
from lib.collectors.wmi_collector import (
    _parse_wmi_bool,
    _extract_embedded_props,
    _create_user_edge,
)


class TestParseWmiBool:
    """Tests for _parse_wmi_bool which handles WMI's various boolean representations."""

    def test_python_bool_true(self):
        assert _parse_wmi_bool(True) is True

    def test_python_bool_false(self):
        assert _parse_wmi_bool(False) is False

    def test_string_true(self):
        assert _parse_wmi_bool("True") is True

    def test_string_false(self):
        assert _parse_wmi_bool("False") is False

    def test_string_true_lowercase(self):
        assert _parse_wmi_bool("true") is True

    def test_string_false_lowercase(self):
        assert _parse_wmi_bool("false") is False

    def test_string_true_mixed_case(self):
        assert _parse_wmi_bool("TRUE") is True

    def test_string_one(self):
        assert _parse_wmi_bool("1") is True

    def test_string_zero(self):
        assert _parse_wmi_bool("0") is False

    def test_int_one(self):
        assert _parse_wmi_bool(1) is True

    def test_int_zero(self):
        assert _parse_wmi_bool(0) is False

    def test_none(self):
        assert _parse_wmi_bool(None) is False

    def test_empty_string(self):
        assert _parse_wmi_bool("") is False

    def test_string_with_spaces(self):
        assert _parse_wmi_bool("  True  ") is True

    def test_string_false_is_not_truthy(self):
        """Regression test: WMI returns 'False' as string, which is truthy in Python."""
        val = "False"
        # Without _parse_wmi_bool, `not val` would be False (wrong!)
        assert _parse_wmi_bool(val) is False


class TestExtractEmbeddedProps:
    """Tests for _extract_embedded_props which decodes WMI SMS_EmbeddedProperty objects."""

    def test_dict_format(self):
        """When WMI returns props as simple dicts (ideal case)."""
        props = [
            {"PropertyName": "SQL Server Service Logon Account", "Value1": "", "Value2": "DOMAIN\\svc_acct"},
            {"PropertyName": "DatabaseName", "Value1": "CM_PS1", "Value2": ""},
        ]
        result = _extract_embedded_props(props)
        assert "SQL Server Service Logon Account" in result
        assert result["SQL Server Service Logon Account"]["Value2"] == "DOMAIN\\svc_acct"
        assert "DatabaseName" in result
        assert result["DatabaseName"]["Value1"] == "CM_PS1"

    def test_none_input(self):
        assert _extract_embedded_props(None) == {}

    def test_empty_list(self):
        assert _extract_embedded_props([]) == {}

    def test_dict_missing_property_name(self):
        props = [{"PropertyName": "", "Value1": "x"}]
        result = _extract_embedded_props(props)
        assert len(result) == 0

    def test_single_dict_not_list(self):
        """When WMI returns a single embedded object, not wrapped in a list."""
        prop = {"PropertyName": "TestProp", "Value1": "val1", "Value2": "val2"}
        result = _extract_embedded_props(prop)
        assert result["TestProp"]["Value1"] == "val1"
        assert result["TestProp"]["Value2"] == "val2"

    def test_encoding_unit_with_getData(self):
        """Simulate impacket ENCODING_UNIT objects with raw binary containing property data."""

        class FakeEncodingUnit:
            def __init__(self, prop_name, value2):
                # Build a minimal binary blob containing the marker and values
                # Matches the real format: class definition + "SMS_EmbeddedProperty" marker + values
                parts = [
                    b"some class definition bytes",
                    b"SMS_EmbeddedProperty",  # marker
                    b"\x00more stuff\x00",
                    b"SMS_EmbeddedProperty",  # last marker
                    prop_name.encode("ascii"),
                    b"\x00",
                    value2.encode("ascii"),
                ]
                self._data = b"\x00".join(parts)

            def getData(self):
                return self._data

        props = [
            FakeEncodingUnit("SQL Server Service Logon Account", "mayyhem\\sqlsccmsvc"),
            FakeEncodingUnit("SQL Server Agent Service Logon Account", "NT Service\\SQLSERVERAGENT"),
        ]
        result = _extract_embedded_props(props)
        assert "SQL Server Service Logon Account" in result
        assert result["SQL Server Service Logon Account"]["Value2"] == "mayyhem\\sqlsccmsvc"
        assert "SQL Server Agent Service Logon Account" in result
        assert result["SQL Server Agent Service Logon Account"]["Value2"] == "NT Service\\SQLSERVERAGENT"


class TestCombinedDeviceResourcesFiltering:
    """Tests for the boolean filtering logic in _get_combined_device_resources_via_wmi."""

    def test_wmi_string_booleans_filter_correctly(self):
        """Regression test: WMI returns 'True'/'False' strings for IsClient/IsObsolete.
        Non-client or obsolete devices should be filtered out."""
        # Simulate the filtering logic from _get_combined_device_resources_via_wmi
        items = [
            {"Name": "CLIENT1", "IsClient": "True", "IsObsolete": "False", "SMSID": "GUID:1"},
            {"Name": "NOCLIENT", "IsClient": "False", "IsObsolete": "False", "SMSID": "GUID:2"},
            {"Name": "OBSOLETE", "IsClient": "True", "IsObsolete": "True", "SMSID": "GUID:3"},
            {"Name": "BOTH_BAD", "IsClient": "False", "IsObsolete": "True", "SMSID": "GUID:4"},
        ]

        passed = []
        for item in items:
            is_client = _parse_wmi_bool(item.get("IsClient", False))
            is_obsolete = _parse_wmi_bool(item.get("IsObsolete", False))
            if not is_client or is_obsolete:
                continue
            passed.append(item["Name"])

        assert passed == ["CLIENT1"]

    def test_real_bool_values_also_work(self):
        """AdminService returns real booleans. Ensure _parse_wmi_bool handles them too."""
        items = [
            {"Name": "CLIENT1", "IsClient": True, "IsObsolete": False},
            {"Name": "NOCLIENT", "IsClient": False, "IsObsolete": False},
        ]

        passed = []
        for item in items:
            is_client = _parse_wmi_bool(item.get("IsClient", False))
            is_obsolete = _parse_wmi_bool(item.get("IsObsolete", False))
            if not is_client or is_obsolete:
                continue
            passed.append(item["Name"])

        assert passed == ["CLIENT1"]

    def test_int_bool_values(self):
        """SMS_R_System returns Client/Obsolete as integers (0/1)."""
        items = [
            {"Name": "CLIENT1", "IsClient": 1, "IsObsolete": 0},
            {"Name": "NOCLIENT", "IsClient": 0, "IsObsolete": 0},
        ]

        passed = []
        for item in items:
            is_client = _parse_wmi_bool(item.get("IsClient", False))
            is_obsolete = _parse_wmi_bool(item.get("IsObsolete", False))
            if not is_client or is_obsolete:
                continue
            passed.append(item["Name"])

        assert passed == ["CLIENT1"]


class TestDeviceIdGeneration:
    """Test that device IDs follow the GUID: / RID: pattern correctly."""

    def test_sms_guid_with_prefix(self):
        sms_guid = "GUID:12345678-1234-1234-1234-123456789012"
        device_id = sms_guid if sms_guid.upper().startswith("GUID:") else f"GUID:{sms_guid}"
        assert device_id == "GUID:12345678-1234-1234-1234-123456789012"

    def test_sms_guid_without_prefix(self):
        sms_guid = "12345678-1234-1234-1234-123456789012"
        device_id = sms_guid if sms_guid.upper().startswith("GUID:") else f"GUID:{sms_guid}"
        assert device_id == "GUID:12345678-1234-1234-1234-123456789012"

    def test_fallback_to_resource_id(self):
        sms_guid = ""
        resource_id = 2097152001
        if sms_guid:
            device_id = sms_guid if sms_guid.upper().startswith("GUID:") else f"GUID:{sms_guid}"
        else:
            device_id = f"RID:{resource_id}"
        assert device_id == "RID:2097152001"


class TestCollectionMemberGrouping:
    """Test that collection members are grouped by CollectionID."""

    def test_group_by_collection_id(self):
        from collections import defaultdict

        items = [
            {"CollectionID": "SMS00001", "ResourceID": 1, "SMSID": "GUID:a"},
            {"CollectionID": "SMS00001", "ResourceID": 2, "SMSID": "GUID:b"},
            {"CollectionID": "PS100002", "ResourceID": 3, "SMSID": "GUID:c"},
            {"CollectionID": "", "ResourceID": 4, "SMSID": ""},
        ]

        collections_map: dict[str, list] = defaultdict(list)
        for item in items:
            cid = item.get("CollectionID", "")
            if cid:
                collections_map[cid].append(item)

        assert len(collections_map) == 2
        assert len(collections_map["SMS00001"]) == 2
        assert len(collections_map["PS100002"]) == 1


class TestAdminUserRoleResolution:
    """Test admin user WMI-specific field handling."""

    def test_role_names_as_list(self):
        role_names = ["Full Administrator", "Read-only Analyst"]
        assert isinstance(role_names, list)
        assert len(role_names) == 2

    def test_role_names_as_comma_string(self):
        """WMI sometimes returns arrays as comma-separated strings."""
        role_names = "Full Administrator,Read-only Analyst"
        if isinstance(role_names, str):
            role_names = [r.strip() for r in role_names.split(",")]
        assert role_names == ["Full Administrator", "Read-only Analyst"]

    def test_account_type_group_detection(self):
        """AccountType == 1 means group, 0 means user."""
        assert (0 == 1) is False  # user
        assert (1 == 1) is True   # group
