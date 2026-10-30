"""The shared parser keeps SCCM's existing permissive phase choices."""

import pytest
from openhound_sccm.context import SourceContext


@pytest.mark.parametrize(
    "value,name,expected",
    [
        ("All", "unknown phase", True),
        ("", "LDAP", True),
        ("LDAP,wmi", "WMI", True),
        ("unknown", "LDAP", False),
        (" ", "LDAP", False),
    ],
)
def test_existing_sccm_method_semantics(value, name, expected):
    context = SourceContext.__new__(SourceContext)
    context.collection_methods = value
    assert context.method_enabled(name) is expected
