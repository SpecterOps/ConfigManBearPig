"""Unit tests for ADClient._entry_to_dict.

Verifies that the output dict uses clean snake_case keys so that dlt's
table-loading step (which lowercases and splits on case boundaries) does not
mangle camelCase LDAP attribute names into broken column names like
``d_ns_host_name``.

The LDAP wire-protocol attribute names (used in search calls) are NOT tested
here — they must stay as real LDAP names and are left untouched by this fix.
"""
from __future__ import annotations

import struct


# ---------------------------------------------------------------------------
# Minimal ldap3 Entry stub
# ---------------------------------------------------------------------------

class _AttrStub:
    """Pretend to be an ldap3 Attribute with only raw_values."""

    def __init__(self, raw: list):
        self.raw_values = raw


class _EntryStub:
    """Pretend to be an ldap3 Entry.

    ``attrs`` is a dict mapping the real LDAP attribute name to a list of raw
    values (bytes or str).  ``entry_dn`` is the distinguished name string.
    """

    def __init__(self, dn: str, attrs: dict[str, list]):
        self.entry_dn = dn
        self._attrs = attrs
        self.entry_attributes = list(attrs.keys())

    def __getitem__(self, attr_name: str) -> _AttrStub:
        return _AttrStub(self._attrs[attr_name])


# ---------------------------------------------------------------------------
# Helper: build a binary objectSid for S-1-5-21-1-2-3-1104
# ---------------------------------------------------------------------------

def _make_sid_bytes() -> bytes:
    """Return the raw binary form of S-1-5-21-1-2-3-1104."""
    # SID binary layout: revision(1) sub_count(1) authority(6 big-endian)
    # followed by sub_count little-endian 4-byte sub-authorities.
    sub_auths = [21, 1, 2, 3, 1104]
    authority = (5).to_bytes(6, "big")
    header = bytes([1, len(sub_auths)]) + authority
    body = b"".join(struct.pack("<I", s) for s in sub_auths)
    return header + body


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_entry_to_dict_uses_snake_case_keys():
    """_entry_to_dict must output snake_case keys, not raw LDAP camelCase."""
    from openhound_sccm.clients.ad import ADClient

    sid_bytes = _make_sid_bytes()

    entry = _EntryStub(
        dn="CN=HOST1,CN=Computers,DC=lab,DC=local",
        attrs={
            "dNSHostName":        [b"host1.lab.local"],
            "sAMAccountName":     [b"HOST1$"],
            "userPrincipalName":  [b"host1@lab.local"],
            "objectClass":        [b"top", b"person", b"computer"],
            "objectSid":          [sid_bytes],
            "name":               [b"HOST1"],
            "cn":                 [b"HOST1"],
        },
    )

    result = ADClient._entry_to_dict(entry)

    # --- keys that must be present with clean snake_case names ---
    assert "distinguished_name" in result,  "distinguishedName (from entry_dn) must map to distinguished_name"
    assert "dns_host_name"       in result,  "dNSHostName must map to dns_host_name"
    assert "sam_account_name"    in result,  "sAMAccountName must map to sam_account_name"
    assert "user_principal_name" in result,  "userPrincipalName must map to user_principal_name"
    assert "object_class"        in result,  "objectClass must map to object_class"
    assert "object_sid"          in result,  "objectSid must be decoded and stored as object_sid"

    # --- old camelCase keys must NOT appear in the output ---
    assert "distinguishedName"  not in result, "distinguishedName key must not survive in output"
    assert "dNSHostName"        not in result, "dNSHostName key must not survive in output"
    assert "sAMAccountName"     not in result, "sAMAccountName key must not survive in output"
    assert "userPrincipalName"  not in result, "userPrincipalName key must not survive in output"
    assert "objectClass"        not in result, "objectClass key must not survive in output"
    assert "objectSid"          not in result, "objectSid key must not survive in output (decoded to object_sid)"


def test_entry_to_dict_correct_values():
    """Values must be decoded correctly and single-item lists unwrapped."""
    from openhound_sccm.clients.ad import ADClient

    sid_bytes = _make_sid_bytes()

    entry = _EntryStub(
        dn="CN=HOST1,CN=Computers,DC=lab,DC=local",
        attrs={
            "dNSHostName":    [b"host1.lab.local"],
            "sAMAccountName": [b"HOST1$"],
            "objectClass":    [b"top", b"computer"],
            "objectSid":      [sid_bytes],
        },
    )

    result = ADClient._entry_to_dict(entry)

    assert result["distinguished_name"] == "CN=HOST1,CN=Computers,DC=lab,DC=local"
    assert result["dns_host_name"] == "host1.lab.local"
    assert result["sam_account_name"] == "HOST1$"
    # multi-value list stays as list
    assert isinstance(result["object_class"], list)
    assert "computer" in result["object_class"]
    # SID decoded to string form
    assert result["object_sid"].startswith("S-1-5-21-")


def test_entry_to_dict_null_attr():
    """Attributes with no raw values must map to None with a snake_case key."""
    from openhound_sccm.clients.ad import ADClient

    entry = _EntryStub(
        dn="CN=HOST2,CN=Computers,DC=lab,DC=local",
        attrs={
            "dNSHostName": [],   # empty raw_values => None
        },
    )

    result = ADClient._entry_to_dict(entry)
    assert result.get("dns_host_name") is None, "Empty attr must produce None under the mapped snake_case key"
    assert "dNSHostName" not in result, "camelCase key must not appear even for None attrs"


def test_entry_to_dict_unknown_attr_passthrough():
    """Attributes with no entry in _ATTR_KEY_MAP are stored under their original name."""
    from openhound_sccm.clients.ad import ADClient

    entry = _EntryStub(
        dn="CN=X,DC=lab,DC=local",
        attrs={
            "mSSMSSiteCode": [b"PS1"],   # SCCM-specific; no mapping needed
        },
    )

    result = ADClient._entry_to_dict(entry)
    # No mapping for mSSMSSiteCode, so it falls through as-is
    assert "mSSMSSiteCode" in result
    assert result["mSSMSSiteCode"] == "PS1"
