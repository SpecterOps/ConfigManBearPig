# src/openhound_sccm/collectors/ldap_test: _parse_sd_generic_all must only report a
# principal when the ACE really grants Full Control on the System Management container
# itself.
#
# An access mask of 0x000F01FF alone does not mean Full Control. Exchange's
# `setup /PrepareAD` writes ACEs at the domain root that carry that exact mask but are
# scoped away from the container -- some are INHERIT_ONLY (they exist only to be copied
# to child objects), others are object ACEs whose mask applies to a single property set.
# Those ACEs inherit down onto System Management. Reading
# the mask and nothing else made Exchange Trusted Subsystem look like a site server
# owner, and the group walk in _expand_group_targets then registered every Exchange
# server as an SCCM scan target.
import struct

from openhound_sccm.collectors.ldap import _parse_sd_generic_all

AD_FULL_CONTROL = 0x000F01FF

ACCESS_ALLOWED_ACE_TYPE = 0x00
ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05

CONTAINER_INHERIT_ACE = 0x02
INHERIT_ONLY_ACE = 0x08
INHERITED_ACE = 0x10

ACE_OBJECT_TYPE_PRESENT = 0x01
ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x02

SITE_SERVER_SID = "S-1-5-21-1-2-3-1104"
SCCM_GROUP_SID = "S-1-5-21-1-2-3-1105"
EXCHANGE_SID = "S-1-5-21-1-2-3-1106"
LOCAL_SYSTEM_SID = "S-1-5-18"
BUILTIN_ADMIN_SID = "S-1-5-32-544"
CREATOR_OWNER_SID = "S-1-3-0"

GUID = bytes(range(16))


def _sid_bytes(sid: str) -> bytes:
    """Pack a string SID back into its on-the-wire form."""
    parts = sid.split("-")[1:]
    revision, authority = int(parts[0]), int(parts[1])
    subs = [int(p) for p in parts[2:]]
    out = struct.pack("<BB", revision, len(subs)) + authority.to_bytes(6, "big")
    return out + b"".join(struct.pack("<I", s) for s in subs)


def _plain_ace(sid: str, mask: int = AD_FULL_CONTROL, flags: int = 0) -> bytes:
    sid_b = _sid_bytes(sid)
    size = 8 + len(sid_b)
    return struct.pack("<BBHI", ACCESS_ALLOWED_ACE_TYPE, flags, size, mask) + sid_b


def _object_ace(sid: str, obj_flags: int, mask: int = AD_FULL_CONTROL, flags: int = 0) -> bytes:
    sid_b = _sid_bytes(sid)
    guids = b""
    if obj_flags & ACE_OBJECT_TYPE_PRESENT:
        guids += GUID
    if obj_flags & ACE_INHERITED_OBJECT_TYPE_PRESENT:
        guids += GUID
    size = 12 + len(guids) + len(sid_b)
    return (struct.pack("<BBHII", ACCESS_ALLOWED_OBJECT_ACE_TYPE, flags, size, mask, obj_flags)
            + guids + sid_b)


def _descriptor(*aces: bytes) -> bytes:
    """Wrap ACEs in a self-relative SECURITY_DESCRIPTOR with the DACL at offset 20."""
    body = b"".join(aces)
    acl = struct.pack("<BBHHH", 2, 0, 8 + len(body), len(aces), 0) + body
    header = struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0, 20)
    return header + acl


def test_plain_full_control_ace_is_reported():
    sd = _descriptor(_plain_ace(SITE_SERVER_SID))
    assert _parse_sd_generic_all(sd) == [SITE_SERVER_SID]


def test_inherited_container_ace_is_still_reported():
    # An SCCM install commonly grants a group Full Control with CONTAINER_INHERIT set,
    # and the ACE may itself be marked as inherited. Both still apply to the container.
    sd = _descriptor(_plain_ace(SCCM_GROUP_SID, flags=CONTAINER_INHERIT_ACE | INHERITED_ACE))
    assert _parse_sd_generic_all(sd) == [SCCM_GROUP_SID]


def test_inherit_only_ace_is_ignored():
    sd = _descriptor(_plain_ace(EXCHANGE_SID, flags=INHERIT_ONLY_ACE | CONTAINER_INHERIT_ACE))
    assert _parse_sd_generic_all(sd) == []


def test_object_ace_scoped_to_a_property_set_is_ignored():
    sd = _descriptor(_object_ace(EXCHANGE_SID, ACE_OBJECT_TYPE_PRESENT, flags=INHERITED_ACE))
    assert _parse_sd_generic_all(sd) == []


def test_inherit_only_object_ace_with_child_class_is_ignored():
    sd = _descriptor(_object_ace(EXCHANGE_SID, ACE_INHERITED_OBJECT_TYPE_PRESENT,
                                 flags=INHERITED_ACE | INHERIT_ONLY_ACE))
    assert _parse_sd_generic_all(sd) == []


def test_inherited_object_type_without_inherit_only_applies_here():
    # InheritedObjectType limits which children receive the ACE; it does not
    # restrict an otherwise effective ACE on this container.
    sd = _descriptor(_object_ace(SCCM_GROUP_SID, ACE_INHERITED_OBJECT_TYPE_PRESENT,
                                 flags=CONTAINER_INHERIT_ACE))
    assert _parse_sd_generic_all(sd) == [SCCM_GROUP_SID]


def test_unscoped_object_ace_is_reported():
    # Type 0x05 with no GUID at all behaves like a plain allow ACE.
    sd = _descriptor(_object_ace(SITE_SERVER_SID, 0))
    assert _parse_sd_generic_all(sd) == [SITE_SERVER_SID]


def test_built_in_principals_are_ignored():
    for sid in (LOCAL_SYSTEM_SID, BUILTIN_ADMIN_SID, CREATOR_OWNER_SID):
        sd = _descriptor(_plain_ace(sid))
        assert _parse_sd_generic_all(sd) == []


def test_exchange_prepare_ad_pattern_leaves_only_the_site_server():
    """The shape of a real System Management DACL in an Exchange domain."""
    sd = _descriptor(
        _plain_ace(SITE_SERVER_SID),
        _plain_ace(SCCM_GROUP_SID, flags=CONTAINER_INHERIT_ACE),
        _plain_ace(LOCAL_SYSTEM_SID),
        _object_ace(EXCHANGE_SID, ACE_OBJECT_TYPE_PRESENT,
                    flags=INHERITED_ACE | CONTAINER_INHERIT_ACE),
        _object_ace(EXCHANGE_SID, ACE_INHERITED_OBJECT_TYPE_PRESENT,
                    flags=INHERITED_ACE | INHERIT_ONLY_ACE | CONTAINER_INHERIT_ACE),
    )
    assert _parse_sd_generic_all(sd) == [SITE_SERVER_SID, SCCM_GROUP_SID]
