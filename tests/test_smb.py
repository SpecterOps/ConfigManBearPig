"""Unit tests for the SMB share + signing collector (collectors/smb.py).

Two layers are exercised:
  * ``_classify_shares`` -- the pure share-name/description -> role/site-code/flag
    classifier, including the PS1 copy-paste bug-fixes (the ``SMS_*`` and
    share-description site-code branches read the matched share's own description).
  * ``collect_smb`` -- the orchestration order: the unauthenticated negotiate
    signing row is always emitted when determined; share/role rows only when an
    SCCM-specific share confirms the host (the http.py-style improvement).

Client I/O (``check_smb_signing`` / ``connect_smb`` / ``list_shares``) is
monkeypatched, so no network is touched.
"""
import struct

from openhound_sccm.clients import smb as smb_client
from openhound_sccm.collectors import smb
from openhound_sccm.collectors.smb import _classify_shares
from openhound_sccm.models.target_entry import TargetEntry


# --- _classify_shares ------------------------------------------------------

def test_sms_site_share_makes_site_server_with_site_code():
    c = _classify_shares([("SMS_SITE", "SMS Site PS1")])
    assert c.is_site_server and not c.is_dp
    assert c.site_code == "PS1"
    assert c.collection_source == ["SMB-SMS_SITE"]
    assert c.roles() == ["SMS Site Server@PS1"]


def test_sms_star_branch_reads_its_own_description():
    # PS1 reads $smsSite.Description here (null); the fix reads the SMS_* share's.
    c = _classify_shares([("SMS_PS1", "SMS Site PS1")])
    assert c.is_site_server
    assert c.site_code == "PS1"
    assert c.collection_source == ["SMB-SMS_*"]


def test_sms_dp_share_makes_distribution_point_and_refines_site_code():
    c = _classify_shares([("SMS_DP$", "SMS Site PS1 DP")])
    assert c.is_dp and not c.is_site_server
    assert c.site_code == "PS1"
    # The DP share's description itself names the site, so the share-description
    # fallback tags it too (PS1-faithful tag ordering), then SMS_DP$ confirms.
    assert c.collection_source == ["SMB-ShareDescription", "SMB-SMS_DP$"]
    assert c.roles() == ["SMS Distribution Point@PS1"]


def test_reminst_and_content_library_flags():
    c = _classify_shares([
        ("SMS_SITE", "SMS Site PS1"),
        ("REMINST", "Remote Installation"),
        ("SCCMContentLib$", "Content Library"),
        ("SMSPKG$", "SMS Package share"),
    ])
    assert c.is_pxe_enabled
    assert c.hosts_content_library
    assert c.collection_source == [
        "SMB-SMS_SITE", "SMB-REMINST", "SMB-SCCMContentLib$", "SMB-SMSPKG$",
    ]


def test_site_code_falls_back_to_any_share_description():
    # No SMS_SITE / SMS_* name match, but a share *description* names the site.
    c = _classify_shares([("RandomShare", "SMS Site PS1 stuff")])
    assert c.site_code == "PS1"
    assert c.collection_source == ["SMB-ShareDescription"]
    assert not c.is_site_server and not c.is_dp


def test_non_sccm_shares_classify_as_not_sccm():
    c = _classify_shares([("C$", ""), ("ADMIN$", ""), ("Users", "")])
    assert not c.is_sccm
    assert c.collection_source == []
    assert c.roles() == []


def test_site_server_and_dp_combined_roles():
    c = _classify_shares([("SMS_SITE", "SMS Site PS1"), ("SMS_DP$", "SMS Site PS1 DP")])
    assert c.roles() == ["SMS Site Server@PS1", "SMS Distribution Point@PS1"]


# --- collect_smb orchestration ---------------------------------------------

class _Ctx:
    """Minimal SourceContext stand-in: gating + one registered target."""

    def __init__(self, ad_object=None, enabled=True):
        self.domain = "mayyhem.com"
        self.username = None
        self.password = None
        self._enabled = enabled
        self.target_hosts_by_hostname = {
            "host": TargetEntry(hostname="host", ad_object=ad_object)
        }

    def method_enabled(self, name):
        return self._enabled


class _FakeSmb:
    def logoff(self):
        pass


def _patch_clients(monkeypatch, *, signing, shares=None, connect=True):
    monkeypatch.setattr(smb, "check_smb_signing", lambda target, **kw: signing)
    monkeypatch.setattr(
        smb, "connect_smb",
        lambda *a, **kw: _FakeSmb() if connect else None,
    )
    monkeypatch.setattr(smb, "list_shares", lambda conn: shares or [])


def test_collect_skips_when_method_disabled(monkeypatch):
    _patch_clients(monkeypatch, signing=True, shares=[("SMS_SITE", "SMS Site PS1")])
    rows = list(smb.collect_smb("host", _Ctx(enabled=False)))
    assert rows == []


def test_collect_emits_signing_row_then_role_row(monkeypatch):
    _patch_clients(monkeypatch, signing=False, shares=[("SMS_SITE", "SMS Site PS1")])
    rows = list(smb.collect_smb("host", _Ctx(ad_object={"name": "HOST", "object_sid": "S-1-5"})))

    tables = [t for t, _ in rows]
    assert tables == ["smb_computers", "smb_sites", "smb_computers"]

    signing_row = rows[0][1]
    assert signing_row["source"] == "SMB-Negotiate"
    assert signing_row["smb_signing_required"] is False
    assert signing_row["object_sid"] == "S-1-5"  # AD object spread through

    site_row = rows[1][1]
    assert site_row == {"source": "SMB-Shares", "site_code": "PS1"}

    role_row = rows[2][1]
    assert role_row["sccm_site_system_roles"] == ["SMS Site Server@PS1"]
    assert role_row["sccm_infra"] is True
    assert role_row["collection_source"] == ["SMB-SMS_SITE"]


def test_collect_unreachable_host_emits_nothing(monkeypatch):
    # signing None == PS1's $result.Error: host unreachable, share enum skipped.
    _patch_clients(monkeypatch, signing=None)
    rows = list(smb.collect_smb("host", _Ctx()))
    assert rows == []


def test_collect_signing_only_when_no_sccm_shares(monkeypatch):
    _patch_clients(monkeypatch, signing=True, shares=[("C$", ""), ("ADMIN$", "")])
    rows = list(smb.collect_smb("host", _Ctx()))
    assert [t for t, _ in rows] == ["smb_computers"]
    assert rows[0][1]["source"] == "SMB-Negotiate"
    assert rows[0][1]["smb_signing_required"] is True


def test_collect_signing_row_survives_auth_failure(monkeypatch):
    # Negotiate succeeded (signing known) but authenticated share enum can't connect.
    _patch_clients(monkeypatch, signing=True, connect=False)
    rows = list(smb.collect_smb("host", _Ctx()))
    assert [t for t, _ in rows] == ["smb_computers"]
    assert rows[0][1]["source"] == "SMB-Negotiate"


def test_collect_forwards_full_credential_set_to_connect_smb(monkeypatch):
    # Share enumeration must honor --nt-hash / --ticket, not just password/SSPI.
    captured = {}

    def _fake_connect(target, domain, username, password, **kw):
        captured.update(target=target, password=password, **kw)
        return _FakeSmb()

    monkeypatch.setattr(smb, "check_smb_signing", lambda t, **k: True)
    monkeypatch.setattr(smb, "connect_smb", _fake_connect)
    monkeypatch.setattr(smb, "list_shares", lambda conn: [])

    ctx = _Ctx()
    ctx.nt_hash = "deadbeef"
    ctx.kerberos_ticket = "TICKETB64"
    list(smb.collect_smb("host", ctx))

    assert captured["nt_hash"] == "deadbeef"
    assert captured["kerberos_ticket"] == "TICKETB64"
    assert "kdc_host" in captured  # derived from ctx.ad.creds (None here, but passed)


# --- signing detection (clients/smb.py): server SecurityMode, NOT RequireSigning

def _smb2_reply(security_mode: int) -> bytes:
    """A minimal SMB2 NEGOTIATE reply carrying *security_mode* at offset 70."""
    data = bytearray(72)
    data[4:8] = b"\xfeSMB"
    struct.pack_into("<H", data, smb_client._SECURITY_MODE_OFFSET, security_mode)
    return bytes(data)


def test_parse_security_mode_required_vs_not():
    assert smb_client._parse_security_mode(_smb2_reply(0x0003)) is True   # ENABLED|REQUIRED
    assert smb_client._parse_security_mode(_smb2_reply(0x0001)) is False  # ENABLED only


def test_parse_security_mode_rejects_short_or_non_smb2():
    assert smb_client._parse_security_mode(b"\x00" * 40) is None          # too short
    bad = bytearray(_smb2_reply(0x0003))
    bad[4:8] = b"\xffSMB"
    assert smb_client._parse_security_mode(bytes(bad)) is None            # not SMB2


def test_build_smb2_negotiate_is_wellformed():
    pkt = smb_client._build_smb2_negotiate()
    assert struct.unpack(">I", pkt[:4])[0] == len(pkt) - 4   # NetBIOS length covers the rest
    assert pkt[4:8] == b"\xfeSMB"                            # SMB2 magic
    # DialectCount lives at body offset 2 -> absolute 4 + 64 + 2 = 70.
    assert struct.unpack_from("<H", pkt, 70)[0] == len(smb_client._PROBE_DIALECTS)


class _FakeSMBConn:
    """Stand-in exposing impacket's getSMBServer()._Connection dict."""

    def __init__(self, conn):
        self._conn = conn

    def getSMBServer(self):
        return type("S", (), {"_Connection": self._conn})()

    def getRemoteHost(self):
        return "1.2.3.4"


def test_negotiated_signing_reads_server_mode_not_client_requiresigning():
    # The regression: a 3.1.1 connection where the SERVER does NOT require signing.
    # impacket forces _Connection['RequireSigning']=True here; ServerSecurityMode is honest.
    not_required = {"Dialect": 0x0311, "RequireSigning": True, "ServerSecurityMode": 0x0001}
    assert smb_client.negotiated_signing_required(_FakeSMBConn(not_required)) is False
    required = {"Dialect": 0x0311, "RequireSigning": True, "ServerSecurityMode": 0x0003}
    assert smb_client.negotiated_signing_required(_FakeSMBConn(required)) is True


def test_negotiated_signing_none_for_legacy_dialect_and_no_connection():
    legacy = {"Dialect": 0x0210, "ServerSecurityMode": 0}  # SMB 2.1: not stored by impacket
    assert smb_client.negotiated_signing_required(_FakeSMBConn(legacy)) is None
    assert smb_client.negotiated_signing_required(None) is None
