"""Unit tests for the unauthenticated HTTP role-probe collector (collectors/http.py).

The collector probes a target's SCCM web endpoints over http then https and turns
the *unauthenticated* status codes (401/403/200) into role-tagged, computer-shaped
rows. Transport is a canned ``_FakeHttp`` keyed by URL substring; the context is a
minimal stand-in that records ``register_target`` calls (the live work-queue
side-effect) and hands back resolvable AD objects.

Behaviour under test reflects the two design decisions:
  * **B** -- all MP endpoints are probed in order (no early-exit), so MPLIST/SMSTRC
    still run after MPKEYINFORMATION confirms the role.
  * **6** -- a row is emitted only when a role is *confirmed* on an SCCM-specific
    path; the connected host's row is attributed to its self-reported FQDN, or the
    probe target itself when no FQDN payload is available. Never a bare row.
"""
import datetime
import logging

import pytest

from openhound_sccm.clients.http import ErrorClass, HttpResult
from openhound_sccm.collectors import http
from openhound_sccm.models.target_entry import TargetEntry


# --- fakes -----------------------------------------------------------------

class _FakeHttp:
    """Canned probe client. ``responses`` maps a URL *substring* -> HttpResult;
    ``fail_on`` substrings return a connection failure; everything else 404s."""

    def __init__(self, responses=None, fail_on=()):
        self.responses = responses or {}
        self.fail_on = fail_on
        self.calls = []

    def get(self, url, headers=None):  # headers mirrors the real HttpClient.get signature
        self.calls.append(url)
        for sub in self.fail_on:
            if sub in url:
                return HttpResult(None, None, ErrorClass.CONNECT_FAILURE)
        for sub, result in self.responses.items():
            if sub in url:
                return result
        return HttpResult(404, b"", ErrorClass.RESPONSE)

    def close(self):
        pass


class _Ctx:
    """Minimal SourceContext stand-in. ``registrations`` overrides the AD object
    returned for a given identifier (lowercased); the default is a resolvable
    object so rows are emitted."""

    def __init__(self, enabled=True, site_codes=None, registrations=None, filtered=()):
        self._enabled = enabled
        self.site_codes = site_codes
        self.domain = "mayyhem.com"
        self.username = self.password = self.nt_hash = self.kerberos_ticket = None
        self.ad = None
        self.target_hosts_by_hostname = {}
        self.registered = []  # (identifier, source, site_code) tuples
        self._registrations = registrations or {}
        self._filtered = {f.lower() for f in filtered}  # excluded from probing by --computers

    def method_enabled(self, name):
        return self._enabled

    def resolve_principal(self, identifier):
        if identifier.lower() in self._registrations:
            return self._registrations[identifier.lower()]
        return {"object_sid": "S-1-5-21-9", "name": identifier}

    def register_target(self, identifier, source, site_code=None):
        self.registered.append((identifier, source, site_code))
        if identifier.lower() in self._filtered:
            return None  # allowed-targets filter excludes it from probing
        ad_object = self.resolve_principal(identifier)
        is_new = identifier.lower() not in self.target_hosts_by_hostname
        entry = TargetEntry(hostname=identifier, ad_object=ad_object,
                            site_code=site_code, is_new=is_new)
        self.target_hosts_by_hostname[identifier.lower()] = entry
        return entry


def _use_fake(monkeypatch, fake):
    monkeypatch.setattr(http.HttpClient, "from_context",
                        classmethod(lambda cls, ctx, target, **kw: fake))


def _site_server_cert_hex(dns_name, issuer_cn="Site Server"):
    """Build a self-signed DER cert with the given issuer CN + SAN DNS, hex-encoded."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER).hex()


def _mp_rows(rows):
    return [r for t, r in rows if t == "http_management_points"]


# --- pure parse helpers (Task 3) -------------------------------------------

def test_parse_mpkeyinformation():
    xml = b"<MPKEYINFORMATION><FQDN>ps1.mayyhem.com</FQDN><SITECODE>PS1</SITECODE></MPKEYINFORMATION>"
    assert http._parse_mpkeyinformation(xml) == ("ps1.mayyhem.com", "PS1")


def test_parse_mplist():
    # The live SCCM MPList carries FQDN as an *attribute* of <MP>, not a child element.
    xml = (b'<MPList><MP Name="MP1" FQDN="mp1.mayyhem.com"><Version>9106</Version></MP>'
           b'<MP Name="MP2" FQDN="mp2.mayyhem.com"></MP></MPList>')
    assert http._parse_mplist(xml) == ["mp1.mayyhem.com", "mp2.mayyhem.com"]


def test_parse_sitesigncert_hex_rejects_short_payload():
    assert http._parse_sitesigncert_hex(b"<X509Certificate>ABCD</X509Certificate>") is None


def test_cert_issuer_and_dns():
    issuer, dns = http._cert_issuer_and_dns(_site_server_cert_hex("siteserver.mayyhem.com"))
    assert issuer == "Site Server" and dns == "siteserver.mayyhem.com"


# A payload that clears _parse_sitesigncert_hex's sanity checks (even length,
# >= 20 chars) but is not hex at all, so bytes.fromhex() rejects it.
_NON_HEX_PAYLOAD = "ZZ" * 12
# Valid hex of sufficient length that is not a DER certificate, so the X.509
# parser rejects it. These are the two distinct ways a hostile or broken
# management point can defeat the parse.
_NOT_A_CERT_PAYLOAD = "ab" * 12


def test_cert_issuer_and_dns_warns_on_non_hex_payload(caplog):
    """A non-hex payload yields (None, None) and names hex decoding as the reason.

    Without this the ValueError escapes to collect_http's broad handler, which
    reports every cause as "failed or not applicable" at VERBOSE.
    """
    with caplog.at_level(logging.WARNING, logger="openhound_sccm.collectors.http"):
        assert http._cert_issuer_and_dns(_NON_HEX_PAYLOAD) == (None, None)
    assert any("hex" in r.message.lower() and r.levelno == logging.WARNING
               for r in caplog.records), caplog.text


def test_cert_issuer_and_dns_warns_on_undecodable_certificate(caplog):
    """Valid hex that is not a certificate yields (None, None) and says so.

    Distinct from the hex failure: this is the branch cryptography 49.0.0 would
    newly reach for certs with NULL AlgorithmIdentifier params.
    """
    with caplog.at_level(logging.WARNING, logger="openhound_sccm.collectors.http"):
        assert http._cert_issuer_and_dns(_NOT_A_CERT_PAYLOAD) == (None, None)
    assert any("certificate" in r.message.lower() and r.levelno == logging.WARNING
               for r in caplog.records), caplog.text


def test_sitesigncert_probe_diagnoses_unparseable_certificate(monkeypatch, caplog):
    """Through the full probe path, an unparseable cert is diagnosed, not swallowed.

    Previously the ValueError escaped to collect_http's ``except Exception``, which
    logs "failed or not applicable" at VERBOSE -- collapsing endpoint-absent,
    network-failure and parser-rejected into one message. The probe must still fail
    soft (it is the only credential-free way to identify the Site Server), but the
    reason has to survive at WARNING.
    """
    xml = f"<X509Certificate>{_NON_HEX_PAYLOAD}</X509Certificate>".encode()
    fake = _FakeHttp({"sitesigncert": HttpResult(200, xml, ErrorClass.RESPONSE)})
    monkeypatch.setattr(http.HttpClient, "from_context", classmethod(lambda cls, *a, **k: fake))
    ctx = _Ctx()
    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.http"):
        rows = list(http.collect_http("mp.mayyhem.com", ctx))
    # Fails soft: no site server registered, collection continues.
    assert not any(src == "HTTP-sitesigncert" for _, src, _ in ctx.registered)
    assert all(t != "http_site_servers" for t, _ in rows)
    # Audibly: a WARNING names the reason ...
    assert any(r.levelno == logging.WARNING and "hex" in r.message.lower()
               for r in caplog.records), caplog.text
    # ... rather than escaping to the generic best-effort swallow.
    assert not any("failed or not applicable" in r.message for r in caplog.records), caplog.text


# --- gating ----------------------------------------------------------------

def test_method_disabled_yields_nothing():
    assert list(http.collect_http("h", _Ctx(enabled=False))) == []


# --- management point detection --------------------------------------------

def test_mpkeyinformation_detects_mp(monkeypatch):
    xml = b"<MPKEYINFORMATION><FQDN>ps1.mayyhem.com</FQDN><SITECODE>PS1</SITECODE></MPKEYINFORMATION>"
    fake = _FakeHttp({"MPKEYINFORMATION": HttpResult(200, xml, ErrorClass.RESPONSE)})
    _use_fake(monkeypatch, fake)
    rows = list(http.collect_http("ps1.mayyhem.com", _Ctx()))

    mp = _mp_rows(rows)
    assert len(mp) == 1
    assert mp[0]["name"] == "ps1.mayyhem.com"
    assert mp[0]["sccm_site_system_roles"] == "SMS Management Point@PS1"
    assert mp[0]["site_code"] == "PS1"
    assert mp[0]["sccm_infra"] is True
    assert mp[0]["client_cert_required"] is False
    assert mp[0]["source"] == "HTTP-MPKEYINFORMATION"
    # Decision B: MPLIST and SMSTRC are still probed after MPKEYINFORMATION confirms.
    assert any("MPLIST" in c for c in fake.calls)
    assert any("SMSTRC" in c for c in fake.calls)


def test_decision_b_probes_mplist_and_smstrc_even_after_mpkeyinformation(monkeypatch):
    xml = b"<MPKEYINFORMATION><FQDN>ps1.mayyhem.com</FQDN><SITECODE>PS1</SITECODE></MPKEYINFORMATION>"
    mplist = (b'<MPList><MP Name="MP1" FQDN="mp1.mayyhem.com"><Version>9106</Version></MP>'
              b'<MP Name="MP2" FQDN="mp2.mayyhem.com"></MP></MPList>')
    fake = _FakeHttp({
        "MPKEYINFORMATION": HttpResult(200, xml, ErrorClass.RESPONSE),
        "MPLIST": HttpResult(200, mplist, ErrorClass.RESPONSE),
        "SMSTRC": HttpResult(403, b"", ErrorClass.RESPONSE),
    })
    _use_fake(monkeypatch, fake)
    ctx = _Ctx()
    rows = list(http.collect_http("ps1.mayyhem.com", ctx))

    mp = _mp_rows(rows)
    # Connected MP + two enumerated siblings; all carry the final cert flag (True).
    assert {r["name"] for r in mp} == {"ps1.mayyhem.com", "mp1.mayyhem.com", "mp2.mayyhem.com"}
    assert all(r["client_cert_required"] is True for r in mp)
    assert all(r["sccm_site_system_roles"] == "SMS Management Point@PS1" for r in mp)
    registered = {ident for ident, _, _ in ctx.registered}
    assert {"mp1.mayyhem.com", "mp2.mayyhem.com"} <= registered


def test_cert_required_mp_attributes_row_to_connected_target(monkeypatch):
    # Decision 6: a cert-required MP 403s on the FQDN-bearing endpoints, so there is
    # no parseable host name -- the row is attributed to the probe target we dialed.
    fake = _FakeHttp({
        "MPKEYINFORMATION": HttpResult(403, b"", ErrorClass.RESPONSE),
        "SMSTRC": HttpResult(403, b"", ErrorClass.RESPONSE),
    })
    _use_fake(monkeypatch, fake)
    rows = list(http.collect_http("mp.mayyhem.com", _Ctx()))

    mp = _mp_rows(rows)
    assert len(mp) == 1
    assert mp[0]["name"] == "mp.mayyhem.com"
    assert mp[0]["client_cert_required"] is True
    assert mp[0]["sccm_site_system_roles"] == "SMS Management Point"  # no site code parsed
    assert mp[0]["source"] == "HTTP-SMS_MP"


def test_non_sccm_target_all_404_emits_nothing(monkeypatch):
    # Decision 6: a host with no SCCM role 404s on every SCCM-specific path, so no
    # role flips and nothing is tagged or registered.
    fake = _FakeHttp()  # everything 404s
    _use_fake(monkeypatch, fake)
    ctx = _Ctx()
    rows = list(http.collect_http("random.mayyhem.com", ctx))

    assert rows == []
    assert ctx.registered == []


def test_mplist_enumerates_management_points(monkeypatch):
    # MPKEYINFORMATION is non-MP (404); MPLIST confirms the target as an MP and lists
    # two siblings. The connected target plus both siblings get rows.
    mplist = (b'<MPList><MP Name="MP1" FQDN="mp1.mayyhem.com"><Version>9106</Version></MP>'
              b'<MP Name="MP2" FQDN="mp2.mayyhem.com"></MP></MPList>')
    fake = _FakeHttp({"MPLIST": HttpResult(200, mplist, ErrorClass.RESPONSE)})
    _use_fake(monkeypatch, fake)
    ctx = _Ctx()
    rows = list(http.collect_http("ps1.mayyhem.com", ctx))

    mp = _mp_rows(rows)
    assert {r["name"] for r in mp} == {"ps1.mayyhem.com", "mp1.mayyhem.com", "mp2.mayyhem.com"}
    assert all(r["sccm_site_system_roles"] == "SMS Management Point" for r in mp)  # no site code
    siblings = [r for r in mp if r["name"] != "ps1.mayyhem.com"]
    assert all(r["source"] == "HTTP-MPLIST" for r in siblings)


def test_mplist_self_entry_not_duplicated(monkeypatch):
    # An MP's MPList lists itself alongside its siblings; that self-entry must not
    # produce a second row for the connected MP (the MPKEYINFORMATION row covers it).
    xml = b"<MPKEYINFORMATION><FQDN>ps1-mp.mayyhem.com</FQDN><SITECODE>PS1</SITECODE></MPKEYINFORMATION>"
    mplist = (b'<MPList><MP Name="PS1-MP" FQDN="ps1-mp.mayyhem.com"></MP>'
              b'<MP Name="PS1-SEC" FQDN="ps1-sec.mayyhem.com"></MP></MPList>')
    fake = _FakeHttp({
        "MPKEYINFORMATION": HttpResult(200, xml, ErrorClass.RESPONSE),
        "MPLIST": HttpResult(200, mplist, ErrorClass.RESPONSE),
    })
    _use_fake(monkeypatch, fake)
    mp = _mp_rows(list(http.collect_http("ps1-mp.mayyhem.com", _Ctx())))
    names = [r["name"] for r in mp]
    assert names.count("ps1-mp.mayyhem.com") == 1  # self-entry skipped, not duplicated
    assert "ps1-sec.mayyhem.com" in names


# --- distribution point + SMS provider -------------------------------------

@pytest.mark.parametrize("status,cert", [(401, False), (200, False), (403, True)])
def test_distribution_point_role(monkeypatch, status, cert):
    fake = _FakeHttp({"SMS_DP_SMSPKG": HttpResult(status, b"x", ErrorClass.RESPONSE)})
    _use_fake(monkeypatch, fake)
    ctx = _Ctx()
    rows = list(http.collect_http("dp.mayyhem.com", ctx))

    dp = [r for t, r in rows if t == "http_distribution_points"]
    assert len(dp) == 1
    assert dp[0]["name"] == "dp.mayyhem.com"
    assert dp[0]["sccm_site_system_roles"] == "SMS Distribution Point"
    assert dp[0]["source"] == "HTTP-SMS_DP_SMSPKG$"
    assert dp[0]["sccm_infra"] is True
    assert dp[0]["client_cert_required"] is cert
    assert ("dp.mayyhem.com", "HTTP-SMS_DP_SMSPKG$", None) in ctx.registered


def test_sms_provider_role(monkeypatch):
    fake = _FakeHttp({"SMS_Identification": HttpResult(200, b"{}", ErrorClass.RESPONSE)})
    _use_fake(monkeypatch, fake)
    rows = list(http.collect_http("sms.mayyhem.com", _Ctx()))

    sms = [r for t, r in rows if t == "http_smsproviders"]
    assert len(sms) == 1
    assert sms[0]["name"] == "sms.mayyhem.com"
    assert sms[0]["sccm_site_system_roles"] == "SMS Provider"
    assert sms[0]["source"] == "HTTP-SMS_Identification"


def test_unresolved_host_emits_no_row_but_still_registers(monkeypatch):
    fake = _FakeHttp({"SMS_DP_SMSPKG": HttpResult(200, b"x", ErrorClass.RESPONSE)})
    _use_fake(monkeypatch, fake)
    ctx = _Ctx(registrations={"dp.mayyhem.com": None})  # unresolvable in AD
    rows = list(http.collect_http("dp.mayyhem.com", ctx))

    assert [r for t, r in rows if t == "http_distribution_points"] == []
    assert ("dp.mayyhem.com", "HTTP-SMS_DP_SMSPKG$", None) in ctx.registered


# --- connection failure short-circuit --------------------------------------

def test_connection_failure_stops_protocol_loop_probing(monkeypatch):
    """A connection failure short-circuits the protocol loop (PS1 $connectionFailed).

    con-7741 carved out one deliberate exception: the SMS Provider probe. It is
    HTTPS-only by construction, so gating it on a port-80 failure cost hosts a role
    they were serving perfectly well on 443. Everything driven by the loop protocol --
    the https MP retry and the DP probe -- is still suppressed as before.
    """
    fake = _FakeHttp(fail_on=("MPKEYINFORMATION",))
    _use_fake(monkeypatch, fake)
    rows = list(http.collect_http("dead.mayyhem.com", _Ctx()))

    assert rows == []
    # http MPKEYINFORMATION failed -> protocol loop breaks: no https retry, no DP.
    assert sum(1 for c in fake.calls if "MPKEYINFORMATION" in c) == 1
    assert not any("SMS_DP_SMSPKG" in c for c in fake.calls)
    # ... but the HTTPS-only SMS Provider probe still runs, exactly once.
    assert sum(1 for c in fake.calls if "SMS_Identification" in c) == 1


# --- sitesigncert site server ----------------------------------------------

def test_sitesigncert_detects_site_server(monkeypatch):
    der_hex = _site_server_cert_hex("siteserver.mayyhem.com")
    xml = (b'<MPSITESIGNCERT><X509Certificate Signature="x">'
           + der_hex.encode() + b"</X509Certificate></MPSITESIGNCERT>")
    fake = _FakeHttp({"sitesigncert": HttpResult(200, xml, ErrorClass.RESPONSE)})
    _use_fake(monkeypatch, fake)
    ctx = _Ctx()
    rows = list(http.collect_http("mp.mayyhem.com", ctx))

    ss = [r for t, r in rows if t == "http_site_servers"]
    assert len(ss) == 1
    assert "SMS Site Server" in ss[0]["sccm_site_system_roles"]
    assert ss[0]["source"] == "HTTP-sitesigncert"
    # mp_host is the breadcrumb naming which MP the cert was read from, so
    # transforms._node_computer can recover the site code the probe ran too
    # early (ps1:8611 ordering) to know itself.
    assert ss[0]["mp_host"] == "mp.mayyhem.com"
    assert ("siteserver.mayyhem.com", "HTTP-sitesigncert", None) in ctx.registered


def test_sitesigncert_ignores_non_site_server_issuer(monkeypatch):
    der_hex = _site_server_cert_hex("mp.mayyhem.com", issuer_cn="Internal Issuing CA")
    xml = b"<X509Certificate>" + der_hex.encode() + b"</X509Certificate>"
    fake = _FakeHttp({"sitesigncert": HttpResult(200, xml, ErrorClass.RESPONSE)})
    _use_fake(monkeypatch, fake)
    ctx = _Ctx()
    rows = list(http.collect_http("mp.mayyhem.com", ctx))

    assert [r for t, r in rows if t == "http_site_servers"] == []
    assert not any(src == "HTTP-sitesigncert" for _, src, _ in ctx.registered)


# --- allowed-targets filter gates probing, not recording -------------------

def test_filtered_site_server_still_recorded(monkeypatch):
    # The --computers filter excludes the cert-named site server from *probing*,
    # but the discovered "SMS Site Server" role must still be recorded.
    der_hex = _site_server_cert_hex("ps1-pss.mayyhem.com")
    xml = b"<X509Data><X509Certificate>" + der_hex.encode() + b"</X509Certificate></X509Data>"
    fake = _FakeHttp({"sitesigncert": HttpResult(200, xml, ErrorClass.RESPONSE)})
    _use_fake(monkeypatch, fake)
    ctx = _Ctx(filtered={"ps1-pss.mayyhem.com"})
    rows = list(http.collect_http("ps1-mp.mayyhem.com", ctx))

    ss = [r for t, r in rows if t == "http_site_servers"]
    assert len(ss) == 1
    assert ss[0]["name"] == "ps1-pss.mayyhem.com"
    # registration was attempted (so the filter could decide) but not queued
    assert ("ps1-pss.mayyhem.com", "HTTP-sitesigncert", None) in ctx.registered
    assert "ps1-pss.mayyhem.com" not in ctx.target_hosts_by_hostname


def test_filtered_sibling_mp_still_recorded(monkeypatch):
    mplist = b'<MPList><MP Name="MP2" FQDN="mp2.mayyhem.com"></MP></MPList>'
    fake = _FakeHttp({"MPLIST": HttpResult(200, mplist, ErrorClass.RESPONSE)})
    _use_fake(monkeypatch, fake)
    ctx = _Ctx(filtered={"mp2.mayyhem.com"})
    rows = list(http.collect_http("ps1-mp.mayyhem.com", ctx))

    mp = _mp_rows(rows)
    assert "mp2.mayyhem.com" in {r["name"] for r in mp}  # recorded despite the filter
    assert "mp2.mayyhem.com" not in ctx.target_hosts_by_hostname  # not queued for probing


# --- pipeline wiring + skip gate -------------------------------------------

def test_http_phase_registered_after_wmi():
    from openhound_sccm.per_host_phases import PER_HOST_PHASES, all_table_names

    names = [p.name for p in PER_HOST_PHASES]
    assert "HTTP" in names
    assert names.index("HTTP") > names.index("WMI")
    tables = set(all_table_names(PER_HOST_PHASES))
    assert {"http_management_points", "http_distribution_points",
            "http_smsproviders", "http_site_servers"} <= tables


class _GateCtx:
    def __init__(self, entries, enabled=True):
        self.target_hosts_by_hostname = entries
        self._enabled = enabled

    def method_enabled(self, name):
        return self._enabled


def _http_phase():
    from openhound_sccm.per_host_phases import PER_HOST_PHASES
    return next(ph for ph in PER_HOST_PHASES if ph.name == "HTTP")


@pytest.mark.parametrize("completed", [{"AdminService"}, {"WMI"}, {"AdminService", "WMI"}])
def test_should_run_phase_skips_http_after_privileged_collection(completed):
    from openhound_sccm.per_host_phases import should_run_phase
    entry = TargetEntry(hostname="h", ad_object=None, completed_phases=set(completed))
    assert should_run_phase("h", _http_phase(), _GateCtx({"h": entry})) is False


def test_should_run_phase_runs_http_when_privileged_collection_absent():
    from openhound_sccm.per_host_phases import should_run_phase
    entry = TargetEntry(hostname="h", ad_object=None)
    assert should_run_phase("h", _http_phase(), _GateCtx({"h": entry})) is True


def test_should_run_phase_skips_http_when_method_disabled():
    from openhound_sccm.per_host_phases import should_run_phase
    entry = TargetEntry(hostname="h", ad_object=None)
    assert should_run_phase("h", _http_phase(), _GateCtx({"h": entry}, enabled=False)) is False


# --- con-7741: a filtered port 80 must not hide an HTTPS-only SMS Provider ---
#
# The role loop runs http then https, breaking out on the first connection failure
# (PS1's $connectionFailed parity). But sms_provider() is HTTPS-only by construction
# -- it builds an https:// URL regardless of the loop protocol -- yet it sat behind
# those breaks. So a host with 80 filtered and 443 serving the AdminService lost its
# SMS Provider tag entirely, on a port that was never the problem.
#
# That tag is load-bearing: SCCM_AssignAllPermissions and the
# SCCM_CoerceAndRelayToAdminService pair list are both built from it, so the loss is
# silent and downstream rather than a visible probe error.

def test_sms_provider_detected_when_port_80_is_filtered(monkeypatch):
    """80 filtered, 443 serving the AdminService -> still tagged SMS Provider."""
    fake = _FakeHttp(
        {"AdminService/wmi/SMS_Identification": HttpResult(401, b"", ErrorClass.RESPONSE)},
        fail_on=("http://",),          # every plaintext URL refuses
    )
    monkeypatch.setattr(http.HttpClient, "from_context", classmethod(lambda cls, *a, **k: fake))
    ctx = _Ctx()
    rows = list(http.collect_http("ps1-sms.mayyhem.com", ctx))
    provider_rows = [r for t, r in rows if t == "http_smsproviders"]
    assert provider_rows, (
        "SMS Provider missed: the probe is HTTPS-only, so a filtered port 80 "
        f"must not suppress it. URLs tried: {fake.calls}"
    )


def test_sms_provider_still_probed_only_once_when_http_succeeds(monkeypatch):
    """The normal path must not gain a duplicate probe from the hoist."""
    fake = _FakeHttp(
        {"AdminService/wmi/SMS_Identification": HttpResult(401, b"", ErrorClass.RESPONSE)},
    )
    monkeypatch.setattr(http.HttpClient, "from_context", classmethod(lambda cls, *a, **k: fake))
    list(http.collect_http("ps1-sms.mayyhem.com", _Ctx()))
    hits = [u for u in fake.calls if "SMS_Identification" in u]
    assert len(hits) == 1, f"expected one AdminService probe, got {hits}"
