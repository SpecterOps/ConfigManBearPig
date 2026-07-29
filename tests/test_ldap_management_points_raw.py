from types import SimpleNamespace
from unittest.mock import MagicMock

from openhound_sccm.collectors.ldap import _parse_mp_capabilities, ldap_management_points_raw


PRIMARY_XML = """<ClientOperationalSettings>
  <CCM CommandLine="SMSSITECODE=PS1" />
  <RootSiteCode>CAS</RootSiteCode>
</ClientOperationalSettings>"""

NO_ROOT_XML = """<ClientOperationalSettings>
  <CCM CommandLine="SMSSITECODE=PS1" />
</ClientOperationalSettings>"""

FSP_XML = """<ClientOperationalSettings>
  <CCM CommandLine="SMSSITECODE=PS1" />
  <RootSiteCode>CAS</RootSiteCode>
  <FSP>
    <FSPServer>fsp1.contoso.com</FSPServer>
    <FSPServer>fsp2.contoso.com</FSPServer>
  </FSP>
</ClientOperationalSettings>"""


def test_primary_site_with_cas_parent():
    result = _parse_mp_capabilities(PRIMARY_XML, "PS1")
    assert result["site_type"] == "Primary Site"
    assert result["parent_site_code"] == "CAS"
    assert result["command_line_site_code"] == "PS1"
    assert result["root_site_code"] == "CAS"


def test_cas_site():
    result = _parse_mp_capabilities(PRIMARY_XML, "CAS")
    assert result["site_type"] == "Central Administration Site"
    assert result["parent_site_code"] == "None"


def test_secondary_site():
    result = _parse_mp_capabilities(PRIMARY_XML, "SEC")
    assert result["site_type"] == "Secondary Site"
    assert result["parent_site_code"] == "CAS"


def test_secondary_site_cmdline_fallback_parent():
    # Secondary with no RootSiteCode — parent falls back to CommandLine site code
    result = _parse_mp_capabilities(NO_ROOT_XML, "SEC")
    assert result["site_type"] == "Secondary Site"
    assert result["parent_site_code"] == "PS1"


def test_primary_standalone_no_root():
    result = _parse_mp_capabilities(NO_ROOT_XML, "PS1")
    assert result["site_type"] == "Primary Site"
    assert result["parent_site_code"] == "None"


def test_fsp_hostname_extracted_takes_first():
    # FSP_XML has two FSPServer nodes; only-if-one semantics keeps the first
    result = _parse_mp_capabilities(FSP_XML, "PS1")
    assert result["fsp_hostname"] == "fsp1.contoso.com"


def test_no_fsp_hostname_when_no_fsp_element():
    result = _parse_mp_capabilities(PRIMARY_XML, "PS1")
    assert result["fsp_hostname"] is None


def test_malformed_xml_returns_safe_defaults():
    result = _parse_mp_capabilities("<<not xml>>", "PS1")
    assert result["site_type"] == "Secondary Site"
    assert result["parent_site_code"] == "Undetermined"
    assert result["fsp_hostname"] is None


def test_empty_string_returns_safe_defaults():
    result = _parse_mp_capabilities("", "PS1")
    assert result["site_type"] == "Secondary Site"
    assert result["parent_site_code"] == "Undetermined"
    assert result["fsp_hostname"] is None


# --- ldap_management_points_raw resource: fsp_sid wiring + unresolved-target
# regression (review fix round 1, MINOR-7 + pre-existing bug) --------------

FSP_XML = """<ClientOperationalSettings>
  <CCM CommandLine="SMSSITECODE=PS1" />
  <RootSiteCode>CAS</RootSiteCode>
  <FSP>
    <FSPServer>fsp1.contoso.com</FSPServer>
  </FSP>
</ClientOperationalSettings>"""


def _mp_entry(mp_name, site_code, capabilities_xml):
    return {
        "mSSMSMPName": mp_name,
        "mSSMSSiteCode": site_code,
        "mSSMSCapabilities": capabilities_xml,
    }


def _raw(resource):
    """Return the undecorated generator behind an ``@app.resource`` DltResource.

    Calling the DltResource object directly runs dlt's own pipe/extraction
    iteration, which -- since this resource declares
    ``columns=raw_table_asset(...)`` with ``return_validated_models: True`` --
    validates each yielded dict into a pydantic model instance rather than a
    plain dict. Reaching the wrapped function bypasses that (the wrapping
    layers are transparent pass-throughs), so assertions can index the plain
    dict as written by the collector. Same technique as
    local_resources_state_test.py's ``_raw()``.
    """
    return resource._pipe.gen.__wrapped__


class _Ctx:
    """Minimal ldap_management_points_raw stand-in: only what the resource touches."""

    def __init__(self, entries, targets=None, resolved=None):
        self.domain = "CONTOSO.COM"
        self.ad = MagicMock()
        self.ad.paged_search.return_value = iter(entries)
        self.system_management_dn = "CN=System Management,CN=System,DC=contoso,DC=com"
        self.primary_site_codes = None
        self._targets = targets or {}
        # FIX-4: register_target returns None when --computers excludes a host,
        # but resolve_principal (called internally by the real register_target
        # BEFORE the filter runs) is still expected to work -- this stands in
        # for that fallback lookup.
        self._resolved = resolved or {}
        self.register_calls = []

    def method_enabled(self, method):
        return True

    def register_target(self, identifier, source, site_code=None):
        self.register_calls.append((identifier, source, site_code))
        return self._targets.get(identifier)

    def resolve_principal(self, identifier):
        return self._resolved.get(identifier)


def test_fsp_sid_reaches_the_yielded_row():
    """fsp_sid (Task 1b) is hoisted out of the log-message-only local it used to
    be and must reach the yielded row so the transform can key its FSP arm on a
    real sid instead of inventing one from the hostname."""
    entry = _mp_entry("ps1-mp.contoso.com", "PS1", FSP_XML)
    ctx = _Ctx(
        [entry],
        targets={
            "ps1-mp.contoso.com": SimpleNamespace(ad_object={"object_sid": "S-1-MP"}),
            "fsp1.contoso.com": SimpleNamespace(ad_object={"object_sid": "S-1-FSP"}),
        },
    )

    rows = list(_raw(ldap_management_points_raw)(ctx))

    assert len(rows) == 1
    assert rows[0]["fsp_hostname"] == "fsp1.contoso.com"
    assert rows[0]["fsp_sid"] == "S-1-FSP"


def test_fsp_sid_is_none_when_fsp_not_resolved_in_ad():
    """An FSP that's registered as a probe target but not (yet) resolved in AD
    yields fsp_sid=None rather than crashing (see the unresolved-MP regression
    test below for the crash this used to cause before the guard)."""
    entry = _mp_entry("ps1-mp.contoso.com", "PS1", FSP_XML)
    ctx = _Ctx(
        [entry],
        targets={
            "ps1-mp.contoso.com": SimpleNamespace(ad_object={"object_sid": "S-1-MP"}),
            "fsp1.contoso.com": SimpleNamespace(ad_object=None),  # registered but unresolved
        },
    )

    rows = list(_raw(ldap_management_points_raw)(ctx))

    assert len(rows) == 1
    assert rows[0]["fsp_sid"] is None


def test_fsp_excluded_by_computers_filter_still_gets_recorded():
    """FIX-4: the --computers allowed-targets filter gates PROBING, not
    RECORDING (mirrors http.py's _register_and_resolve / D6). register_target
    resolves the AD object internally BEFORE applying that filter, so a None
    return here means the object was found and then discarded, not that it's
    unresolvable. The FSP arm must fall back to resolve_principal (cached, no
    extra LDAP round-trip) so an FSP excluded from probing by --computers still
    yields its role instead of silently vanishing."""
    entry = _mp_entry("ps1-mp.contoso.com", "PS1", FSP_XML)
    ctx = _Ctx(
        [entry],
        targets={
            "ps1-mp.contoso.com": SimpleNamespace(ad_object={"object_sid": "S-1-MP"}),
            # fsp1.contoso.com deliberately absent: register_target returns
            # None, simulating the --computers filter declining to queue it.
        },
        resolved={"fsp1.contoso.com": {"object_sid": "S-1-FSP"}},
    )

    rows = list(_raw(ldap_management_points_raw)(ctx))

    assert len(rows) == 1
    assert rows[0]["fsp_sid"] == "S-1-FSP"


def test_fsp_excluded_and_unresolvable_yields_none_not_a_crash():
    """When the FSP is excluded by --computers AND cannot be resolved in AD at
    all (e.g. it's not a real computer object), fsp_sid stays None -- no role
    to record -- rather than the fallback lookup raising."""
    entry = _mp_entry("ps1-mp.contoso.com", "PS1", FSP_XML)
    ctx = _Ctx(
        [entry],
        targets={"ps1-mp.contoso.com": SimpleNamespace(ad_object={"object_sid": "S-1-MP"})},
        resolved={},  # fsp1.contoso.com not resolvable either
    )

    rows = list(_raw(ldap_management_points_raw)(ctx))

    assert len(rows) == 1
    assert rows[0]["fsp_sid"] is None


def test_unresolved_mp_still_yields_its_capabilities_row():
    """Regression for the pre-existing bug the review flagged: register_target
    can return an entry with ad_object=None (host registered as a probe target
    but not resolved in AD). An unguarded `.ad_object.get(...)` raises
    AttributeError, which the per-entry except swallows -- discarding the WHOLE
    capabilities row, including site_type/parent_site_code/root_site_code that
    the low-priv site_hierarchy (Task 1) depends on. A single unresolvable MP
    must not cost the whole hierarchy."""
    entry = _mp_entry("ps1-mp.contoso.com", "PS1", PRIMARY_XML)  # no FSP in this XML
    ctx = _Ctx(
        [entry],
        targets={"ps1-mp.contoso.com": SimpleNamespace(ad_object=None)},  # unresolved
    )

    rows = list(_raw(ldap_management_points_raw)(ctx))

    assert len(rows) == 1
    assert rows[0]["site_type"] == "Primary Site"
    assert rows[0]["parent_site_code"] == "CAS"
    assert rows[0]["root_site_code"] == "CAS"
