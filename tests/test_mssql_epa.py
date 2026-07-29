"""Unit tests for SCCM's EPA adapter (clients/mssql_epa.py).

The EPA probe matrix + Off/Allowed/Required decision tree now live in the shared
library (``openhound_collector_common.clients.mssql.detect_epa``) and are validated
end-to-end by ``debug_epa_matrix.py`` against a live SQL Server across all 12 EPA
configurations. These tests cover the SCCM-facing *adapter*: MSSQLSvc SPN
selection, the explicit/SSPI/skip credential ladder, and the verdict->EPAResult
mapping (with ``detect_epa`` mocked so no network is needed).
"""
from openhound_sccm.clients import mssql_epa
# NB: call test_epa via the module (mssql_epa.test_epa) rather than importing it —
# a bare `test_epa` in this namespace would be collected by pytest as a test.
from openhound_sccm.clients.mssql_epa import EPAResult, _select_mssql_spn


# --- MSSQLSvc SPN selection ------------------------------------------------

def test_select_mssql_spn_prefers_registered():
    spns = ["HOST/ps1-db", "TERMSRV/ps1-db", "MSSQLSvc/ps1-db.mayyhem.com:1433"]
    assert _select_mssql_spn(spns, "ps1-db.mayyhem.com", 1433) == "MSSQLSvc/ps1-db.mayyhem.com:1433"


def test_select_mssql_spn_match_is_case_insensitive():
    spns = ["mssqlsvc/PS1-DB.mayyhem.com"]
    assert _select_mssql_spn(spns, "ps1-db.mayyhem.com", 1433) == "mssqlsvc/PS1-DB.mayyhem.com"


def test_select_mssql_spn_derives_when_absent():
    assert _select_mssql_spn([], "ps1-db.mayyhem.com", 1433) == "MSSQLSvc/ps1-db.mayyhem.com:1433"


def test_select_mssql_spn_derives_when_none():
    assert _select_mssql_spn(None, "ps1-db.mayyhem.com", 1433) == "MSSQLSvc/ps1-db.mayyhem.com:1433"


# --- test_epa adapter: credential ladder + verdict mapping ------------------

_VERDICT = {"forceEncryption": True, "extendedProtection": "Required",
            "strictEncryption": False, "encryptionFlag": 1, "unmodifiedSuccess": True}


def test_test_epa_explicit_creds_builds_explicit_auth_and_maps(monkeypatch):
    """Explicit username+password -> explicit Auth (no SSPI) -> mapped EPAResult."""
    captured = {}

    def fake_detect(target, auth, **kw):
        captured["target"] = target
        captured["auth"] = auth
        return _VERDICT

    monkeypatch.setattr(mssql_epa, "detect_epa", fake_detect)
    result = mssql_epa.test_epa(target="ps1-db.mayyhem.com", port=1433, domain="mayyhem.com",
                      username="MAYYHEM\\domainadmin", password="pw",
                      spns=["MSSQLSvc/ps1-db.mayyhem.com:1433"])
    assert isinstance(result, EPAResult)
    assert result.extended_protection == "Required"
    assert result.force_encryption is True and result.strict_encryption is False
    # DOMAIN\user was split; the pinned SPN passed through; SSPI not used; host:port target.
    auth = captured["auth"]
    assert auth.username == "domainadmin" and auth.domain == "MAYYHEM"
    assert auth.use_sspi is False and auth.spn == "MSSQLSvc/ps1-db.mayyhem.com:1433"
    assert captured["target"] == "ps1-db.mayyhem.com:1433"


def test_test_epa_falls_back_to_sspi_when_no_creds(monkeypatch):
    """No creds + SSPI available -> current-user SSPI Auth."""
    captured = {}
    monkeypatch.setattr(mssql_epa, "_sspi_available", lambda: True)
    monkeypatch.setattr(mssql_epa, "detect_epa",
                        lambda t, a, **k: (captured.update(auth=a) or _VERDICT))
    result = mssql_epa.test_epa(target="ps1-db.mayyhem.com", domain="mayyhem.com")
    assert result.extended_protection == "Required"
    assert captured["auth"].use_sspi is True


def test_test_epa_skips_when_no_creds_and_no_sspi(monkeypatch):
    """No creds + no SSPI -> None (skip); detect_epa is never called."""
    called = []
    monkeypatch.setattr(mssql_epa, "_sspi_available", lambda: False)
    monkeypatch.setattr(mssql_epa, "detect_epa", lambda *a, **k: called.append(1))
    assert mssql_epa.test_epa(target="ps1-db.mayyhem.com", domain="mayyhem.com") is None
    assert called == []


def test_test_epa_surfaces_allowed_required_verbatim(monkeypatch):
    """The SSPI 'Allowed/Required' uncertainty label is passed through verbatim."""
    monkeypatch.setattr(
        mssql_epa, "detect_epa",
        lambda t, a, **k: {"forceEncryption": False, "strictEncryption": False,
                           "extendedProtection": "Allowed/Required"},
    )
    result = mssql_epa.test_epa(target="x", username="u", password="p", domain="d")
    assert result.extended_protection == "Allowed/Required"


def test_test_epa_warns_and_skips_when_only_ticket(monkeypatch, caplog):
    """Ticket only (no explicit creds, no SSPI) -> WARNING + None; detect_epa never called."""
    import logging
    called = []
    monkeypatch.setattr(mssql_epa, "_sspi_available", lambda: False)
    monkeypatch.setattr(mssql_epa, "detect_epa", lambda *a, **k: called.append(1))
    with caplog.at_level(logging.WARNING):
        result = mssql_epa.test_epa(target="ps1-db.mayyhem.com", domain="mayyhem.com",
                                    kerberos_ticket="Zm9vYmFy")
    assert result is None
    assert called == []
    assert "pass-the-ticket" in caplog.text.lower()
    assert "--nt-hash" in caplog.text


def test_test_epa_prefers_sspi_over_ticket_only(monkeypatch):
    """Ticket + SSPI available -> SSPI is used (EPA is server-side; SSPI still detects it)."""
    captured = {}
    monkeypatch.setattr(mssql_epa, "_sspi_available", lambda: True)
    monkeypatch.setattr(mssql_epa, "detect_epa",
                        lambda t, a, **k: (captured.update(auth=a) or _VERDICT))
    result = mssql_epa.test_epa(target="x", domain="d", kerberos_ticket="Zm9vYmFy")
    assert result.extended_protection == "Required"
    assert captured["auth"].use_sspi is True
