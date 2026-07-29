"""CLI/credential wiring tests for the HTTP client auth inputs."""
import os

from openhound_sccm.context import SourceContext


def test_source_context_carries_kerberos_ticket():
    ctx = SourceContext(ad=None, domain="mayyhem.com", kerberos_ticket="QUJD")
    assert ctx.kerberos_ticket == "QUJD"
    # nt_hash already exists; confirm both credential carriers coexist.
    ctx2 = SourceContext(ad=None, domain="mayyhem.com", nt_hash="aabb")
    assert ctx2.nt_hash == "aabb"
    assert ctx2.kerberos_ticket is None


def test_flags_map_to_env(monkeypatch):
    from openhound_sccm import main as sccm_main

    for var in ("SOURCES__SCCM__NT_HASH", "SOURCES__SCCM__KERBEROS_TICKET"):
        monkeypatch.delenv(var, raising=False)
    sccm_main._apply_env_overrides({"nt_hash": "aabbccdd", "kerberos_ticket": "QUJD"})
    assert os.environ["SOURCES__SCCM__NT_HASH"] == "aabbccdd"
    assert os.environ["SOURCES__SCCM__KERBEROS_TICKET"] == "QUJD"


def test_new_flags_are_redaction_aware():
    from openhound_sccm import main as sccm_main

    # --nt-hash and --ticket carry secrets and must be treated as sensitive.
    assert "--nt-hash" in sccm_main._SENSITIVE_OPTIONS
    assert "--ticket" in sccm_main._SENSITIVE_OPTIONS
    assert "--nt-hash" in sccm_main._LONG_OPTIONS_WITH_VALUES
    assert "--ticket" in sccm_main._LONG_OPTIONS_WITH_VALUES
