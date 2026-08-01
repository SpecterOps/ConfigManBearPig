"""Tests for the collect-sccm ``--help`` panel grouping and the CRED-2 removal.

The options carry a ``rich_help_panel`` so ``--help`` renders titled sections
(Authentication / Collection / Performance / Output / Testing / Logging) instead
of one flat list, and the six inert CRED-2 / machine-account flags were deleted.

Most assertions read the option metadata off ``collect_sccm``'s signature — that
is deterministic and needs no live domain auto-detection. Two end-to-end checks
drive the real ``--help`` render through Typer's ``CliRunner`` (its output stream
is UTF-8, so the cp1252 redirect issue that bites a piped shell ``--help`` does
not apply here).
"""
import inspect

import typer
from typer.models import OptionInfo
from typer.testing import CliRunner

from openhound_sccm.main import _FLAG_TO_ENV, collect_sccm

# Options that once existed on collect_sccm and must stay gone. Listed so that
# re-adding one makes these tests fail loudly, which is the reminder to also file it
# into a panel.
REMOVED_PARAMS = [
    # The six inert CRED-2 / machine-account flags dropped during the --help reorg.
    "machine_name",
    "machine_pass",
    "client_name",
    "create_machine_account",
    "use_altauth",
    "registration_sleep",
    # The BloodHound Upload panel, removed 2026-07-29 with the direct-upload feature.
    # Operators register the shipped schema JSON files and ingest the OpenGraph output
    # through BloodHound's own File Ingest UI instead.
    "bloodhound",
    "bloodhound_url",
    "token_id",
    "token_key",
    "upload_schema_only",
    "upload_results_only",
    "skip_collection",
    "upload_dir",
]

# Every surviving option -> the rich_help_panel it must belong to. Keys are the
# Python parameter names on collect_sccm.
EXPECTED_PANEL = {
    # Authentication — identity + the directory endpoint we bind to.
    "domain": "Authentication",
    "domain_controller": "Authentication",
    "username": "Authentication",
    "password": "Authentication",
    "nt_hash": "Authentication",
    "ticket": "Authentication",
    "ldap_port": "Authentication",
    # Collection — what to collect + how the traffic is routed/resolved.
    "collection_methods": "Collection",
    "computers": "Collection",
    "computer_file": "Collection",
    "site_codes": "Collection",
    "dc_only": "Collection",
    "socks_proxy": "Collection",
    "dns_resolver": "Collection",
    "enable_bad_opsec": "Collection",
    # Performance
    "threads": "Performance",
    # Output — what the run produces / how the graph + console present it.
    "clean": "Output",
    "run_all": "Output",
    "progress": "Output",
    "disable_possible_edges": "Output",
    "show_cleartext_passwords": "Output",
    "tables": "Output",
    "columns": "Output",
    "data_type": "Output",
    # Testing — assert/diff the graph a run just produced; both imply --run-all.
    "run_integration_tests": "Testing",
    "integration_privilege": "Testing",
    "compare_to_zip": "Testing",
    # Logging
    "verbose": "Logging",
    "silent": "Logging",
    "debug": "Logging",
}

# Panel display order in --help follows the order each panel first appears in the
# parameter list, so this is also the intended source ordering.
PANEL_ORDER = ["Authentication", "Collection", "Performance", "Output", "Testing", "Logging"]


def _option_params():
    """Map param name -> OptionInfo for every typer.Option on collect_sccm.

    Positional arguments (output_path) and typer.Argument params (resources) have
    no OptionInfo default, so they fall out here and never carry a panel.
    """
    params = inspect.signature(collect_sccm).parameters
    return {
        name: p.default
        for name, p in params.items()
        if isinstance(p.default, OptionInfo)
    }


# ---------------------------------------------------------------------------
# CRED-2 removal — flags gone from both the signature and the env-var map
# ---------------------------------------------------------------------------

def test_removed_cred2_flags_absent_from_signature():
    params = inspect.signature(collect_sccm).parameters
    for name in REMOVED_PARAMS:
        assert name not in params, f"{name} should have been removed from collect_sccm"


def test_removed_cred2_flags_absent_from_env_map():
    for name in REMOVED_PARAMS:
        assert name not in _FLAG_TO_ENV, f"{name} should be gone from _FLAG_TO_ENV"


# ---------------------------------------------------------------------------
# Panel grouping — every option is assigned, and to the expected panel
# ---------------------------------------------------------------------------

def test_every_option_is_accounted_for():
    # No stray option outside EXPECTED_PANEL, and nothing expected has vanished.
    assert set(_option_params()) == set(EXPECTED_PANEL)


def test_every_option_has_expected_panel():
    for name, opt in _option_params().items():
        assert opt.rich_help_panel == EXPECTED_PANEL[name], (
            f"{name} is in panel {opt.rich_help_panel!r}, expected {EXPECTED_PANEL[name]!r}"
        )


def test_panels_appear_in_intended_order():
    seen = []
    for opt in _option_params().values():
        panel = opt.rich_help_panel
        if panel and panel not in seen:
            seen.append(panel)
    assert seen == PANEL_ORDER


# ---------------------------------------------------------------------------
# End-to-end --help render
# ---------------------------------------------------------------------------

def _help_output():
    app = typer.Typer()
    app.command()(collect_sccm)
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0, result.output
    return result.output


def test_help_renders_all_panels():
    out = _help_output()
    for panel in PANEL_ORDER:
        assert panel in out, f"panel {panel!r} missing from --help"


def test_help_omits_removed_flags():
    out = _help_output()
    for flag in (
        "--machine-name",
        "--machine-pass",
        "--client-name",
        "--create-machine-account",
        "--use-altauth",
        "--registration-sleep",
    ):
        assert flag not in out, f"{flag} should not appear in --help"


# ---------------------------------------------------------------------------
# Encoding guard: option help must survive a redirected --help on Windows
# ---------------------------------------------------------------------------
# rich renders help to the active console encoding. A piped/redirected --help on
# Windows uses cp1252, which cannot encode characters like U+2192 ("->") and
# raises UnicodeEncodeError mid-render. Keep every option's help text encodable
# in cp1252 so `openhound collect sccm --help > file` never crashes there.

def test_option_help_is_cp1252_encodable():
    offenders = []
    for name, opt in _option_params().items():
        help_text = opt.help or ""
        try:
            help_text.encode("cp1252")
        except UnicodeEncodeError as exc:
            offenders.append(f"{name}: {exc}")
    assert not offenders, "non-cp1252 characters in help text: " + "; ".join(offenders)
