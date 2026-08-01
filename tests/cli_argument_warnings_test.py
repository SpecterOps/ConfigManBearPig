import inspect
import logging

from openhound_sccm import main as sccm_main


def test_warns_for_one_dash_dc_typo(caplog):
    caplog.set_level(logging.WARNING, logger=sccm_main.__name__)

    sccm_main._warn_for_suspicious_cli_arguments(
        ["collect", "sccm", "out", "-dc", "10.2.10.100"]
    )

    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert 'Suspicious CLI option "-dc 10.2.10.100"' in message
    assert 'Did you mean "--dc 10.2.10.100"?' in message


def test_does_not_warn_for_valid_dc_option():
    warnings = sccm_main._suspicious_cli_argument_warnings(
        ["collect", "sccm", "out", "--dc", "10.2.10.100"]
    )

    assert warnings == []


def test_does_not_warn_for_valid_domain_forms():
    separated = sccm_main._suspicious_cli_argument_warnings(
        ["collect", "sccm", "out", "-d", "corp.local"]
    )
    attached = sccm_main._suspicious_cli_argument_warnings(
        ["collect", "sccm", "out", "-dcorp.local", "users"]
    )

    assert separated == []
    assert attached == []


def test_warns_for_split_short_value_without_logging_password():
    warnings = sccm_main._suspicious_cli_argument_warnings(
        ["collect", "sccm", "out", "-pMy", "Secret"]
    )

    assert len(warnings) == 1
    assert "Did you mean to quote the --password value" in warnings[0]
    assert "My" not in warnings[0]
    assert "Secret" not in warnings[0]


def test_sms_option_removed():
    from openhound_sccm import source as sccm_source

    assert "sms_provider" not in inspect.signature(sccm_main.collect_sccm).parameters
    assert "sms_provider" not in inspect.signature(sccm_source.source).parameters
