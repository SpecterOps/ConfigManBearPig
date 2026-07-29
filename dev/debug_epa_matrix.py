#!/usr/bin/env python
"""Live EPA-detection validation matrix for SQL Server.

Port of MSSQLHound's ``test-epa-matrix`` (cmd_test_epa_matrix.go +
internal/epamatrix/*). For each of the 12 combinations of ForceEncryption,
ForceStrictEncryption, and ExtendedProtection it:

  1. writes the three ``SuperSocketNetLib`` registry DWORDs (impacket ``rrp``),
  2. restarts the SQL Server service (impacket ``scmr``),
  3. waits for the SQL TCP port to come back,
  4. runs ``mssql_epa.test_epa`` once per enabled authentication method
     (SSPI / user+password / NT-hash) and compares the detected EPA enforcement
     to the value implied by ExtendedProtection (0=Off, 1=Allowed, 2=Required).

Original registry values are restored on normal exit and on Ctrl+C.

Registry + service management authenticates over SMB as the current Windows user
(SSPI) unless ``--smb-user``/``--smb-pass`` are given.

WARNING: this modifies registry settings and restarts the SQL Server service on
the target repeatedly. Intended for a lab SQL Server you control. The lab
defaults at the bottom of this file (``_LAB_*`` constants) are baked in for
zero-flag convenience; override any of them with the corresponding CLI flag.

Example (zero flags - uses baked-in lab defaults, runs all three sections):
    python debug_epa_matrix.py

Example (override target while keeping the other lab defaults):
    python debug_epa_matrix.py --target other-db.mayyhem.com
"""
from __future__ import annotations

import argparse
import logging
import os
import socket
import sys
import time
from dataclasses import dataclass
from typing import Optional

from impacket.dcerpc.v5 import rrp, scmr, transport

from openhound_sccm.clients.mssql_epa import EPAPrereqError, test_epa
from openhound_sccm.clients.smb_sso import connect_smb

logger = logging.getLogger("epa_matrix")

_SQL_ROOT = r"SOFTWARE\Microsoft\Microsoft SQL Server"
_INSTANCE_NAMES_KEY = _SQL_ROOT + r"\Instance Names\SQL"


@dataclass
class InstanceInfo:
    """Auto-detected SQL Server instance details."""

    registry_path: str  # full SuperSocketNetLib key path under HKLM
    service_name: str   # SCM service name (e.g. MSSQLSERVER or MSSQL$INST)


@dataclass
class Settings:
    """The three SQL Server EPA-related registry DWORDs."""

    force_encryption: int
    force_strict_encryption: int
    extended_protection: int


def _ep_label(value: int) -> str:
    return {0: "Off", 1: "Allowed", 2: "Required"}.get(value, f"Unknown({value})")


def _yes_no(value: int) -> str:
    return "Yes" if value == 1 else "No"


# --- remote registry (rrp) --------------------------------------------------


class _Registry:
    """Remote registry helper bound to HKLM over an existing SMB connection.

    RemoteRegistry is trigger-started on modern Windows: the first ``\\winreg``
    pipe open wakes the service but races its listener, so the first bind often
    returns STATUS_PIPE_NOT_AVAILABLE. Retry briefly (mirrors registry.py).
    """

    _BIND_RETRIES = 4
    _BIND_RETRY_DELAY = 1.5

    def __init__(self, smb) -> None:
        from impacket.smbconnection import SessionError

        last_exc: Optional[Exception] = None
        for attempt in range(1, self._BIND_RETRIES + 1):
            try:
                rpc = transport.SMBTransport(
                    smb.getRemoteHost(), filename=r"\winreg", smb_connection=smb
                )
                rpc.connect()
                self.dce = rpc.get_dce_rpc()
                self.dce.connect()
                self.dce.bind(rrp.MSRPC_UUID_RRP)
                self.hklm = rrp.hOpenLocalMachine(self.dce)["phKey"]
                return
            except SessionError as ex:
                last_exc = ex
                if "STATUS_PIPE_NOT_AVAILABLE" in str(ex) and attempt < self._BIND_RETRIES:
                    logger.info(
                        "winreg pipe not listening yet (attempt %d/%d); RemoteRegistry "
                        "still starting, retrying in %.1fs",
                        attempt, self._BIND_RETRIES, self._BIND_RETRY_DELAY,
                    )
                    time.sleep(self._BIND_RETRY_DELAY)
                    continue
                raise
        raise last_exc  # type: ignore[misc]

    def read_string(self, key_path: str, value_name: str) -> Optional[str]:
        sub = rrp.hBaseRegOpenKey(self.dce, self.hklm, key_path)["phkResult"]
        try:
            _, value = rrp.hBaseRegQueryValue(self.dce, sub, value_name)
            if isinstance(value, bytes):
                value = value.decode("utf-16-le", errors="replace")
            return str(value).rstrip("\x00").strip()
        finally:
            rrp.hBaseRegCloseKey(self.dce, sub)

    def read_dword(self, key_path: str, value_name: str, default: int = 0) -> int:
        sub = rrp.hBaseRegOpenKey(self.dce, self.hklm, key_path)["phkResult"]
        try:
            _, value = rrp.hBaseRegQueryValue(self.dce, sub, value_name)
            if isinstance(value, int):
                return value
            if isinstance(value, bytes) and len(value) >= 4:
                import struct

                return struct.unpack("<I", value[:4])[0]
            return int(value) if value else default
        except rrp.DCERPCException as ex:
            if "ERROR_FILE_NOT_FOUND" in str(ex):
                return default
            raise
        finally:
            rrp.hBaseRegCloseKey(self.dce, sub)

    def write_dword(self, key_path: str, value_name: str, value: int) -> None:
        sub = rrp.hBaseRegOpenKey(self.dce, self.hklm, key_path)["phkResult"]
        try:
            rrp.hBaseRegSetValue(self.dce, sub, value_name + "\x00", rrp.REG_DWORD, value)
        finally:
            rrp.hBaseRegCloseKey(self.dce, sub)

    def close(self) -> None:
        try:
            self.dce.disconnect()
        except Exception:  # noqa: BLE001
            pass


def detect_instance(reg: _Registry, instance_name: str) -> InstanceInfo:
    """Resolve the SuperSocketNetLib key path and SCM service name for an instance."""
    root = reg.read_string(_INSTANCE_NAMES_KEY, instance_name)
    if not root:
        raise RuntimeError(f"SQL instance {instance_name!r} not found under {_INSTANCE_NAMES_KEY}")
    registry_path = rf"{_SQL_ROOT}\{root}\MSSQLServer\SuperSocketNetLib"
    service_name = "MSSQLSERVER" if instance_name == "MSSQLSERVER" else f"MSSQL${instance_name}"
    logger.info("Instance %s -> root=%s service=%s", instance_name, root, service_name)
    return InstanceInfo(registry_path=registry_path, service_name=service_name)


def read_settings(reg: _Registry, registry_path: str) -> Settings:
    return Settings(
        force_encryption=reg.read_dword(registry_path, "ForceEncryption"),
        force_strict_encryption=reg.read_dword(registry_path, "ForceStrictEncryption"),
        extended_protection=reg.read_dword(registry_path, "ExtendedProtection"),
    )


def write_settings(reg: _Registry, registry_path: str, settings: Settings) -> None:
    reg.write_dword(registry_path, "ForceEncryption", settings.force_encryption)
    reg.write_dword(registry_path, "ForceStrictEncryption", settings.force_strict_encryption)
    reg.write_dword(registry_path, "ExtendedProtection", settings.extended_protection)


# --- service control (scmr) -------------------------------------------------


def restart_service(smb, service_name: str, wait_seconds: int) -> None:
    """Stop (with dependents) then start a service, waiting for RUNNING."""
    rpc = transport.SMBTransport(smb.getRemoteHost(), filename=r"\svcctl", smb_connection=smb)
    rpc.connect()
    dce = rpc.get_dce_rpc()
    dce.connect()
    dce.bind(scmr.MSRPC_UUID_SCMR)
    try:
        scm = scmr.hROpenSCManagerW(dce)["lpScHandle"]
        _stop_service(dce, scm, service_name, wait_seconds)
        _start_service(dce, scm, service_name, wait_seconds)
    finally:
        try:
            dce.disconnect()
        except Exception:  # noqa: BLE001
            pass


def _svc_status(dce, handle) -> int:
    return scmr.hRQueryServiceStatus(dce, handle)["lpServiceStatus"]["dwCurrentState"]


def _stop_service(dce, scm, service_name: str, wait_seconds: int) -> None:
    handle = scmr.hROpenServiceW(dce, scm, service_name + "\x00")["lpServiceHandle"]
    try:
        if _svc_status(dce, handle) == scmr.SERVICE_STOPPED:
            return
        try:
            scmr.hRControlService(dce, handle, scmr.SERVICE_CONTROL_STOP)
        except Exception as ex:  # noqa: BLE001 - dependents must stop first
            if "ERROR_DEPENDENT_SERVICES_RUNNING" not in str(ex):
                raise
            logger.info("Stopping dependent services of %s first", service_name)
            for dep in scmr.hREnumDependentServicesW(dce, handle, scmr.SERVICE_STATE_ALL)["lpServices"]:
                _stop_service(dce, scm, dep["lpServiceName"][:-1], wait_seconds)
            scmr.hRControlService(dce, handle, scmr.SERVICE_CONTROL_STOP)
        _wait_state(dce, handle, scmr.SERVICE_STOPPED, wait_seconds, service_name, "stop")
    finally:
        scmr.hRCloseServiceHandle(dce, handle)


def _start_service(dce, scm, service_name: str, wait_seconds: int) -> None:
    handle = scmr.hROpenServiceW(dce, scm, service_name + "\x00")["lpServiceHandle"]
    try:
        scmr.hRStartServiceW(dce, handle)
        _wait_state(dce, handle, scmr.SERVICE_RUNNING, wait_seconds, service_name, "start")
    finally:
        scmr.hRCloseServiceHandle(dce, handle)


def _wait_state(dce, handle, target_state: int, wait_seconds: int, name: str, verb: str) -> None:
    deadline = wait_seconds
    while deadline > 0:
        if _svc_status(dce, handle) == target_state:
            return
        time.sleep(2)
        deadline -= 2
    raise RuntimeError(f"Service {name} did not {verb} within {wait_seconds}s")


def wait_for_port(host: str, port: int, extra_delay: int, attempts: int = 12) -> None:
    for _ in range(attempts):
        try:
            with socket.create_connection((host, port), timeout=5):
                if extra_delay > 0:
                    time.sleep(extra_delay)
                return
        except OSError:
            time.sleep(5)
    raise RuntimeError(f"SQL port {host}:{port} not reachable after restart")


# --- matrix -----------------------------------------------------------------


def all_combinations(skip_strict: bool) -> list[Settings]:
    combos = []
    for fe in (0, 1):
        for fse in (0, 1):
            if skip_strict and fse == 1:
                continue
            for ep in (0, 1, 2):
                combos.append(Settings(fe, fse, ep))
    return combos


@dataclass
class Result:
    index: int
    settings: Settings
    detected: Optional[str]
    verdict: str


@dataclass
class AuthSpec:
    """One authentication method to exercise against each combo.

    ``test_epa_kwargs`` is what gets splatted into ``test_epa`` — empty for
    SSPI (the auth-ladder falls through to current-user integrated auth) or
    a ``username``/``password``/``nt_hash`` triple for explicit / PtH paths.
    """

    name: str
    test_epa_kwargs: dict


def _sspi_supported() -> bool:
    """True only on Windows with pywin32 SSPI importable.

    Local mirror of ``mssql_epa._sspi_available`` so the matrix harness stays
    self-contained and doesn't reach into another module's private helper.
    """
    if sys.platform != "win32":
        return False
    try:
        import sspi  # noqa: F401
        import sspicon  # noqa: F401
        import win32security  # noqa: F401
        return True
    except ImportError:
        return False


def _build_auth_specs(args) -> list[AuthSpec]:
    """Return one AuthSpec per auth method to run.

    Selection rules:

    * ``--integrated-auth-only`` -> SSPI only (any creds are ignored).
    * Explicit ``--password`` or ``--nt-hash`` on the command line -> only the
      section(s) for the explicitly-given secret(s); SSPI is skipped so the
      matrix exercises *exactly* what the operator asked for.
    * Otherwise (no auth-selecting flags given) -> all three sections, with
      the baked-in lab defaults supplying the secrets.

    ``args.password`` and ``args.nt_hash`` come in as ``None`` when the
    operator didn't pass the flag; we resolve the "use lab defaults" branch
    here so the distinction between explicit-on-CLI and unset isn't lost.
    """
    specs: list[AuthSpec] = []

    if args.integrated_auth_only:
        if not _sspi_supported():
            raise RuntimeError("--integrated-auth-only requires Windows + pywin32 (SSPI)")
        specs.append(AuthSpec(
            name="Windows integrated auth (SSPI)",
            test_epa_kwargs={},
        ))
        return specs

    explicit_password = args.password is not None
    explicit_nt_hash = args.nt_hash is not None
    use_lab_defaults = not explicit_password and not explicit_nt_hash

    if use_lab_defaults:
        # No --password / --nt-hash on the CLI -> include SSPI and fill in
        # both explicit-auth secrets from the lab defaults.
        if _sspi_supported():
            specs.append(AuthSpec(
                name="Windows integrated auth (SSPI)",
                test_epa_kwargs={},
            ))
        else:
            logger.warning("SSPI not available on this platform; skipping SSPI section")
        password = _LAB_PASSWORD
        nt_hash = _LAB_NT_HASH
        # Warn rather than exit: the SSPI section above needs no credential, so a
        # credential-less run is still useful. Naming both sources saves guessing
        # why the explicit-auth sections failed.
        if not password and not nt_hash:
            logger.warning("No credential from $SCCM_LAB_PASSWORD/$SCCM_LAB_NT_HASH or "
                           "--password/--nt-hash; only the SSPI section will run.")
        else:
            logger.debug("Lab credential supplied (password=%s, nt_hash=%s)",
                         bool(password), bool(nt_hash))
    else:
        # An explicit credential flag restricts the run to just that auth
        # method; SSPI and the *other* explicit method are skipped unless
        # both --password and --nt-hash are given explicitly.
        password = args.password
        nt_hash = args.nt_hash

    if args.user and password:
        specs.append(AuthSpec(
            name="Explicit credentials (username + password)",
            test_epa_kwargs={
                "domain": args.domain or "",
                "username": args.user,
                "password": password,
            },
        ))
    elif explicit_password and not args.user:
        logger.warning("--password ignored: requires --user")

    if args.user and nt_hash:
        specs.append(AuthSpec(
            name="Pass-the-hash (NT hash)",
            test_epa_kwargs={
                "domain": args.domain or "",
                "username": args.user,
                "nt_hash": nt_hash,
            },
        ))
    elif explicit_nt_hash and not args.user:
        logger.warning("--nt-hash ignored: requires --user")

    return specs


def run_matrix(args, smb) -> dict[str, list[Result]]:
    """Apply each registry combo once, then probe with every configured auth method.

    Returns a mapping ``{auth_spec.name: [Result, ...]}`` so the printer can
    emit one table per auth method.
    """
    auth_specs = _build_auth_specs(args)
    if not auth_specs:
        raise RuntimeError(
            "No authentication method available: enable SSPI (Windows + pywin32) "
            "or pass --user with --password and/or --nt-hash"
        )
    logger.info(
        "Running matrix with %d auth method(s): %s",
        len(auth_specs), ", ".join(spec.name for spec in auth_specs),
    )

    reg = _Registry(smb)
    try:
        instance = detect_instance(reg, args.sql_instance)
        original = read_settings(reg, instance.registry_path)
        logger.info(
            "Original settings: FE=%s FSE=%s EP=%s",
            _yes_no(original.force_encryption),
            _yes_no(original.force_strict_encryption),
            _ep_label(original.extended_protection),
        )

        combos = all_combinations(args.skip_strict)
        results_by_auth: dict[str, list[Result]] = {spec.name: [] for spec in auth_specs}
        try:
            for i, combo in enumerate(combos, start=1):
                logger.info(
                    "[%d/%d] Configuring SQL Server: FE=%s FSE=%s EP=%s",
                    i, len(combos),
                    _yes_no(combo.force_encryption),
                    _yes_no(combo.force_strict_encryption),
                    _ep_label(combo.extended_protection),
                )
                # Write + restart once per combo; all auth methods then probe
                # the same server state back-to-back. If the setup fails, mark
                # every auth section's row for this combo as errored so all
                # tables stay aligned by index.
                try:
                    write_settings(reg, instance.registry_path, combo)
                    restart_service(smb, instance.service_name, args.restart_wait)
                    wait_for_port(args.target, args.port, args.post_restart_delay)
                except Exception as ex:  # noqa: BLE001
                    logger.error("Combo %d setup failed: %s", i, ex)
                    for spec in auth_specs:
                        results_by_auth[spec.name].append(
                            Result(i, combo, None, f"Error: setup - {ex}")
                        )
                    continue

                for spec in auth_specs:
                    logger.info("  Probing with %s", spec.name)
                    results_by_auth[spec.name].append(_run_probe(args, combo, i, spec))
        finally:
            logger.info("Restoring original settings and restarting service")
            try:
                write_settings(reg, instance.registry_path, original)
                restart_service(smb, instance.service_name, args.restart_wait)
            except Exception as ex:  # noqa: BLE001
                logger.error("Failed to restore original settings: %s", ex)
        return results_by_auth
    finally:
        reg.close()


def _run_probe(args, combo: Settings, index: int, spec: AuthSpec) -> Result:
    """Run one EPA detection against the already-configured server.

    Assumes the registry has been written and the service restarted by the
    caller. Only does the probe + verdict classification.
    """
    expected = _ep_label(combo.extended_protection)
    try:
        result = test_epa(
            target=args.target,
            port=args.port,
            **spec.test_epa_kwargs,
        )
        detected = result.extended_protection if result else None
    except EPAPrereqError as ex:
        logger.error("  prereq failed: %s", ex)
        return Result(index, combo, None, f"Error: prereq - {ex}")
    except Exception as ex:  # noqa: BLE001
        logger.error("  error: %s", ex)
        return Result(index, combo, None, f"Error: {ex}")

    # Explicit-credential and NT-hash paths distinguish Allowed vs Required
    # precisely (impacket can genuinely omit the AV pairs). SSPI cannot, so
    # it returns the literal "Allowed/Required" — which counts as correct
    # whenever the actual setting is either Allowed or Required.
    if detected == expected:
        verdict = "Correct"
    elif detected == "Allowed/Required" and expected in ("Allowed", "Required"):
        verdict = "Correct (uncertainty preserved)"
    else:
        verdict = f"Incorrect (detected {detected}, expected {expected})"
    logger.info("  detected=%s expected=%s -> %s", detected, expected, verdict)
    return Result(index, combo, detected, verdict)


def print_table(results: list[Result]) -> None:
    # Detected column is 18 wide so the literal "Allowed/Required" (16 chars)
    # fits without bleeding into the verdict column.
    header = f"{'#':>2}  {'ForceEnc':<9}{'Strict':<8}{'ExtProt':<10}{'Detected':<18}{'Verdict'}"
    print(header)
    print("-" * len(header))
    for r in results:
        print(
            f"{r.index:>2}  "
            f"{_yes_no(r.settings.force_encryption):<9}"
            f"{_yes_no(r.settings.force_strict_encryption):<8}"
            f"{_ep_label(r.settings.extended_protection):<10}"
            f"{(r.detected or 'N/A'):<18}"
            f"{r.verdict}"
        )
    correct = sum(1 for r in results if r.verdict.startswith("Correct"))
    errors = sum(1 for r in results if r.verdict.startswith("Error"))
    incorrect = len(results) - correct - errors
    print(f"\nSummary: {correct} correct, {incorrect} incorrect, {errors} errors out of {len(results)}")


def print_tables(results_by_auth: dict[str, list[Result]]) -> None:
    """Print one table per auth method, with a section banner above each."""
    for auth_name, results in results_by_auth.items():
        banner = f"=== {auth_name} ==="
        print(f"\n{banner}\n")
        print_table(results)


#: Lab defaults — this script is a lab-only debug harness, so the target and
#: account name are baked in for zero-flag convenience. Override any of them
#: with the corresponding CLI flag.
_LAB_TARGET = "ps1-db.mayyhem.com"
_LAB_DOMAIN = "MAYYHEM"
_LAB_USER = "domainadmin"

#: Credentials are read from the environment, never hardcoded: this file is
#: published. `None` when unset rather than a hard failure, because the SSPI
#: section needs no credential at all — main() warns when neither the
#: environment nor a CLI flag supplied one.
_LAB_NT_HASH = os.environ.get("SCCM_LAB_NT_HASH")
_LAB_PASSWORD = os.environ.get("SCCM_LAB_PASSWORD")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Live EPA detection validation matrix. With no auth flags, runs "
            "all three sections (SSPI + user/pass + NT-hash) using baked-in "
            "lab defaults. Passing --password or --nt-hash restricts the run "
            "to that auth method only. --integrated-auth-only runs SSPI only."
        ),
    )
    parser.add_argument("--target", default=_LAB_TARGET, help="SQL Server hostname/FQDN")
    parser.add_argument("--port", type=int, default=1433)
    parser.add_argument("--domain", default=_LAB_DOMAIN, help="Domain for EPA detection auth")
    parser.add_argument("--user", default=_LAB_USER, help="Username for EPA detection (explicit auth)")
    # --password and --nt-hash default to None so we can tell whether the
    # operator gave a value explicitly (-> restrict to that section) versus
    # left it unset (-> fall back to the lab default and run all three).
    parser.add_argument("--password", default=None, help="Password for EPA detection (restricts run to user/pass section)")
    parser.add_argument("--nt-hash", default=None, help="NT hash for EPA detection (restricts run to pass-the-hash section)")
    parser.add_argument(
        "--integrated-auth-only", action="store_true",
        help="Run only the SSPI (Windows integrated auth) section, ignoring any credentials.",
    )
    parser.add_argument("--smb-user", default=None, help="SMB management username (default: current user via SSPI)")
    parser.add_argument("--smb-pass", default=None, help="SMB management password")
    parser.add_argument("--sql-instance", default="MSSQLSERVER")
    parser.add_argument("--skip-strict", action="store_true", help="Skip ForceStrictEncryption=1 combos")
    parser.add_argument("--restart-wait", type=int, default=60)
    parser.add_argument("--post-restart-delay", type=int, default=5)
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Reduce log verbosity to INFO (default: DEBUG).",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO if args.quiet else logging.DEBUG,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    logger.info("Connecting to %s for registry/service management", args.target)
    smb = connect_smb(args.target, args.domain, args.smb_user, args.smb_pass)
    if smb is None:
        logger.error("SMB management connection failed")
        return 1

    try:
        results_by_auth = run_matrix(args, smb)
    finally:
        try:
            smb.logoff()
        except Exception:  # noqa: BLE001
            pass

    print_tables(results_by_auth)
    all_correct = bool(results_by_auth) and all(
        r.verdict.startswith("Correct")
        for results in results_by_auth.values()
        for r in results
    )
    return 0 if all_correct else 1


if __name__ == "__main__":
    sys.exit(main())
