#!/usr/bin/env python
"""Live validation of connect_smb / list_shares / check_smb_signing per auth method.

Sibling of debug_wmi_auth.py. Authorized lab target: ps1-sms.mayyhem.com
(MAYYHEM). Exercises the SMB auth ladder added for the SMB collector end to end
against a real host, then enumerates shares and runs the collector's
_classify_shares over the live data.

For each method it: (1) runs the unauthenticated signing-required negotiate,
(2) authenticates with connect_smb, (3) lists shares, and (4) prints the SCCM
classification (roles / site code / flags) the SMB collector would emit.

Methods (note: for SMB an explicit password is NTLM via smb.login -- only a
ticket drives kerberosLogin, so `password` and `pth` share the NTLM path):
  sspi      current Windows user via SSPI Negotiate     (no creds)
  password  explicit -u/-p   -> NTLM login              (impacket)
  pth       -u + NT hash     -> NTLM pass-the-hash       (impacket)
  ptt       pass-the-ticket  -> mints a TGT, kerberosLogin

Usage:
  python dev/debug_smb_auth.py [method ...]      # default: all
  python dev/debug_smb_auth.py --target host --domain d --user u --password p

Credentials come from the environment, never from this file -- it ships in a
public repository. Set either or both before running:
  PowerShell: $env:SCCM_LAB_PASSWORD = "..."; $env:SCCM_LAB_NT_HASH = "..."
  bash:       export SCCM_LAB_PASSWORD="..." SCCM_LAB_NT_HASH="..."
The sspi and ptt methods need neither.
"""
from __future__ import annotations

import argparse
import base64
import logging
import os
import sys

from openhound_sccm.clients.smb import check_smb_signing, list_shares
from openhound_sccm.clients.smb_sso import connect_smb
from openhound_sccm.collectors.smb import _classify_shares

logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(name)s: %(message)s")
log = logging.getLogger("smb_auth")

_LAB_TARGET = "ps1-sms.mayyhem.com"
_LAB_DOMAIN = "mayyhem.com"
_LAB_USER = "MAYYHEM\\domainadmin"
_LAB_KDC = "dc.mayyhem.com"

# Credentials are read from the environment, not hardcoded: this file is published.
# `None` when unset rather than a hard failure, because these stay argparse defaults
# (so --password/--nt-hash still override) and the sspi/ptt methods need no credential
# at all. main() warns when neither source supplied one.
_LAB_PASSWORD = os.environ.get("SCCM_LAB_PASSWORD")
_LAB_NT_HASH = os.environ.get("SCCM_LAB_NT_HASH")

# Share names the SMB collector keys on (for a quick eyeball of the raw enum).
_SCCM_SHARE_HINTS = ("SMS_SITE", "SMS_DP$", "REMINST", "SCCMContentLib$", "SMSPKG")


def _probe(name: str, *, target: str, domain: str, kdc: str, **creds) -> bool:
    print(f"\n===== {name} (target={target}) =====")

    # 1) Unauthenticated signing-required negotiate (auth-method-independent).
    signing = check_smb_signing(target)
    print(f"  check_smb_signing() -> {signing!r}")

    # 2) Authenticate over SMB with this method's credentials.
    smb = connect_smb(
        target, domain,
        creds.get("username"), creds.get("password"),
        nt_hash=creds.get("nt_hash"),
        kerberos_ticket=creds.get("kerberos_ticket"),
        kdc_host=kdc,
    )
    if smb is None:
        print("  FAIL: connect_smb returned None (auth/transport failure)")
        return False

    # 3) Enumerate shares and (4) classify them as the collector would.
    try:
        shares = list_shares(smb)
        print(f"  list_shares() -> {len(shares)} shares")
        sccm = [(n, d) for n, d in shares
                if any(h in n for h in _SCCM_SHARE_HINTS) or "SMS Site" in d]
        for n, d in sccm:
            print(f"      {n}  ({d})")
        cls = _classify_shares(shares)
        print(f"  classification: is_sccm={cls.is_sccm} site_code={cls.site_code!r} "
              f"roles={cls.roles()} pxe={cls.is_pxe_enabled} "
              f"content_lib={cls.hosts_content_library}")
        print(f"  collection_source={cls.collection_source}")
        return True
    except Exception as ex:  # noqa: BLE001 - live diagnostic
        log.exception("  ERROR during share enumeration for %s: %s", name, ex)
        return False
    finally:
        try:
            smb.logoff()
        except Exception:  # noqa: BLE001
            pass


def _mint_kirbi(user: str, password: str, domain: str, kdc: str, nthash: str = "") -> str | None:
    """Mint a base64 KRB-CRED (.kirbi) TGT for pass-the-ticket testing.

    Copied from debug_wmi_auth.py so PtT can be exercised without a pre-staged
    ticket on disk.
    """
    try:
        from impacket.krb5 import constants
        from impacket.krb5.ccache import CCache
        from impacket.krb5.kerberosv5 import getKerberosTGT
        from impacket.krb5.types import Principal
    except ImportError as ex:
        log.warning("cannot mint ticket: %s", ex)
        return None
    sam = user.split("\\", 1)[1] if "\\" in user else user
    principal = Principal(sam, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    tgt, _cipher, okey, skey = getKerberosTGT(principal, password, domain.upper(), "", nthash, "", kdc)
    ccache = CCache()
    ccache.fromTGT(tgt, okey, skey)
    to_kirbi = getattr(ccache, "toKRBCRED", None)
    if to_kirbi is None:
        log.warning("this impacket build has no CCache.toKRBCRED(); skipping live PtT")
        return None
    return base64.b64encode(to_kirbi()).decode()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("methods", nargs="*", default=None,
                    help="subset of: sspi password pth ptt (default: all)")
    ap.add_argument("--target", default=_LAB_TARGET)
    ap.add_argument("--domain", default=_LAB_DOMAIN)
    ap.add_argument("--user", default=_LAB_USER)
    ap.add_argument("--password", default=_LAB_PASSWORD,
                    help="default: $SCCM_LAB_PASSWORD")
    ap.add_argument("--nt-hash", default=_LAB_NT_HASH,
                    help="default: $SCCM_LAB_NT_HASH")
    ap.add_argument("--kdc", default=_LAB_KDC)
    args = ap.parse_args()

    chosen = args.methods or ["sspi", "password", "pth", "ptt"]
    # Warn rather than exit: sspi and ptt need no credential, so a credential-less run
    # is legitimate. Naming both sources here saves guessing why password/pth failed.
    if not args.password and not args.nt_hash:
        log.warning("No credential from $SCCM_LAB_PASSWORD/$SCCM_LAB_NT_HASH or "
                    "--password/--nt-hash; the password and pth methods will fail.")
    else:
        log.debug("Credential supplied (password=%s, nt_hash=%s)",
                  bool(args.password), bool(args.nt_hash))
    base = dict(target=args.target, domain=args.domain, kdc=args.kdc)
    results: dict[str, bool] = {}

    if "sspi" in chosen:
        results["sspi"] = _probe("sspi (current Windows user)", **base)
    if "password" in chosen:
        results["password"] = _probe("password (NTLM login)", **base,
                                     username=args.user, password=args.password)
    if "pth" in chosen:
        results["pth"] = _probe("pass-the-hash (NTLM)", **base,
                                username=args.user, nt_hash=args.nt_hash)
    if "ptt" in chosen:
        kirbi = _mint_kirbi(args.user, args.password, args.domain, args.kdc)
        if kirbi:
            results["ptt"] = _probe("pass-the-ticket (kerberosLogin)", **base, kerberos_ticket=kirbi)
        else:
            print("\n===== ptt ===== SKIPPED (could not mint a .kirbi in this impacket build)")

    print("\n===== summary =====")
    for m, ok in results.items():
        print(f"  {m:10} {'OK' if ok else 'FAIL'}")
    return 0 if results and all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
