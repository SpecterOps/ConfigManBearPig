"""
SCCM version fingerprinting for ConfigManBearPig.

Issues an unauthenticated HTTP Range request against a management point's
/CCM_CLIENT/ccmsetup.exe and extracts the embedded client version string.
The detected version is mapped to a build stack so the set of missing
hotfixes — and therefore the set of unpatched CVEs — can be reported.
"""

# Version fingerprinting logic (BUILD_MAP, CVE_MAP, version detection, and
# hotfix-stack / CVE matching) originally authored by Mehdi Elyassa (Synacktiv)
# in SCCMVersionGuesser.py:
#   https://github.com/synacktiv/SCCMVersionGuesser/blob/main/SCCMVersionGuesser.py

import logging
import re
from typing import Optional

import requests
import urllib3

logger = logging.getLogger("ConfigManBearPig")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Mapping CVE -> List of KBs that fix it
CVE_MAP = {
    "CVE-2025-59501 (Auth Bypass)": ["KB35360093", "KB32851084"],  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2025-59501
    "CVE-2025-59213 (Unauth SQLi)": ["KB34503790", "KB34503768"],  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59213
    "CVE-2025-55320 (Auth SQLi)": ["KB34503790", "KB34503768"],    # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-55320
    "CVE-2025-47178 (Auth SQLi)": ["KB31909343", "KB33926600", "KB32480179"],  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2025-47178
    "CVE-2024-43468 (Unauth SQLi)": ["KB29166583"],  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2024-43468
}

# Structure: "BuildNumber": { "BaseName": "...", "Stack": [ (ClientVer, KB, Name, FullVersionNumber), ... ] }
# Sorted by release order (ascending) within each build
# Source: https://github.com/MicrosoftDocs/memdocs/tree/main/intune/configmgr/hotfix
BUILD_MAP = {
    "9141": {
        "BaseName": "SCCM 2509",
        "Stack": [
            ("5.00.9141.1000", "Base", "SCCM 2509 Release", "5.00.9141.1000"),
            ("5.00.9141.1015", "KB36495448", "Update", "5.00.9141.1015"),
            ("5.00.9141.1015", "KB36419072", "Update", "5.00.9141.1017"),
        ],
    },
    "9135": {
        "BaseName": "SCCM 2503",
        "Stack": [
            ("5.00.9135.1001", "Base", "SCCM 2503 Release", "5.00.9135.1000"),
            ("5.00.9135.1001", "KB31909343", "Hotfix for 2503", "5.00.9135.1001"),
            ("5.00.9135.1001", "KB32480179", "Hotfix for 2503", "5.00.9135.1003"),
            ("5.00.9135.1006", "KB33177653", "Update for 2503", "5.00.9135.1006"),
            ("5.00.9135.1006", "KB34503790", "Hotfix for 2503", "5.00.9135.1008"),
            ("5.00.9135.1013", "KB32851084", "Hotfix for 2503", "5.00.9135.1013"),
            ("5.00.9135.1013", "KB35958849", "Hotfix for 2503", "5.00.9135.1014"),
            ("5.00.9135.1017", "KB36495448", "Hotfix for 2503", "5.00.9135.1017"),
            ("5.00.9132.1017", "KB36419072", "Hotfix for 2503", "5.00.9135.1019"),
        ],
    },
    "9132": {
        "BaseName": "SCCM 2409",
        "Stack": [
            ("5.00.9132.1011", "Base", "SCCM 2409 Release", "5.00.9132.1000"),
            ("5.00.9132.1013", "KB30833053", "Hotfix KB30833053", "5.00.9132.1013"),
            ("5.00.9132.1023", "KB30385346", "Hotfix Rollup KB30385346", "5.00.9132.1023"),
            ("5.00.9132.1027", "KB33177653", "Hotfix Rollup KB33177653", "5.00.9132.1027"),
            ("5.00.9132.1027", "KB33926600", "Hotfix Rollup KB33926600", "5.00.9132.1028"),
            ("5.00.9132.1027", "KB34503768", "Hotfix Rollup KB34503768", "5.00.9132.1029"),
            ("5.00.9132.1027", "KB35360093", "Hotfix Rollup KB35360093", "5.00.9132.1031"),
            ("5.00.9132.1027", "KB35958849", "Hotfix Rollup KB35958849", "5.00.9132.1032"),
            ("5.00.9132.1027", "KB36419072", "Hotfix Rollup KB36419072", "5.00.9132.1034"),
        ],
    },
    "9128": {
        "BaseName": "SCCM 2403",
        "Stack": [
            ("5.00.9128.1005", "Base", "SCCM 2403 Release", "5.00.9128.1000"),
            ("5.00.9128.1005", "KB28290310", "Hotfix KB28290310", "5.00.9128.1012"),
            ("5.00.9128.1014", "KB28458746", "Hotfix KB28458746", "5.00.9128.1014"),
            ("5.00.9128.1014", "KB29166583", "Hotfix KB29166583", "5.00.9128.1024"),
            ("5.00.9128.1030", "KB28204160", "Rollup KB28204160", "5.00.9128.1030"),
            ("5.00.9128.1033", "KB33177653", "Hotfix KB33177653", "5.00.9128.1033"),
            ("5.00.9128.1033", "KB33926600", "Hotfix KB33926600", "5.00.9128.1034"),
            ("5.00.9128.1033", "KB34503768", "Hotfix KB34503768", "5.00.9128.1035"),
            ("5.00.9128.1033", "KB35360093", "Hotfix KB35360093", "5.00.9128.1037"),
        ],
    },
    "9122": {
        "BaseName": "SCCM 2309",
        "Stack": [
            ("5.00.9122.1002", "Base", "SCCM 2309 Release", "5.00.9122.1000"),
            ("5.00.9122.1007", "KB26129847", "Hotfix KB26129847", "5.00.9122.1007"),
            ("5.00.9122.1018", "KB25858444", "Original Hotfix KB25858444", "5.00.9122.1018"),
            ("5.00.9122.1019", "KB27863823", "Revised Hotfix KB27863823", "5.00.9122.1019"),
            ("5.00.9122.1019", "KB29166583", "MP Hotfix", "5.00.9122.1033"),
        ],
    },
    "9106": {
        "BaseName": "SCCM 2303",
        "Stack": [
            ("5.00.9106.1000", "Base", "SCCM 2303 Release", "5.00.9106.1000"),
            ("5.00.9106.1015", "KB21010486", "Original release", "5.00.9106.1015"),
            ("5.00.9106.1015", "KB24721208", "Hotfix KB24721208", "5.00.9106.1018"),
            ("5.00.9106.1022", "KB24719670", "Revised release", "5.00.9106.1022"),
            ("5.00.9106.1027", "KB25073607", "Hotfix", "5.00.9106.1027"),
            ("5.00.9122.1019", "KB29166583", "MP Hotfix", "5.00.9106.1037"),
        ],
    },
    "9096": {
        "BaseName": "SCCM 2211",
        "Stack": [
            ("5.00.9096.1000", "Base", "SCCM 2211 Release", "5.00.9096.1000"),
            ("5.00.9096.1024", "KB16643863", "Hotfix KB16643863", "5.00.9096.1000"),
        ],
    },
    "9088": {
        "BaseName": "SCCM 2207",
        "Stack": [
            ("5.00.9088.1007", "Base", "SCCM 2207 Release", "5.00.9088.1000"),
            ("5.00.9088.1007", "KB14978429", "Hotfix KB14978429", "5.00.9088.1000"),
            ("5.00.9088.1007", "KB15498768", "Hotfix KB15498768", "5.00.9088.1012"),
            ("5.00.9088.1007", "KB15599094", "Hotfix KB15599094", "5.00.9088.1013"),
            ("5.00.9088.1010", "KB14959905", "Hotfix KB14959905", "5.00.9088.1010"),
            ("5.00.9088.1025", "KB15152495", "Hotfix KB15152495", "5.00.9088.1025"),
        ],
    },
    "9078": {
        "BaseName": "SCCM 2203",
        "Stack": [
            ("5.00.9078.1006", "Base", "SCCM 2203 Release", "5.00.9078.1000"),
            ("5.00.9078.1006", "KB13953025", "Hotfix KB13953025", "5.00.9078.1007"),
            ("5.00.9078.1006", "KB14480034", "Hotfix KB14480034", "5.00.9078.1007"),
            ("5.00.9078.1025", "KB14244456", "Hotfix KB14244456", "5.00.9078.1025"),
        ],
    },
    "9068": {
        "BaseName": "SCCM 2111",
        "Stack": [
            ("5.00.9068.1005", "Base", "SCCM 2111 Release", "5.00.9068.1000"),
            ("5.00.9068.1008", "KB12709700", "Hotfix KB12709700", "5.00.9068.1000"),
            ("5.00.9068.1012", "KB12959506", "Hotfix KB12959506", "5.00.9068.1000"),
            ("5.00.9068.1026", "KB12896009", "Hotfix KB12896009", "5.00.9068.1000"),
        ],
    },
}

# UTF-16LE pattern for "5.00.DDDD.DDDD" as embedded in ccmsetup.exe
_VERSION_PATTERN = rb"5\x00\.\x00\d\x00\d\x00\.\x00\d\x00\d\x00\d\x00\d\x00\.\x00\d\x00\d\x00\d\x00\d\x00"


def _normalize(version: str) -> str:
    return version.replace(".00.", ".0.")


def _locate_build(detected_ver: str) -> Optional[str]:
    for build_id, data in BUILD_MAP.items():
        for item in data["Stack"]:
            if detected_ver in item[0]:
                return build_id
    return None


def _missing_cves_for_stack(stack: list, detected_ver: str) -> list[str]:
    """
    Determine which CVEs the target is still vulnerable to.

    Walks the build's ordered hotfix stack. Rows at-or-before the first
    row whose client version matches the detection are treated as
    installed; rows after are treated as missing (mirrors the
    [INSTALLED]/[CURRENT]/[MISSING] states in Synacktiv's audit_build).
    A CVE is considered patched if any of its fix KBs appears in the
    installed portion for this build.
    """
    installed_kbs: set[str] = set()
    found_current = False
    detected_norm = _normalize(detected_ver)

    for client_v, kb, _name, _full_v in stack:
        is_match = detected_ver == client_v or detected_norm == _normalize(client_v)

        if not found_current:
            if kb != "Base":
                installed_kbs.add(kb)
            if is_match:
                found_current = True

    missing = []
    for cve, fix_kbs in CVE_MAP.items():
        if not any(kb in installed_kbs for kb in fix_kbs):
            missing.append(cve)
    return sorted(missing)


def fingerprint_sccm_version(
    hostname: str,
    http_open: bool,
    timeout: int = 10,
) -> tuple[Optional[str], list[str]]:
    """
    Attempt to fingerprint an SCCM management point's build over plain HTTP.

    Returns a tuple of (detected_client_version, missing_cves). Either or
    both may be empty/None if fingerprinting fails or the detected
    version is not in BUILD_MAP. The Synacktiv technique only works
    over HTTP (TLS-wrapped ccmsetup.exe downloads are not supported).
    """
    if not http_open:
        return None, []

    url = f"http://{hostname}/CCM_CLIENT/ccmsetup.exe"
    try:
        response = requests.get(
            url,
            headers={"Range": "bytes=5000000-"},
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
    except requests.exceptions.RequestException:
        return None, []
    except Exception:
        return None, []

    if response.status_code not in (200, 206):
        logger.debug(f"Version fingerprint: {url} returned {response.status_code}")
        return None, []

    matches = re.findall(_VERSION_PATTERN, response.content)
    if not matches:
        logger.debug(f"Version fingerprint: no version string in ccmsetup.exe on {hostname}")
        return None, []

    try:
        detected = matches[0].decode("utf-16-le")
    except UnicodeDecodeError:
        return None, []

    build_id = _locate_build(detected)
    if not build_id:
        logger.info(
            f"Version fingerprint on {hostname}: detected {detected} (unknown build — no CVE data)"
        )
        return detected, []

    data = BUILD_MAP[build_id]
    missing_cves = _missing_cves_for_stack(data["Stack"], detected)
    logger.info(
        f"Version fingerprint on {hostname}: {detected} ({data['BaseName']}); "
        f"unpatched CVEs: {len(missing_cves)}"
    )
    return detected, missing_cves
