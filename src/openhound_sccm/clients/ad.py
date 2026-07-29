"""LDAP / Active Directory client for SCCM data collection.

SCCM's :class:`ADClient` is now a thin subclass of the shared
:class:`openhound_collector_common.clients.ad.AdClient`. The shared client
contributes the entire **lockout-safe** transport/bind waterfall (LDAPS:636+CBT →
StartTLS:389+CBT → LDAP:389+sign/seal, with Kerberos / current-user SSPI-NTLM /
anonymous fallbacks), the paged-search loop, and the SID/GUID decoders — all
originally proven here and generalized into the shared library (which the MSSQL
collector also consumes). This subclass keeps only the SCCM-specific surface:

  * constructed from SCCM's :class:`ADCredentials` (username+password, an NT hash
    for pass-the-hash, a base64 Kerberos ticket for pass-the-ticket, or
    integrated auth), mapped onto the shared ``LdapAuth``;
  * :meth:`_entry_to_dict` emits **snake_case** keys (``dns_host_name`` …) so
    dlt's table loader doesn't mangle camelCase, and preserves opaque binary
    attributes (``ntSecurityDescriptor`` / ``dnsRecord``) as raw bytes;
  * :meth:`get_spns` — servicePrincipalName lookup by hostname.

Lockout-safety (inherited): only AD's ``data 52e`` family of result-49 sub-codes
(bad/locked/expired/disabled credentials) increments ``badPwdCount``. Protocol-
level rejections — ``strongerAuthRequired`` (result 8), CBT mismatch
(``data 80090346``), TLS handshake / connect failures — are returned *before* the
password is validated, so retrying with a different transport profile after one
of those does not advance the lockout counter. The shared ``bind`` propagates
immediately on a credential-class failure (see ``_is_credential_failure``) and
falls through only on protocol/transport errors.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from openhound_collector_common.clients.ad import (
    AdClient,
    LdapAuth,
    bytes_to_guid,
    bytes_to_sid,
)

logger = logging.getLogger(__name__)


@dataclass
class ADCredentials:
    domain: str
    domain_controller: str | None = None
    username: str | None = None
    password: str | None = None
    # Pass-the-hash (bare 32-hex NT or LM:NT) and pass-the-ticket (base64
    # KRB-CRED / .kirbi). The shared waterfall selects the bind mode by
    # credential precedence: ticket -> nt_hash -> password -> integrated.
    nt_hash: str | None = None
    kerberos_ticket: str | None = None
    # Optional port override. ``None`` lets ``bind()`` auto-detect the transport
    # (LDAPS 636 → StartTLS 389 → LDAP 389+sign/seal). Setting a value pins the
    # port and narrows the attempt chain: 636/3269 → LDAPS; anything else → LDAP
    # (with NTLM sign/seal when creds are supplied, plain LDAP only as a last
    # resort).
    port: int | None = None


def _find_mssql_spn_entries(ad_client: Any, dns_hostname: str) -> list[tuple[dict[str, Any], list[str]]]:
    """Shared LDAP search + host-pinning for MSSQLSvc SPN lookups.

    :meth:`ADClient.find_mssql_spns` and :meth:`ADClient.find_mssql_spn_holder`
    (Task 13) both build on this, so the filter and the trailing-wildcard
    host-pinning logic live in exactly one place. Returns one ``(entry,
    matched_spns)`` pair per LDAP entry that has at least one SPN genuinely
    naming *dns_hostname*.

    Module-level (not a method): both callers are invoked in tests as
    ``ADClient.find_mssql_spns(fake_ad, host)``, binding the real method to a
    minimal duck-typed fake that implements only ``paged_search`` — a plain
    function call here (rather than ``ad_client._find_mssql_spn_entries(...)``,
    which would look the helper up on the fake and fail) keeps that pattern working.
    """
    needle = (dns_hostname or "").lower()
    if not needle:
        # No hostname to match on — an empty search would wildcard the whole forest.
        logger.debug("MSSQLSvc SPN search called with an empty hostname; returning none")
        return []
    try:
        logger.info("Searching AD for MSSQLSvc SPNs naming host %s", dns_hostname)
        results = list(
            ad_client.paged_search(
                search_filter=f"(servicePrincipalName=MSSQLSvc/{dns_hostname}*)",
                attributes=["servicePrincipalName", "objectSid", "sAMAccountName", "objectClass"],
            )
        )
    except Exception as ex:
        logger.error("MSSQLSvc SPN search for %s failed: %s", dns_hostname, ex)
        return []

    # The trailing wildcard is needed to match the ':<port>' / '\<instance>' suffix,
    # but it would also match a LONGER hostname that merely starts with ours, so pin
    # the host part exactly here rather than trusting the filter.
    matched: list[tuple[dict[str, Any], list[str]]] = []
    for entry in results:
        # snake_case FIRST: paged_search yields _entry_to_dict output, which lowercases
        # the LDAP attribute name and maps it through _ATTR_KEY_MAP -- so
        # 'servicePrincipalName' arrives as 'service_principal_name'. Reading only the
        # camelCase form silently returns None for every real entry while still passing
        # any test whose fake uses camelCase keys, which is exactly how this went
        # unnoticed. camelCase is kept as a fallback for raw/unmapped callers.
        values = entry.get("service_principal_name") or entry.get("servicePrincipalName") or []
        if isinstance(values, str):
            values = [values]
        entry_spns = [
            spn for spn in values
            if spn.upper().startswith("MSSQLSVC/")
            and spn.split("/", 1)[1].split(":", 1)[0].split("\\", 1)[0].lower() == needle
        ]
        if entry_spns:
            matched.append((entry, entry_spns))
    return matched


class ADClient(AdClient):
    """SCCM LDAP client: the shared lockout-safe ``AdClient`` waterfall plus
    SCCM's snake_case entry mapping and ``get_spns``. See the module docstring."""

    # dlt table columns are snake_case, so entry dicts use snake_case keys rather
    # than the shared client's camelCase. objectSid/objectGuid are decoded
    # separately (binary), so they're intentionally absent from this map.
    _ATTR_KEY_MAP: dict[str, str] = {
        "distinguishedname": "distinguished_name",
        "dnshostname": "dns_host_name",
        "samaccountname": "sam_account_name",
        "userprincipalname": "user_principal_name",
        "objectclass": "object_class",
        "useraccountcontrol": "user_account_control",
        "serviceprincipalname": "service_principal_name",
    }
    # Attributes whose values are always opaque binary blobs and must NOT be
    # UTF-8-decoded (doing so corrupts them via errors="replace" substitution).
    _BINARY_ATTRS = frozenset({"ntsecuritydescriptor", "dnsrecord"})

    def __init__(self, credentials: ADCredentials):
        # Kept for callers that read ``ctx.ad.creds`` (clients/http.py,
        # collectors/dns.py read ``creds.domain_controller``).
        self.creds = credentials
        # SCCM binds LDAP with username+password, an NT hash (pass-the-hash), a
        # Kerberos ticket (pass-the-ticket), or integrated auth; the shared
        # LdapAuth + waterfall selects the mode by credential precedence
        # (ticket → nt_hash → password → SSPI/anonymous).
        super().__init__(
            domain=credentials.domain,
            dc=credentials.domain_controller,
            auth=LdapAuth(
                username=credentials.username,
                password=credentials.password,
                nt_hash=credentials.nt_hash,
                kerberos_ticket=credentials.kerberos_ticket,
            ),
            port=credentials.port,
        )

    @staticmethod
    def _entry_to_dict(entry) -> dict[str, Any]:
        """Convert an ldap3 Entry into a plain dict, decoding binary SIDs/GUIDs.

        All output keys are clean snake_case so dlt's table-loading step does not
        mangle them (e.g. ``dNSHostName`` → ``d_ns_host_name``). LDAP query
        attribute names (the wire protocol) are left unchanged in search calls.
        """
        # distinguishedName always comes from entry.entry_dn; normalise the key
        # here so every other attribute goes through the same mapping path.
        out: dict[str, Any] = {"distinguished_name": str(entry.entry_dn)}
        for attr_name in entry.entry_attributes:
            raw = entry[attr_name].raw_values
            if not raw:
                # Use the mapped key if available, else the raw name.
                out_key = ADClient._ATTR_KEY_MAP.get(attr_name.lower(), attr_name)
                out[out_key] = None
                continue
            if attr_name.lower() == "objectsid":
                out["object_sid"] = bytes_to_sid(raw[0])
                continue
            if attr_name.lower() == "objectguid":
                out["object_guid"] = bytes_to_guid(raw[0])
                continue
            if attr_name.lower() in ADClient._BINARY_ATTRS:
                v = raw[0]
                if isinstance(v, str):
                    v = v.encode("latin-1")
                # Binary attrs like ntsecuritydescriptor have no camelCase alias,
                # so the raw attr_name is already acceptable here.
                out[attr_name] = v
                continue
            values = []
            for v in raw:
                if isinstance(v, (bytes, bytearray)):
                    try:
                        values.append(v.decode("utf-8", errors="replace"))
                    except Exception:
                        values.append(v.hex())
                else:
                    values.append(v)
            out_key = ADClient._ATTR_KEY_MAP.get(attr_name.lower(), attr_name)
            out[out_key] = values if len(values) > 1 else values[0]
        return out

    def get_spns(self, dns_hostname: str) -> list[str]:
        """Query the servicePrincipalName attribute of a computer object by its
        hostname. Returns a list of SPNs or an empty list on miss/failure."""
        try:
            logger.info("Querying SPNs for %s", dns_hostname)
            results = list(
                self.paged_search(
                    search_filter=f"(dNSHostName={dns_hostname})",
                    attributes=["servicePrincipalName"],
                )
            )
            # snake_case FIRST -- see the note in _find_mssql_spn_entries. paged_search
            # yields _entry_to_dict output, so this key is 'service_principal_name'.
            # Reading only the camelCase form made this method return [] for EVERY host
            # since it was written: the port then always silently fell back to 1433 and
            # test_epa never received an SPN to bind against. Found 2026-07-28.
            if results:
                spns = (results[0].get("service_principal_name")
                        or results[0].get("servicePrincipalName"))
                if spns:
                    # ldap3 hands back a bare string when the attribute has one value.
                    return [spns] if isinstance(spns, str) else list(spns)
            logger.debug("No SPNs found for %s", dns_hostname)
        except Exception as ex:
            logger.error("Failed to query SPN for %s: %s", dns_hostname, ex)
        return []

    def find_mssql_spns(self, dns_hostname: str) -> list[str]:
        """Return every ``MSSQLSvc`` SPN whose HOST part is *dns_hostname*, held by any principal.

        Distinct from :meth:`get_spns`, which reads a single computer object's own
        ``servicePrincipalName``. That misses the common case: SQL Server running as a
        *domain service account* — Microsoft's recommended configuration, and the usual
        one for an SCCM site database — registers ``MSSQLSvc/<host>:<port>`` on a **user**
        object, leaving the computer object with no SPN at all.

        The host portion of the SPN names the machine running SQL regardless of which
        principal holds it, so searching for the SPN answers exactly what decision D2(a)
        needs — "does anything in AD advertise SQL Server on this host?" — without caring
        who the holder is. (Resolving the *holder* is :meth:`find_mssql_spn_holder`'s job,
        needed only for the service-account edges.)

        Returns [] on miss or failure; callers treat that as "no SPN evidence".
        """
        matched = _find_mssql_spn_entries(self, dns_hostname)
        spns = [spn for _entry, entry_spns in matched for spn in entry_spns]
        if spns:
            logger.info("Found %d MSSQLSvc SPN(s) for %s: %s", len(spns), dns_hostname, spns)
        else:
            logger.debug("No MSSQLSvc SPN in AD names host %s", dns_hostname)
        return spns

    def find_mssql_spn_holder(self, dns_hostname: str) -> dict[str, Any] | None:
        """Resolve the identity of the AD principal holding an MSSQLSvc SPN naming
        *dns_hostname*, plus the matching SPN string(s).

        Task 13's ``MSSQL_ServiceAccountFor``/``HasSession`` edges need to know WHO
        holds the SPN, not just that one exists (that's :meth:`find_mssql_spns` /
        D2a's job) — the SPN is registered on the account SQL Server actually runs
        as. Shares the search + host-pinning logic via :meth:`_find_mssql_spn_entries`.

        Returns ``None`` if no SPN names this host. If more than one AD principal's
        SPN names it (unusual — AD does not prevent duplicate registrations), the
        first is used and a warning names how many were ignored, since a SQL
        service can only run as one account.
        """
        matched = _find_mssql_spn_entries(self, dns_hostname)
        if not matched:
            logger.debug("No MSSQLSvc SPN holder found for %s", dns_hostname)
            return None
        if len(matched) > 1:
            # Ambiguous registration: log it so an operator can review, but proceed
            # with the first rather than failing the whole lookup.
            logger.warning(
                "%d distinct AD principals hold an MSSQLSvc SPN naming %s; using the "
                "first -- a SQL service can only run as one account, so this is worth "
                "reviewing manually", len(matched), dns_hostname,
            )
        entry, spns = matched[0]
        obj_class = entry.get("object_class") or entry.get("objectClass") or []
        if isinstance(obj_class, str):
            obj_class = [obj_class]
        holder = {
            "spns": spns,
            "object_sid": entry.get("object_sid") or entry.get("objectSid"),
            "sam_account_name": entry.get("sam_account_name") or entry.get("sAMAccountName"),
            "object_class": obj_class,
        }
        logger.info(
            "MSSQLSvc SPN for %s is held by %s (%s)",
            dns_hostname, holder["sam_account_name"], holder["object_sid"],
        )
        return holder
