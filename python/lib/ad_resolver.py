"""
Active Directory object resolution for ConfigManBearPig.

Translated from PowerShell Resolve-PrincipalInDomain and Get-ActiveDirectoryObject.
Uses ldap3 for LDAP queries instead of .NET AD module/ADSI/DirectorySearcher.

Supports explicit credentials for use through proxychains/SOCKS.
"""

import logging
import re
import threading
from typing import Any, Optional

from ldap3 import (
    ALL,
    NTLM,
    SUBTREE,
    AUTO_BIND_NO_TLS,
    Connection,
    Server,
    ServerPool,
)
from ldap3.core.exceptions import LDAPException

logger = logging.getLogger("ConfigManBearPig")


class ADResolver:
    """
    Resolves AD principals (users, computers, groups) via LDAP.

    Translated from PowerShell Resolve-PrincipalInDomain (lines 460-905)
    and Get-ActiveDirectoryObject (lines 907-1131).
    """

    def __init__(
        self,
        domain: str,
        domain_controller: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_ssl: bool = False,
        port: Optional[int] = None,
    ):
        """
        Initialize AD resolver with connection parameters.

        Args:
            domain: Domain name (e.g., mayyhem.com)
            domain_controller: DC hostname/IP (auto-discovered if None)
            username: DOMAIN\\user format for explicit auth
            password: Password for explicit auth
            use_ssl: Use LDAPS (port 636)
            port: Custom port (defaults to 389 or 636)
        """
        self.domain = domain
        self.domain_controller = domain_controller
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.port = port or (636 if use_ssl else 389)

        # Cache for resolved principals: key -> AD object dict
        self._cache: dict[str, Optional[dict[str, Any]]] = {}

        # Base DN derived from domain
        self.base_dn = ",".join(f"DC={part}" for part in domain.split("."))

        # Connection (lazy init)
        self._connection: Optional[Connection] = None

        # Thread safety locks
        self._cache_lock = threading.RLock()
        self._conn_lock = threading.RLock()

    def _get_connection(self) -> Connection:
        """Get or create LDAP connection. Thread-safe."""
        with self._conn_lock:
            if self._connection is not None and self._connection.bound:
                return self._connection

            server_host = self.domain_controller or self.domain
            server = Server(
                server_host,
                port=self.port,
                use_ssl=self.use_ssl,
                get_info=ALL,
                connect_timeout=5,
            )

            if self.username and self.password:
                self._connection = Connection(
                    server,
                    user=self.username,
                    password=self.password,
                    authentication=NTLM,
                    auto_bind=AUTO_BIND_NO_TLS,
                    read_only=True,
                    receive_timeout=30,
                )
            else:
                # Use current Kerberos context (for domain-joined systems)
                self._connection = Connection(
                    server,
                    auto_bind=AUTO_BIND_NO_TLS,
                    read_only=True,
                    receive_timeout=30,
                )

            logger.debug(f"Connected to LDAP server: {server_host}:{self.port}")
            return self._connection

    def close(self) -> None:
        """Close the LDAP connection."""
        with self._conn_lock:
            if self._connection:
                try:
                    self._connection.unbind()
                except Exception:
                    pass
                self._connection = None

    def _search(
        self,
        search_filter: str,
        search_base: Optional[str] = None,
        attributes: Optional[list[str]] = None,
        scope: str = SUBTREE,
        controls: Optional[list] = None,
    ) -> list[dict[str, Any]]:
        """
        Execute an LDAP search and return results as list of dicts.

        Args:
            search_filter: LDAP filter string
            search_base: Search base DN (defaults to domain base)
            attributes: Attributes to retrieve (defaults to all)
            scope: Search scope
            controls: Additional LDAP controls to send with the request

        Returns:
            List of result dictionaries
        """
        with self._conn_lock:
            conn = self._get_connection()
            base = search_base or self.base_dn
            attrs = attributes or ["*"]

            try:
                conn.search(
                    search_base=base,
                    search_filter=search_filter,
                    search_scope=scope,
                    attributes=attrs,
                    paged_size=1000,
                    controls=controls,
                )
            except LDAPException as e:
                logger.error(f"LDAP search failed: {e}")
                return []

            results = []
            for entry in conn.entries:
                obj = self._entry_to_dict(entry)
                results.append(obj)

            # Handle paged results
            cookie = conn.result.get("controls", {}).get(
                "1.2.840.113556.1.4.319", {}
            ).get("value", {}).get("cookie")

            while cookie:
                try:
                    conn.search(
                        search_base=base,
                        search_filter=search_filter,
                        search_scope=scope,
                        attributes=attrs,
                        paged_size=1000,
                        paged_cookie=cookie,
                    )
                except LDAPException:
                    break

                for entry in conn.entries:
                    obj = self._entry_to_dict(entry)
                    results.append(obj)

                cookie = conn.result.get("controls", {}).get(
                    "1.2.840.113556.1.4.319", {}
                ).get("value", {}).get("cookie")

            return results

    @staticmethod
    def _entry_to_dict(entry) -> dict[str, Any]:
        """Convert ldap3 entry to a flat dictionary."""
        obj: dict[str, Any] = {}
        obj["distinguishedName"] = str(entry.entry_dn)

        for attr_name in entry.entry_attributes:
            values = entry[attr_name].values
            if len(values) == 0:
                obj[attr_name] = None
            elif len(values) == 1:
                val = values[0]
                # Convert bytes to string where possible
                if isinstance(val, bytes):
                    try:
                        val = val.decode("utf-8")
                    except (UnicodeDecodeError, AttributeError):
                        pass
                obj[attr_name] = val
            else:
                obj[attr_name] = [
                    v.decode("utf-8") if isinstance(v, bytes) else v
                    for v in values
                ]

        return obj

    def resolve_principal(self, name: str, domain: Optional[str] = None) -> Optional[dict[str, Any]]:
        """
        Resolve a principal name to its AD object with SID.

        Translated from PowerShell Resolve-PrincipalInDomain (lines 460-905).
        Handles: DOMAIN\\name, name@domain, SID strings, bare names.

        Args:
            name: Principal name in various formats
            domain: Optional domain override

        Returns:
            Dictionary with AD attributes including objectSid, or None if not found
        """
        if not name:
            return None

        # Normalize the name
        name = name.strip()
        cache_key = name.lower()

        # Check cache first (thread-safe)
        with self._cache_lock:
            if cache_key in self._cache:
                return self._cache[cache_key]

        resolved = None

        # Try different resolution strategies (LDAP calls are serialized by _conn_lock)
        try:
            # Strategy 1: Already a SID
            if name.upper().startswith("S-1-"):
                resolved = self._resolve_by_sid(name)

            # Strategy 2: DOMAIN\name format
            elif "\\" in name:
                parts = name.split("\\", 1)
                account_name = parts[1]
                resolved = self._resolve_by_samaccountname(account_name)

            # Strategy 3: name@domain format (UPN)
            elif "@" in name and "." in name.split("@")[-1]:
                resolved = self._resolve_by_upn(name)
                if not resolved:
                    # Fallback: extract the name part
                    account_name = name.split("@")[0]
                    resolved = self._resolve_by_samaccountname(account_name)

            # Strategy 4: Distinguished name
            elif name.upper().startswith("CN="):
                resolved = self._resolve_by_dn(name)

            # Strategy 5: Bare name (try sAMAccountName)
            else:
                resolved = self._resolve_by_samaccountname(name)

        except Exception as e:
            logger.debug(f"Failed to resolve principal '{name}': {e}")

        # Convert SID bytes to string if needed
        if resolved and "objectSid" in resolved:
            sid = resolved["objectSid"]
            if isinstance(sid, bytes):
                resolved["objectSid"] = self._sid_bytes_to_string(sid)
            # Also set as 'SID' for convenience
            resolved["SID"] = resolved["objectSid"]

        # Set Domain property on resolved objects (matching PowerShell behavior)
        # PowerShell sets Domain = $domainToTry on every resolved AD object
        if resolved and "Domain" not in resolved:
            resolved["Domain"] = self.domain

        with self._cache_lock:
            self._cache[cache_key] = resolved
        return resolved

    def _resolve_by_sid(self, sid: str) -> Optional[dict[str, Any]]:
        """Resolve by SID string."""
        results = self._search(
            f"(objectSid={sid})",
            attributes=[
                "objectSid", "sAMAccountName", "distinguishedName",
                "dNSHostName", "objectClass", "userPrincipalName",
                "name", "cn", "servicePrincipalName",
            ],
        )
        return results[0] if results else None

    def _resolve_by_samaccountname(self, name: str) -> Optional[dict[str, Any]]:
        """Resolve by sAMAccountName."""
        # Escape LDAP special chars
        escaped = self._ldap_escape(name)
        results = self._search(
            f"(sAMAccountName={escaped})",
            attributes=[
                "objectSid", "sAMAccountName", "distinguishedName",
                "dNSHostName", "objectClass", "userPrincipalName",
                "name", "cn", "servicePrincipalName",
            ],
        )
        return results[0] if results else None

    def _resolve_by_upn(self, upn: str) -> Optional[dict[str, Any]]:
        """Resolve by userPrincipalName."""
        escaped = self._ldap_escape(upn)
        results = self._search(
            f"(userPrincipalName={escaped})",
            attributes=[
                "objectSid", "sAMAccountName", "distinguishedName",
                "dNSHostName", "objectClass", "userPrincipalName",
                "name", "cn", "servicePrincipalName",
            ],
        )
        return results[0] if results else None

    def _resolve_by_dn(self, dn: str) -> Optional[dict[str, Any]]:
        """Resolve by distinguishedName."""
        results = self._search(
            "(objectClass=*)",
            search_base=dn,
            attributes=[
                "objectSid", "sAMAccountName", "distinguishedName",
                "dNSHostName", "objectClass", "userPrincipalName",
                "name", "cn", "servicePrincipalName",
            ],
        )
        return results[0] if results else None

    def get_ad_object(
        self,
        search_filter: str,
        search_base: Optional[str] = None,
        attributes: Optional[list[str]] = None,
    ) -> list[dict[str, Any]]:
        """
        Search for AD objects matching a filter.

        Translated from PowerShell Get-ActiveDirectoryObject (lines 907-1131).

        Args:
            search_filter: LDAP filter
            search_base: Search base DN
            attributes: Attributes to return

        Returns:
            List of matching AD objects
        """
        return self._search(search_filter, search_base, attributes)

    def get_ad_computer(self, hostname: str) -> Optional[dict[str, Any]]:
        """
        Resolve a computer hostname to its AD object.

        Args:
            hostname: Computer name (with or without $ suffix, with or without FQDN)

        Returns:
            AD computer object dict with SID, or None
        """
        # Strip domain suffix to get short name
        short_name = hostname.split(".")[0].rstrip("$")

        cache_key = f"computer:{short_name.lower()}"
        with self._cache_lock:
            if cache_key in self._cache:
                return self._cache[cache_key]

        # Search for computer by sAMAccountName (computers end with $)
        sam = f"{short_name}$"
        results = self._search(
            f"(&(objectClass=computer)(sAMAccountName={self._ldap_escape(sam)}))",
            attributes=[
                "objectSid", "sAMAccountName", "distinguishedName",
                "dNSHostName", "operatingSystem", "operatingSystemVersion",
                "name", "cn", "servicePrincipalName", "objectClass",
            ],
        )

        result = results[0] if results else None

        # Convert SID
        if result and "objectSid" in result:
            sid = result["objectSid"]
            if isinstance(sid, bytes):
                result["objectSid"] = self._sid_bytes_to_string(sid)
            result["SID"] = result["objectSid"]

        # Set Domain property (matching PowerShell behavior)
        if result and "Domain" not in result:
            result["Domain"] = self.domain

        with self._cache_lock:
            self._cache[cache_key] = result
        return result

    def get_forest_root(self) -> Optional[str]:
        """
        Get the forest root domain name.

        Translated from PowerShell Get-ForestRoot (lines 1133-1146).

        Returns:
            Forest root domain name or None
        """
        try:
            conn = self._get_connection()
            if conn.server.info and hasattr(conn.server.info, "other"):
                root_dn = conn.server.info.other.get("rootDomainNamingContext", [None])[0]
                if root_dn:
                    # Convert DN to domain name
                    parts = re.findall(r"DC=([^,]+)", root_dn, re.IGNORECASE)
                    return ".".join(parts)
        except Exception as e:
            logger.debug(f"Failed to get forest root: {e}")

        return self.domain

    def get_domain_sid(self) -> Optional[str]:
        """Get the domain SID."""
        try:
            results = self._search(
                "(objectClass=domain)",
                search_base=self.base_dn,
                attributes=["objectSid"],
            )
            if results and "objectSid" in results[0]:
                sid = results[0]["objectSid"]
                if isinstance(sid, bytes):
                    return self._sid_bytes_to_string(sid)
                return str(sid)
        except Exception as e:
            logger.debug(f"Failed to get domain SID: {e}")
        return None

    @staticmethod
    def _sid_bytes_to_string(sid_bytes: bytes) -> str:
        """Convert binary SID to string representation (S-1-...)."""
        if isinstance(sid_bytes, str):
            return sid_bytes

        try:
            revision = sid_bytes[0]
            sub_authority_count = sid_bytes[1]
            authority = int.from_bytes(sid_bytes[2:8], byteorder="big")
            sub_authorities = []
            for i in range(sub_authority_count):
                offset = 8 + i * 4
                sub_auth = int.from_bytes(
                    sid_bytes[offset : offset + 4], byteorder="little"
                )
                sub_authorities.append(sub_auth)
            return f"S-{revision}-{authority}-" + "-".join(
                str(sa) for sa in sub_authorities
            )
        except Exception:
            return sid_bytes.hex()

    @staticmethod
    def _ldap_escape(value: str) -> str:
        """Escape special characters in LDAP filter values."""
        replacements = {
            "\\": "\\5c",
            "*": "\\2a",
            "(": "\\28",
            ")": "\\29",
            "\x00": "\\00",
        }
        for char, escaped in replacements.items():
            value = value.replace(char, escaped)
        return value

    def search_system_management_container(self) -> list[dict[str, Any]]:
        """
        Search the System Management container for SCCM objects.

        Translated from Invoke-LDAPCollection's container search.

        Returns:
            List of objects in the System Management container
        """
        # Find System Management container
        system_dn = f"CN=System,{self.base_dn}"
        container_dn = f"CN=System Management,{system_dn}"

        try:
            return self._search(
                "(objectClass=*)",
                search_base=container_dn,
                attributes=["*"],
            )
        except Exception as e:
            logger.debug(f"System Management container search failed: {e}")
            return []

    def get_well_known_sid_name(self, sid: str) -> Optional[str]:
        """
        Map well-known SIDs to names for creating group nodes.

        Args:
            sid: SID string

        Returns:
            Group name or None
        """
        # Well-known SIDs
        well_known = {
            "S-1-5-11": "Authenticated Users",
            "S-1-5-32-544": "Administrators",
            "S-1-5-32-545": "Users",
            "S-1-5-32-546": "Guests",
            "S-1-5-18": "SYSTEM",
            "S-1-5-19": "LOCAL SERVICE",
            "S-1-5-20": "NETWORK SERVICE",
            "S-1-1-0": "Everyone",
            "S-1-5-10": "SELF",
        }

        # Check exact match
        if sid in well_known:
            return well_known[sid]

        # Check domain-relative well-known SIDs (e.g., DOMAIN_SID-512)
        for wk_sid, name in well_known.items():
            if sid.endswith(f"-{wk_sid.split('-')[-1]}"):
                if wk_sid.startswith("S-1-5-32-"):
                    return name

        return None
