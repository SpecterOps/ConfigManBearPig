"""Base OpenGraph node/edge dataclasses + shared helpers for the SCCM collector.

Concrete node models (models/*.py) build these in their `as_node`. `SCCMNode`
supplies the `id` directly (we already know the SID / site code), unlike the
framework's UUID-deriving base. `domain_environment_id` derives the AD-domain SID
used as `environmentid` for Base AD nodes (spec §2 "Root/environment node").
"""
import re
from dataclasses import dataclass, field

from openhound.core.models.entries_dataclass import EdgeProperties, Node, NodeProperties

# A domain SID is the `S-1-5-21-X-Y-Z` prefix; an account SID appends `-RID`.
_DOMAIN_SID = re.compile(r"^(S-1-5-21(?:-\d+){3})-\d+$")


def domain_environment_id(sid: str, fallback_domain_sid: str | None = None) -> str | None:
    """Return the AD-domain SID to use as `environmentid` for a Base AD node.

    - Normal account SID `S-1-5-21-X-Y-Z-RID` -> `S-1-5-21-X-Y-Z`.
    - Well-known/builtin SID (no `S-1-5-21` domain part, e.g. `S-1-5-32-544`,
      `S-1-5-11`) -> `fallback_domain_sid` (the domain SID known from the record
      that produced this principal; SharpHound-style per-domain qualification).
    - `None` if neither applies; caller drops the node and logs.
    """
    if not sid:
        return None
    m = _DOMAIN_SID.match(sid.upper())
    if m:
        return m.group(1)
    return fallback_domain_sid


# Edge kind -> the kind to give a synthesised stub when the edge's END id has no node.
# Only edges whose end is a user/group SID (or a device smsid) appear here; ambiguous
# ends (user OR group) get "Base". See Stage 2 graph-integrity decision (2026-06-23).
BACKFILL_END_KIND: dict[str, str] = {
    "SCCM_HasPrimaryUser": "User",
    "SCCM_HasCurrentUser": "User",
    "SCCM_HasADLastLogonUser": "User",
    "HasSession": "User",
    "MemberOf": "Group",
    "SCCM_HasMember": "Base",
    "SCCM_HasStoredAccount": "Base",
}


@dataclass
class SCCMEdgeProperties(EdgeProperties):
    """Property set carried by every edge this collector emits.

    Property names mirror ConfigManBearPig.ps1 exactly so BloodHound entity panels
    render the keys operators know from the original tool. `traversable`/`composed`
    come from the framework EdgeProperties base and already match CMBP. The five
    help fields carry entity-panel documentation (see edge_help.py); they default to
    None so edges without authored content omit them (convert prunes null values).

    Attributes:
        collectionSource: Which collection method(s) produced this edge (e.g.
            ``AdminService``, ``LDAP``, ``RemoteRegistry``), as a list of tags. An edge
            can be confirmed by more than one method, in which case the list has
            more than one entry.
        general: Entity-panel "General" text — what this edge means and why it
            matters — or None if no help content is authored for this edge kind.
        windowsAbuse: Entity-panel "Windows Abuse" text — how to abuse this edge from
            a Windows host — or None.
        linuxAbuse: Entity-panel "Linux Abuse" text — how to abuse this edge from a
            Linux host — or None.
        opsec: Entity-panel "OPSEC" text — detection / operational-security
            considerations for abusing this edge — or None.
        references: Entity-panel "References" URLs for this edge kind, or None.
        SCCMInfra: True when this edge flags its start-node principal as SCCM
            infrastructure (CMBP ps1:7807, SCCM_IsMappedTo only) — or None for every
            other edge kind, which convert prunes so their panels stay uncluttered.
        assumed: True when this edge is templated/inferred rather than built from
            observed data (D3) — the MSSQL site-DB scaffolding edges that rest on the
            SPN+SCCM inference (Task 4), and the SCCM permission/coerce/local-admin
            edges that assume RBAC/relay feasibility from role topology (Task 5) —
            or None for every confirmed edge, which convert prunes.
        assumptionBasis: Human-readable explanation of the inference, present only
            when `assumed` is true.
    """
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    general: str | None = field(default=None, kw_only=True)
    windowsAbuse: str | None = field(default=None, kw_only=True)
    linuxAbuse: str | None = field(default=None, kw_only=True)
    opsec: str | None = field(default=None, kw_only=True)
    references: list[str] | None = field(default=None, kw_only=True)
    SCCMInfra: bool | None = field(default=None, kw_only=True)
    assumed: bool | None = field(default=None, kw_only=True)
    assumptionBasis: str | None = field(default=None, kw_only=True)


@dataclass
class SCCMRelayEdgeProperties(SCCMEdgeProperties):
    """Property set for the 3 coerce-and-relay edge kinds.

    Coerce-and-relay context (CMBP Process-CoerceAndRelayTo*). ONLY the three
    CoerceAndRelay* edge kinds carry these — every other edge keeps the lean base
    SCCMEdgeProperties so its BloodHound panel stays uncluttered. Field names mirror
    ConfigManBearPig.ps1 exactly (ps1:6617/6719/6777).

    Attributes:
        coercionVictimAndRelayTargetPairs: The specific "coerce this victim, relay to
            this target" combinations that make the attack possible, each written as a
            single string pairing the two (e.g. ``"victim.corp.local -> target.corp.local"``).
            Lets an operator see exactly which host pairs to use without cross-referencing
            other data.
        coercionVictimHostnames: The hostnames of machines that can be coerced into
            authenticating for this relay, listed on their own when the edge's start/end
            nodes already convey the relay target (so this list isn't paired with a target
            the way `coercionVictimAndRelayTargetPairs` is).
    """
    coercionVictimAndRelayTargetPairs: list[str] = field(default_factory=list, kw_only=True)
    coercionVictimHostnames: list[str] = field(default_factory=list, kw_only=True)


@dataclass
class SCCMNode(Node):
    """Concrete SCCM node: `id` is supplied directly (no UUID derivation)."""
    id: str = ""

    def __post_init__(self):
        # id is set by the caller; nothing to derive. (Node declares this abstract.)
        return


# All node-property field names below mirror ConfigManBearPig.ps1's exact casing (camelCase for
# LDAP-derived attributes like dNSHostName/samAccountName, PascalCase for SCCM-specific properties
# like SCCMSiteSystemRoles). The framework base fields name/displayname/environmentid/last_seen are
# left as-is. dataclasses.asdict() emits these field names verbatim as the OpenGraph JSON keys.
@dataclass
class ComputerProperties(NodeProperties):
    """AD `Computer` node, extended with SCCM/SMB posture data.

    Attributes:
        collectionSource: Which collection method(s) saw this computer (e.g.
            ``AdminService``, ``LDAP``, ``RemoteRegistry``, ``SMB``), as a list of tags.
        SCCMSiteSystemRoles: The SCCM roles this machine performs, each written as
            ``"<role>@<siteCode>"`` (e.g. ``"SMS Site Server@PS1"``). A machine can hold
            more than one role, and can hold roles for more than one site.
        SCCMInfra: True if this computer is part of the SCCM infrastructure itself
            (a site server, SQL server, management point, etc.) rather than an
            ordinary managed endpoint.
        SCCMResourceIDs: The SCCM internal "ResourceID" number(s) that identify this
            computer inside SCCM's own database, one per site it's known to.
        SCCMClientDeviceIdentifier: The unique ID SCCM's client software assigns to this
            machine (its "SMS unique identifier"), used to link this AD computer object
            to its `SCCM_ClientDevice` node.
        dNSHostName: The computer's fully-qualified DNS name, as recorded in Active
            Directory.
        samAccountName: The computer's pre-Windows-2000 logon name (its AD "SAM account
            name", e.g. ``COMPUTER1$``).
        distinguishedName: The computer's Active Directory distinguished name (its full
            path in the AD tree, e.g. ``CN=COMPUTER1,OU=Workstations,DC=corp,DC=local``).
        SMBSigningRequired: Whether this computer requires SMB signing (True), allows it
            to be skipped (False), or it wasn't collected (null). SMB signing prevents a
            class of relay attacks, so False here is a notable weakness.
        SCCMHasClientRemoteControlSPN: True if this computer has published a Kerberos
            Service Principal Name (SPN) for SCCM's Remote Control feature, which is how
            the collector infers a machine is an SCCM client even without querying SCCM
            itself directly.
        networkBootServer: True if this computer is configured to serve PXE network-boot
            images (an SCCM Distribution Point capability).
        disableLoopbackCheck: Whether this computer has the Windows "loopback check"
            security feature turned off (True), left on (False), or it wasn't collected
            (null). Disabling it can expose the machine to certain authentication
            reflection issues.
        restrictReceivingNtlmTraffic: This computer's inbound-NTLM restriction policy as
            collected (e.g. ``Off`` / ``Deny all``), or null if it wasn't observed.
        SCCMClientCertificateRequired: Whether this computer's SCCM site requires a PKI
            client certificate for communication (True), allows unauthenticated HTTP
            (False), or it wasn't collected (null).
        SCCMHostsContentLibrary: Whether this computer hosts an SCCM Distribution Point's
            content library (the file share holding deployed application/package files),
            or null if not collected.
        SCCMIsPXESupportEnabled: Whether this computer has PXE (network boot) support
            turned on for SCCM OS deployment, or null if not collected.
        Domain: The AD domain (e.g. ``lab.local``) this computer's account belongs to,
            or null if the account was never resolved against AD (e.g. an SCCM-only
            device record with no matching AD object).
        Enabled: Whether this computer account is enabled in AD (True), disabled
            (False), or null if it was never resolved against AD.
        IsDomainPrincipal: True if this computer was successfully resolved to a real AD
            object via LDAP, or null if it wasn't (so this is unknown rather than "no").
        Type: The AD object type this computer resolved to (e.g. ``Computer``), or null
            if it was never resolved against AD.
        objectClass: The AD `objectClass` attribute values for this computer's account
            (e.g. ``["top", "person", "computer"]``), or null if never resolved against AD.
        servicePrincipalName: The Kerberos Service Principal Names (SPNs) published on
            this computer's AD account, or null if never resolved against AD.
        CN: The AD `cn` (Common Name) attribute for this computer's account, or null if
            never resolved against AD.
    """
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    SCCMSiteSystemRoles: list[str] = field(default_factory=list, kw_only=True)
    SCCMInfra: bool = field(default=False, kw_only=True)
    SCCMResourceIDs: list[str] = field(default_factory=list, kw_only=True)
    SCCMClientDeviceIdentifier: str | None = field(default=None, kw_only=True)
    dNSHostName: str | None = field(default=None, kw_only=True)
    samAccountName: str | None = field(default=None, kw_only=True)
    distinguishedName: str | None = field(default=None, kw_only=True)
    SMBSigningRequired: bool | None = field(default=None, kw_only=True)
    SCCMHasClientRemoteControlSPN: bool = field(default=False, kw_only=True)
    networkBootServer: bool = field(default=False, kw_only=True)
    disableLoopbackCheck: bool | None = field(default=None, kw_only=True)
    restrictReceivingNtlmTraffic: str | None = field(default=None, kw_only=True)
    SCCMClientCertificateRequired: bool | None = field(default=None, kw_only=True)
    SCCMHostsContentLibrary: bool | None = field(default=None, kw_only=True)
    SCCMIsPXESupportEnabled: bool | None = field(default=None, kw_only=True)
    Domain: str | None = field(default=None, kw_only=True)
    Enabled: bool | None = field(default=None, kw_only=True)
    IsDomainPrincipal: bool | None = field(default=None, kw_only=True)
    Type: str | None = field(default=None, kw_only=True)
    objectClass: list[str] | None = field(default=None, kw_only=True)
    servicePrincipalName: list[str] | None = field(default=None, kw_only=True)
    CN: str | None = field(default=None, kw_only=True)


@dataclass
class UserProperties(NodeProperties):
    """AD `User` node, extended with SCCM-relevant data.

    Attributes:
        collectionSource: Which collection method(s) saw this user (e.g.
            ``AdminService``, ``LDAP``), as a list of tags.
        SCCMResourceIDs: The SCCM internal "ResourceID" number(s) that identify this
            user inside SCCM's own database, one per site it's known to.
        SCCMInfra: True if this user is part of the SCCM infrastructure itself (e.g. a
            service account used to run SCCM/SQL) rather than an ordinary AD user.
        storedInSCCMSite: The site code of the SCCM site that holds a "stored account"
            (a saved credential) for this user, or null if this user isn't one.
        distinguishedName: The user's Active Directory distinguished name (its full path
            in the AD tree, e.g. ``CN=User1,OU=People,DC=corp,DC=local``).
        userPrincipalName: The user's AD logon name in email-address form (e.g.
            ``user1@corp.local``).
        samAccountName: The user's pre-Windows-2000 logon name (its AD "SAM account name",
            e.g. ``sqlsccmsvc``). camelCase to match ``ComputerProperties.samAccountName`` —
            OpenHound normalizes this LDAP attribute to camelCase (CMBP writes it PascalCase,
            but BloodHound/Neo4j property lookup is case-insensitive). Needed so edges keyed on
            the SQL service account or AD users (HasSession, MSSQL_GetTGS/GetAdminTGS/
            ServiceAccountFor, SCCM_HasPrimaryUser/HasADLastLogonUser/IsMappedTo) can resolve
            their User endpoint by ``samAccountName``.
        Domain: The AD domain (e.g. ``lab.local``) this user's account belongs to, or
            null if the account was never resolved against AD.
        Enabled: Whether this user account is enabled in AD (True), disabled (False),
            or null if it was never resolved against AD.
        IsDomainPrincipal: True if this user was successfully resolved to a real AD
            object via LDAP, or null if it wasn't (so this is unknown rather than "no").
        Type: The AD object type this user resolved to (e.g. ``User``), or null if it
            was never resolved against AD.
        objectClass: The AD `objectClass` attribute values for this user's account
            (e.g. ``["top", "person", "user"]``), or null if never resolved against AD.
        servicePrincipalName: The Kerberos Service Principal Names (SPNs) published on
            this user's AD account, or null if never resolved against AD.
        CN: The AD `cn` (Common Name) attribute for this user's account, or null if
            never resolved against AD.
    """
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    SCCMResourceIDs: list[str] = field(default_factory=list, kw_only=True)
    SCCMInfra: bool = field(default=False, kw_only=True)
    storedInSCCMSite: str | None = field(default=None, kw_only=True)
    distinguishedName: str | None = field(default=None, kw_only=True)
    userPrincipalName: str | None = field(default=None, kw_only=True)
    samAccountName: str | None = field(default=None, kw_only=True)
    Domain: str | None = field(default=None, kw_only=True)
    Enabled: bool | None = field(default=None, kw_only=True)
    IsDomainPrincipal: bool | None = field(default=None, kw_only=True)
    Type: str | None = field(default=None, kw_only=True)
    objectClass: list[str] | None = field(default=None, kw_only=True)
    servicePrincipalName: list[str] | None = field(default=None, kw_only=True)
    CN: str | None = field(default=None, kw_only=True)


@dataclass
class GroupProperties(NodeProperties):
    """AD `Group` node, extended with SCCM-relevant data.

    Attributes:
        collectionSource: Which collection method(s) saw this group (e.g.
            ``AdminService``, ``LDAP``), as a list of tags.
        SCCMInfra: True if this group is part of the SCCM infrastructure itself (e.g.
            a built-in SCCM security group) rather than an ordinary AD group.
        SCCMResourceIDs: The SCCM internal "ResourceID" number(s) that identify this
            group inside SCCM's own database, one per site it's known to.
        Domain: The AD domain (e.g. ``lab.local``) this group belongs to, or null if
            it was never resolved against AD.
        Enabled: Whether this group is enabled in AD — always null in practice, since
            AD groups have no ACCOUNTDISABLE bit, but present for schema symmetry with
            Computer/User.
        IsDomainPrincipal: True if this group was successfully resolved to a real AD
            object via LDAP, or null if it wasn't (so this is unknown rather than "no").
        Type: The AD object type this group resolved to (e.g. ``Group``), or null if it
            was never resolved against AD.
        objectClass: The AD `objectClass` attribute values for this group (e.g.
            ``["top", "group"]``), or null if never resolved against AD.
        servicePrincipalName: The Kerberos Service Principal Names (SPNs) published on
            this group's AD object, or null if never resolved against AD (groups rarely
            carry SPNs, but the field is present for schema symmetry).
        CN: The AD `cn` (Common Name) attribute for this group, or null if never
            resolved against AD.
        SamAccountName: The group's pre-Windows-2000 name (its AD "SAM account name"),
            or null if never resolved against AD. PascalCase to match CMBP's Group
            output verbatim -- unlike Computer/User, CMBP does not camelCase this key
            for Group.
        distinguishedName: The group's Active Directory distinguished name (its full
            path in the AD tree, e.g. ``CN=Domain Admins,CN=Users,DC=corp,DC=local``),
            or null if never resolved against AD.
    """
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    SCCMInfra: bool = field(default=False, kw_only=True)
    SCCMResourceIDs: list[str] = field(default_factory=list, kw_only=True)
    Domain: str | None = field(default=None, kw_only=True)
    Enabled: bool | None = field(default=None, kw_only=True)
    IsDomainPrincipal: bool | None = field(default=None, kw_only=True)
    Type: str | None = field(default=None, kw_only=True)
    objectClass: list[str] | None = field(default=None, kw_only=True)
    servicePrincipalName: list[str] | None = field(default=None, kw_only=True)
    CN: str | None = field(default=None, kw_only=True)
    SamAccountName: str | None = field(default=None, kw_only=True)
    distinguishedName: str | None = field(default=None, kw_only=True)


@dataclass
class SCCMSiteProperties(NodeProperties):
    """An SCCM site — one management boundary in the SCCM hierarchy (CAS, Primary, or
    Secondary), together with the servers and accounts that run it.

    Attributes:
        collectionSource: Which collection method(s) produced this site's data (e.g.
            ``AdminService``, ``LDAP``), as a list of tags.
        siteCode: The site's 3-character SCCM site code (e.g. ``PS1``).
        parentSiteCode: The site code of this site's parent in the SCCM hierarchy (the
            Primary site above a Secondary, or the CAS above a Primary), or null if this
            site has no parent (it's the top of the hierarchy).
        rootSiteCode: The site code of the top-most site in this site's hierarchy (the
            CAS, or the lone Primary if there's no CAS).
        siteType: The kind of site this is (e.g. Central Administration Site, Primary,
            or Secondary).
        siteGUID: The site's globally unique identifier as assigned by SCCM.
        siteServerName: The short (NetBIOS) name of the server running this site.
        SQLServerName: The short (NetBIOS) name of the SQL Server instance backing this
            site's database.
        SQLDatabaseName: The name of the SQL Server database that stores this site's data.
        version: The SCCM product version string for this site.
        buildNumber: The SCCM build number for this site.
        installDir: The filesystem path where SCCM is installed on the site server.
        SQLServiceAccountName: The logon name of the Windows account the SQL Server
            service runs as for this site's database.
        distinguishedName: The site server's Active Directory distinguished name, when
            it could be resolved.
        sourceForest: The name of the Active Directory forest this site was published to
            / discovered from.
        adminUsers: The node IDs of every `SCCM_AdminUser` granted access at this site.
        storedAccounts: The node IDs of every AD user/group whose credentials are saved
            in this site as a "stored account" (e.g. for OSD task sequences or client push).
        siteSystemRoles: One "<dnsHostName>: <role>@<siteCode>" string per computer that
            hosts a site-system role at this site (e.g. "srv1.corp.local: SMS Site
            Server@CAS"), aggregated from every node_computer whose own per-host
            SCCMSiteSystemRoles list contains a role suffixed with this site's code
            (CMBP ps1:1851-1897). Distinct from `Computer.SCCMSiteSystemRoles`, which is
            the same role data viewed per-host instead of per-site.
        SCCMInfra: Always true for a site node — sites are always part of the SCCM
            infrastructure by definition.
        siteServerFQDN: The fully-qualified DNS name of the server running this site.
        siteServerDomainSID: The full Active Directory SID of the site server's computer
            object (despite the "DomainSID" name inherited from CMBP, this holds the
            whole object SID, not just the domain portion).
        SQLServerFQDN: The fully-qualified DNS name of the SQL Server backing this site.
        SQLServerDomainSID: The full Active Directory SID of the SQL Server's computer
            object (same "DomainSID" naming note as `siteServerDomainSID`).
        SQLServiceAccountDomainSID: The full Active Directory SID of the account the SQL
            Server service runs as (same "DomainSID" naming note as above).
        SQLServicePort: The TCP port the SQL Server instance listens on.
        versionCVEs: The CVE identifiers this site's SCCM build is still exposed to,
            derived from ``version`` via cve_table.lookup_cves. None when the version is
            unknown; an empty list when the version is known but fully patched.
    """
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    siteCode: str | None = field(default=None, kw_only=True)
    parentSiteCode: str | None = field(default=None, kw_only=True)
    rootSiteCode: str | None = field(default=None, kw_only=True)
    siteType: str | None = field(default=None, kw_only=True)
    siteGUID: str | None = field(default=None, kw_only=True)
    siteServerName: str | None = field(default=None, kw_only=True)
    SQLServerName: str | None = field(default=None, kw_only=True)
    SQLDatabaseName: str | None = field(default=None, kw_only=True)
    version: str | None = field(default=None, kw_only=True)
    buildNumber: str | None = field(default=None, kw_only=True)
    installDir: str | None = field(default=None, kw_only=True)
    # Stage 3 C5 additions — CMBP parity.
    SQLServiceAccountName: str | None = field(default=None, kw_only=True)
    distinguishedName: str | None = field(default=None, kw_only=True)
    sourceForest: str | None = field(default=None, kw_only=True)
    adminUsers: list[str] = field(default_factory=list, kw_only=True)
    storedAccounts: list[str] = field(default_factory=list, kw_only=True)
    siteSystemRoles: list[str] = field(default_factory=list, kw_only=True)
    SCCMInfra: bool = field(default=True, kw_only=True)
    # Site/SQL server identity (CMBP ps1:7052-7065, 3040). The *DomainSID fields hold the full
    # resolved computer/account SID (CMBP names them "DomainSID" but stores the whole object SID).
    siteServerFQDN: str | None = field(default=None, kw_only=True)
    siteServerDomainSID: str | None = field(default=None, kw_only=True)
    SQLServerFQDN: str | None = field(default=None, kw_only=True)
    SQLServerDomainSID: str | None = field(default=None, kw_only=True)
    SQLServiceAccountDomainSID: str | None = field(default=None, kw_only=True)
    SQLServicePort: str | None = field(default=None, kw_only=True)
    versionCVEs: list[str] | None = field(default=None, kw_only=True)


@dataclass
class SCCMCollectionProperties(NodeProperties):
    """An SCCM collection — a named group of devices or users that admins target with
    deployments, and that can carry its own security-role assignments.

    Attributes:
        collectionSource: Which collection method(s) produced this collection's data
            (e.g. ``AdminService``, ``WMI``), as a list of tags.
        collectionID: The collection's SCCM ID (e.g. ``PS100002``), uppercased.
        collectionType: What kind of objects this collection groups: ``"Other"``,
            ``"User"``, or ``"Device"``.
        memberCount: How many members SCCM reports this collection currently has.
        comment: The free-text description an admin attached to this collection.
        isBuiltIn: True if this is one of SCCM's built-in collections (e.g. "All
            Systems") rather than one an admin created.
        limitToCollectionID: The ID of the collection this one is scoped to (a
            collection can only contain members that are also in its "limiting
            collection"), or null if it has none.
        limitToCollectionName: The name of the limiting collection identified by
            `limitToCollectionID`.
        collectionVariablesCount: How many collection variables (deployment-time
            settings) are defined on this collection.
        rootSiteCode: The site code of the top-most site in this collection's site
            hierarchy.
        sourceSiteCode: The site code of the SCCM site where this collection was created.
        lastChangeTime: When this collection's definition was last modified, as
            reported by SCCM.
        lastMemberChangeTime: When this collection's membership list was last
            recalculated/updated, as reported by SCCM.
        members: The node IDs of every device or user this collection currently contains.
        SCCMInfra: Always true for a collection node — collections are always part of
            the SCCM infrastructure by definition.
    """
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    collectionID: str | None = field(default=None, kw_only=True)
    collectionType: str | None = field(default=None, kw_only=True)   # "Other"/"User"/"Device"
    memberCount: int | None = field(default=None, kw_only=True)
    comment: str | None = field(default=None, kw_only=True)
    isBuiltIn: bool | None = field(default=None, kw_only=True)
    limitToCollectionID: str | None = field(default=None, kw_only=True)
    limitToCollectionName: str | None = field(default=None, kw_only=True)
    collectionVariablesCount: int | None = field(default=None, kw_only=True)
    rootSiteCode: str | None = field(default=None, kw_only=True)
    sourceSiteCode: str | None = field(default=None, kw_only=True)
    lastChangeTime: str | None = field(default=None, kw_only=True)
    lastMemberChangeTime: str | None = field(default=None, kw_only=True)
    members: list[str] = field(default_factory=list, kw_only=True)
    SCCMInfra: bool = field(default=True, kw_only=True)


@dataclass
class SCCMAdminUserProperties(NodeProperties):
    """An SCCM "admin user" — an AD user or group that has been granted access in the
    SCCM console, together with the roles and collections it's been assigned.

    Attributes:
        collectionSource: Which collection method(s) produced this admin-user record
            (e.g. ``AdminService``, ``WMI``), as a list of tags.
        adminID: The admin user's SCCM internal admin-user ID.
        adminSid: The Active Directory SID of the underlying AD user or group this
            admin-user record represents.
        distinguishedName: The AD distinguished name of the underlying user/group,
            when it could be resolved.
        isGroup: True if this admin-user is an AD group (rather than an individual user).
        accountType: A port-added numeric account-type code (no equivalent CMBP output
            key) captured for completeness; not otherwise interpreted by the collector.
        rootSiteCode: The site code of the top-most site in this admin-user's site
            hierarchy.
        displayName: The admin-user's display name as recorded by SCCM. Admin-user nodes
            emit ONLY this camelCase key (CMBP parity) and deliberately drop the framework
            base lowercase `displayname`: the two differ only by case and would collide as
            a duplicate key for any case-insensitive consumer (BloodHound/Neo4j ingestion,
            the PowerShell unit-test kit). See ``SCCMAdminUser.to_node``.
        sourceSiteCode: The site code of the SCCM site where this admin-user was created.
        createdBy: Who (which account) created this admin-user assignment in SCCM.
        createdDate: When this admin-user assignment was created, as reported by SCCM.
        lastModifiedBy: Who (which account) last modified this admin-user assignment.
        lastModifiedDate: When this admin-user assignment was last modified.
        collectionIds: The SCCM collection IDs this admin-user has been scoped to.
        roleIDs: The SCCM security-role IDs assigned to this admin-user.
        memberOf: The node IDs of the SCCM security roles and/or collections this
            admin-user is a member of, resolved to graph node IDs (as opposed to the
            raw ID lists in `collectionIds`/`roleIDs`).
        SCCMInfra: Always true for an admin-user node — admin-user assignments are
            always part of the SCCM infrastructure by definition.
    """
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    adminID: str | None = field(default=None, kw_only=True)
    adminSid: str | None = field(default=None, kw_only=True)
    distinguishedName: str | None = field(default=None, kw_only=True)
    isGroup: bool | None = field(default=None, kw_only=True)
    accountType: int | None = field(default=None, kw_only=True)  # port-added (no CMBP key)
    rootSiteCode: str | None = field(default=None, kw_only=True)
    # Audit fields from ADMIN_COLUMNS (CMBP parity, Stage 3 C3). displayName is the ONLY display-name
    # key on admin-user nodes: the model sets the base lowercase `displayname` to None (pruned on emit)
    # so the two casings can't collide as a duplicate key for case-insensitive consumers. See
    # sccm_admin_user.py::SCCMAdminUser.to_node.
    displayName: str | None = field(default=None, kw_only=True)
    sourceSiteCode: str | None = field(default=None, kw_only=True)
    createdBy: str | None = field(default=None, kw_only=True)
    createdDate: str | None = field(default=None, kw_only=True)
    lastModifiedBy: str | None = field(default=None, kw_only=True)
    lastModifiedDate: str | None = field(default=None, kw_only=True)
    # Assignment lists: raw role ids, resolved role node ids, resolved collection node ids.
    collectionIds: list[str] = field(default_factory=list, kw_only=True)
    roleIDs: list[str] = field(default_factory=list, kw_only=True)
    memberOf: list[str] = field(default_factory=list, kw_only=True)
    SCCMInfra: bool = field(default=True, kw_only=True)


@dataclass
class SCCMSecurityRoleProperties(NodeProperties):
    """An SCCM security role — a named bundle of permissions (e.g. "Full
    Administrator") that gets granted to admin users.

    Attributes:
        collectionSource: Which collection method(s) produced this role's data (e.g.
            ``AdminService``, ``WMI``), as a list of tags.
        roleID: The role's SCCM internal role ID (e.g. ``SMS0001R`` for Full
            Administrator), uppercased.
        roleName: The role's display name (e.g. ``"Full Administrator"``).
        roleDescription: The free-text description SCCM has for this role.
        isBuiltIn: True if this is one of SCCM's built-in roles rather than one an
            admin created.
        isSecAdminRole: True if this role includes the "Modify folder security scopes"
            or other security-administrator-level permission (marks it as especially
            powerful).
        copiedFromID: The role ID this role was cloned from, if it was created by
            copying an existing role, or null otherwise.
        numberOfAdmins: How many admin users currently hold this role.
        operations: The list of individual permissions/operations this role grants.
        rootSiteCode: The site code of the top-most site in this role's site hierarchy.
        siteCode: The site code of the SCCM site where this role is defined.
        createdBy: Who (which account) created this role.
        createdDate: When this role was created, as reported by SCCM.
        lastModifiedBy: Who (which account) last modified this role.
        lastModifiedDate: When this role was last modified.
        members: The admin users holding this role, each written as
            ``"<upper-cased logon name>@<root site code>"``.
        SCCMInfra: Always true for a security-role node — roles are always part of the
            SCCM infrastructure by definition.
    """
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    roleID: str | None = field(default=None, kw_only=True)
    roleName: str | None = field(default=None, kw_only=True)
    roleDescription: str | None = field(default=None, kw_only=True)
    isBuiltIn: bool | None = field(default=None, kw_only=True)
    isSecAdminRole: bool | None = field(default=None, kw_only=True)
    copiedFromID: str | None = field(default=None, kw_only=True)
    numberOfAdmins: int | None = field(default=None, kw_only=True)
    operations: list[str] = field(default_factory=list, kw_only=True)
    rootSiteCode: str | None = field(default=None, kw_only=True)
    # Audit fields from ROLE_COLUMNS (CMBP parity, Stage 3 C2).
    siteCode: str | None = field(default=None, kw_only=True)
    createdBy: str | None = field(default=None, kw_only=True)
    createdDate: str | None = field(default=None, kw_only=True)
    lastModifiedBy: str | None = field(default=None, kw_only=True)
    lastModifiedDate: str | None = field(default=None, kw_only=True)
    # Members: upper(logon_name)@root for each admin assigned to this role.
    members: list[str] = field(default_factory=list, kw_only=True)
    SCCMInfra: bool = field(default=True, kw_only=True)


@dataclass
class SCCMClientDeviceProperties(NodeProperties):
    """An SCCM-managed device — a Windows machine that SCCM knows about as a client,
    identified by its "SMS unique identifier" rather than its AD SID.

    Attributes:
        collectionSource: Which collection method(s) produced this device's data (e.g.
            ``AdminService``, ``WMI``), as a list of tags.
        SMSID: The device's SMS unique identifier (its ID inside SCCM), uppercased.
        resourceID: The device's SCCM internal "ResourceID" number, as a string.
        siteCode: The site code of the SCCM site that manages this device.
        deviceOS: The operating system SCCM reports this device is running.
        deviceOSBuild: The OS build number/string SCCM reports for this device.
        isVirtualMachine: True if SCCM reports this device is a virtual machine.
        coManaged: True if this device is co-managed (jointly managed by SCCM and
            Microsoft Intune).
        AADDeviceID: The device's Entra ID (Azure AD) device object ID, if it's
            registered there.
        AADTenantID: The Entra ID (Azure AD) tenant this device is registered to.
        lastReportedMPServerName: The name of the last SCCM Management Point this
            device checked in with.
        primaryUser: The name of the user configured as this device's "primary user"
            in SCCM (used for user-centric app deployment and reporting).
        currentLogonUser: The name of the user SCCM last saw logged on to this device.
        ADLastLogonUser: The name of the user Active Directory's `lastLogon`/
            `lastLogonTimestamp` attributes show most recently signed in to the
            underlying AD computer object.
        rootSiteCode: The site code of the top-most site in this device's site
            hierarchy.
        is_confirmed_active_client: A port-added field (no CMBP output key, and
            deliberately kept in snake_case rather than converted to CMBP casing).
            True when the device was confirmed as a real, currently-managed SCCM
            client (seen via AdminService or WMI, and not marked obsolete); False when
            the device was only inferred to be an SCCM client because it published a
            Remote Control Kerberos SPN, without independent confirmation.
        ADDomainSID: The Active Directory SID of this device, when known.
        ADLastLogonTime: The timestamp of the AD last-logon event referenced by
            `ADLastLogonUser`.
        ADLastLogonUserDomain: The AD domain of the user in `ADLastLogonUser`.
        sourceSiteCode: The site code of the SCCM site where this device record
            originated.
        lastActiveTime: The last time SCCM saw any activity from this device.
        lastOnlineTime: The last time SCCM saw this device come online.
        lastOfflineTime: The last time SCCM saw this device go offline.
        primaryUserSID: The resolved AD SID of the user named in `primaryUser`.
        currentLogonUserSID: The resolved AD SID of the user named in `currentLogonUser`.
        ADLastLogonUserSID: The resolved AD SID of the user named in `ADLastLogonUser`.
        lastReportedMPServerSID: The resolved AD SID of the Management Point computer
            named in `lastReportedMPServerName`.
        collectionIds: The SCCM collection IDs this device is a member of.
        collectionNames: The names of the collections identified by `collectionIds`.
        SCCMInfra: True if this device is itself part of the SCCM infrastructure
            (rare for a client device; usually False).
        currentManagementPoint: The name of the Management Point this device currently
            uses, from AdminService/WMI or (for the collector's own host) Local SMS_Authority.
        currentManagementPointSID: The resolved AD SID of the computer named in
            `currentManagementPoint`.
        previousSMSID: This device's previous SMS unique identifier, if SCCM re-issued it
            a new one (Local-only; CCM_Client's `PreviousClientId`).
        previousSMSIDChangeDate: The timestamp SCCM recorded when `previousSMSID` changed to
            the current `SMSID` (Local-only; CCM_Client's `ClientIdChangeDate`).
        userName: The name of the user Active Directory's `lastLogon`/`lastLogonTimestamp`
            attributes show most recently signed in to this device. Mirrors `ADLastLogonUser`
            -- CMBP emits the same collected value under both output keys.
        userDomainName: The AD domain of the user in `userName`. Mirrors `ADLastLogonUserDomain`.
        CN: The AD `cn` (Common Name) attribute of the underlying AD computer (joined
            via `ADDomainSID`), or null if that computer was never resolved against AD.
        DNSHostName: The fully-qualified DNS name of the underlying AD computer, as
            recorded in Active Directory, or null if never resolved.
        distinguishedName: The Active Directory distinguished name of the underlying
            computer (its full path in the AD tree), or null if never resolved.
        domain: The AD domain of the underlying computer, or null if never resolved.
            Lowercase `domain` (not `Domain`) to match CMBP's SCCM_ClientDevice output
            verbatim -- unlike Computer/User/Group, CMBP does not capitalize this key
            here.
        objectClass: The AD `objectClass` attribute values of the underlying computer,
            or null if never resolved.
        samAccountName: The pre-Windows-2000 logon name of the underlying computer
            (e.g. ``COMPUTER1$``), or null if never resolved.
        servicePrincipalName: The Kerberos Service Principal Names published on the
            underlying computer's AD account, or null if never resolved.
    """
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    SMSID: str | None = field(default=None, kw_only=True)
    resourceID: str | None = field(default=None, kw_only=True)
    siteCode: str | None = field(default=None, kw_only=True)
    deviceOS: str | None = field(default=None, kw_only=True)
    deviceOSBuild: str | None = field(default=None, kw_only=True)
    isVirtualMachine: bool | None = field(default=None, kw_only=True)
    coManaged: bool | None = field(default=None, kw_only=True)
    AADDeviceID: str | None = field(default=None, kw_only=True)
    AADTenantID: str | None = field(default=None, kw_only=True)
    lastReportedMPServerName: str | None = field(default=None, kw_only=True)
    primaryUser: str | None = field(default=None, kw_only=True)
    currentLogonUser: str | None = field(default=None, kw_only=True)
    ADLastLogonUser: str | None = field(default=None, kw_only=True)
    rootSiteCode: str | None = field(default=None, kw_only=True)
    is_confirmed_active_client: bool = field(default=False, kw_only=True)  # port-added (no CMBP key): real SCCM client vs SPN-inferred
    ADDomainSID: str | None = field(default=None, kw_only=True)
    # Telemetry scalars — Stage 3 C4 (CMBP parity).
    ADLastLogonTime: str | None = field(default=None, kw_only=True)
    ADLastLogonUserDomain: str | None = field(default=None, kw_only=True)
    sourceSiteCode: str | None = field(default=None, kw_only=True)
    lastActiveTime: str | None = field(default=None, kw_only=True)
    lastOnlineTime: str | None = field(default=None, kw_only=True)
    lastOfflineTime: str | None = field(default=None, kw_only=True)
    # Resolved SID fields — Stage 3 C4 (CMBP ps1:7227/7232/7245/7248).
    primaryUserSID: str | None = field(default=None, kw_only=True)
    currentLogonUserSID: str | None = field(default=None, kw_only=True)
    ADLastLogonUserSID: str | None = field(default=None, kw_only=True)
    lastReportedMPServerSID: str | None = field(default=None, kw_only=True)
    # Collection membership lists — Stage 3 C4 (CMBP ps1:7228-7229).
    collectionIds: list[str] = field(default_factory=list, kw_only=True)
    collectionNames: list[str] = field(default_factory=list, kw_only=True)
    SCCMInfra: bool = field(default=False, kw_only=True)
    # Telemetry extras — Task B3 (CMBP ps1:4010-4011/4016-4017/7233-7234/7253-7254).
    currentManagementPoint: str | None = field(default=None, kw_only=True)
    currentManagementPointSID: str | None = field(default=None, kw_only=True)
    previousSMSID: str | None = field(default=None, kw_only=True)
    previousSMSIDChangeDate: str | None = field(default=None, kw_only=True)
    userName: str | None = field(default=None, kw_only=True)
    userDomainName: str | None = field(default=None, kw_only=True)
    # AD attributes of the underlying computer, joined in via ADDomainSID (ope-fb99).
    CN: str | None = field(default=None, kw_only=True)
    DNSHostName: str | None = field(default=None, kw_only=True)
    distinguishedName: str | None = field(default=None, kw_only=True)
    domain: str | None = field(default=None, kw_only=True)
    objectClass: list[str] | None = field(default=None, kw_only=True)
    samAccountName: str | None = field(default=None, kw_only=True)
    servicePrincipalName: list[str] | None = field(default=None, kw_only=True)


# ----------------------------------------------------------------------------
# MSSQL node properties (Stage 5). Field names mirror ConfigManBearPig.ps1's
# Add-MSSQLServerNodesAndEdges / Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer
# Upsert-Node calls verbatim. `environmentid` is the AD-domain SID of the SQL host
# (spec §2). `strictEncryption` / `instanceNames` are port-added (no CMBP key).
# ----------------------------------------------------------------------------
@dataclass
class MSSQLServerProperties(NodeProperties):
    """A SQL Server instance discovered on an SCCM-related host (a site database
    server, or a computer with sysadmin rights on some other SQL instance).

    Attributes:
        collectionSource: Which collection method(s) produced this server's data
            (e.g. ``SQL``, ``WMI``), as a list of tags.
        dnsHostName: The fully-qualified DNS name of the computer hosting this SQL
            Server instance.
        SQLServicePort: The TCP port this SQL Server instance listens on.
        SCCMInfra: True if this SQL Server backs an SCCM site database.
        SCCMSite: The site code of the SCCM site this server belongs to, if it hosts
            a site database.
        databases: The node IDs of every `MSSQL_Database` hosted on this server.
        forceEncryption: Whether this SQL Server instance is configured to force
            encryption on all client connections, or null if not collected.
        extendedProtection: This instance's "Extended Protection for Authentication"
            setting as collected (a setting that hardens against certain relay
            attacks), or null if not collected.
        SQLServiceAccountDomainSID: The full Active Directory SID of the account the
            SQL Server service runs as.
        SQLServiceAccountName: The logon name of the account the SQL Server service
            runs as.
        strictEncryption: A port-added field (no CMBP output key) recording whether
            this instance uses SQL Server's newer "Strict" TLS encryption mode
            (distinct from the older `forceEncryption` setting), or null if not
            collected.
        instanceNames: A port-added field (no CMBP output key) listing every named SQL
            Server instance found on this host (a single computer can run more than
            one SQL Server instance side by side).
        assumed: True when this server was only ever resolved as an SCCM site
            database through the SPN+SCCM inference (D2b/D3), never confirmed by
            RemoteRegistry/AdminService/WMI; omitted (null, pruned) otherwise.
        assumptionBasis: Human-readable explanation of the inference, present only
            when `assumed` is true.
    """
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    dnsHostName: str | None = field(default=None, kw_only=True)
    SQLServicePort: str | None = field(default=None, kw_only=True)
    SCCMInfra: bool = field(default=False, kw_only=True)
    SCCMSite: str | None = field(default=None, kw_only=True)
    databases: list[str] = field(default_factory=list, kw_only=True)
    forceEncryption: bool | None = field(default=None, kw_only=True)
    extendedProtection: str | None = field(default=None, kw_only=True)
    SQLServiceAccountDomainSID: str | None = field(default=None, kw_only=True)
    SQLServiceAccountName: str | None = field(default=None, kw_only=True)
    # port-added (no CMBP key)
    strictEncryption: bool | None = field(default=None, kw_only=True)
    instanceNames: list[str] = field(default_factory=list, kw_only=True)
    assumed: bool | None = field(default=None, kw_only=True)
    assumptionBasis: str | None = field(default=None, kw_only=True)


@dataclass
class MSSQLDatabaseProperties(NodeProperties):
    """A database hosted on an `MSSQL_Server`.

    Attributes:
        collectionSource: Which collection method(s) produced this database's data
            (e.g. ``SQL``), as a list of tags.
        isTrustworthy: Whether the database's TRUSTWORTHY setting is on, which (when
            combined with certain permissions) can let a database owner escalate to
            control of the whole SQL Server instance. Always emitted as true here
            because the collector only records databases reachable through a path
            that already requires it, matching CMBP's behavior.
        SCCMInfra: Always true for a database node — every database this collector
            records is part of the SCCM infrastructure by definition (either the site
            database itself or one reached via an SCCM-managed sysadmin path).
        SCCMSite: The site code of the SCCM site this database belongs to, if any.
        SQLServer: The node ID of the `MSSQL_Server` this database is hosted on.
        assumed: True when this database rests on the SPN+SCCM inference rather than
            a confirmed site database (D2b/D3); omitted (null, pruned) otherwise.
        assumptionBasis: Human-readable explanation of the inference, present only
            when `assumed` is true.
    """
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    isTrustworthy: bool = field(default=True, kw_only=True)
    SCCMInfra: bool = field(default=True, kw_only=True)
    SCCMSite: str | None = field(default=None, kw_only=True)
    SQLServer: str | None = field(default=None, kw_only=True)
    assumed: bool | None = field(default=None, kw_only=True)
    assumptionBasis: str | None = field(default=None, kw_only=True)


@dataclass
class MSSQLServerRoleProperties(NodeProperties):
    """A server-level SQL Server role (e.g. ``sysadmin``) on an `MSSQL_Server`.

    Attributes:
        collectionSource: Which collection method(s) produced this role's data (e.g.
            ``SQL``), as a list of tags.
        isFixedRole: True if this is one of SQL Server's built-in fixed server roles
            (like ``sysadmin``) rather than a custom one an admin created. Only
            fixed roles are collected today, so this is always true.
        members: The node IDs of every `MSSQL_Login` that is a member of this role.
        SCCMSite: The site code of the SCCM site this role's server belongs to, if any.
        SQLServer: The node ID of the `MSSQL_Server` this role is defined on.
        assumed: True when this role's server rests on the SPN+SCCM inference (D2b/D3);
            omitted (null, pruned) otherwise.
        assumptionBasis: Human-readable explanation of the inference, present only
            when `assumed` is true.
    """
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    isFixedRole: bool = field(default=True, kw_only=True)
    members: list[str] = field(default_factory=list, kw_only=True)
    SCCMSite: str | None = field(default=None, kw_only=True)
    SQLServer: str | None = field(default=None, kw_only=True)
    assumed: bool | None = field(default=None, kw_only=True)
    assumptionBasis: str | None = field(default=None, kw_only=True)


@dataclass
class MSSQLDatabaseRoleProperties(NodeProperties):
    """A database-level SQL Server role (e.g. ``db_owner``) on an `MSSQL_Database`.

    Attributes:
        collectionSource: Which collection method(s) produced this role's data (e.g.
            ``SQL``), as a list of tags.
        database: The node ID of the `MSSQL_Database` this role is defined on.
        isFixedRole: True if this is one of SQL Server's built-in fixed database
            roles (like ``db_owner``) rather than a custom one an admin created. Only
            fixed roles are collected today, so this is always true.
        members: The node IDs of every `MSSQL_DatabaseUser` that is a member of this
            role.
        SCCMSite: The site code of the SCCM site this role's database belongs to,
            if any.
        SQLServer: The node ID of the `MSSQL_Server` hosting this role's database.
        assumed: True when this role's database rests on the SPN+SCCM inference
            (D2b/D3); omitted (null, pruned) otherwise.
        assumptionBasis: Human-readable explanation of the inference, present only
            when `assumed` is true.
    """
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    database: str | None = field(default=None, kw_only=True)
    isFixedRole: bool = field(default=True, kw_only=True)
    members: list[str] = field(default_factory=list, kw_only=True)
    SCCMSite: str | None = field(default=None, kw_only=True)
    SQLServer: str | None = field(default=None, kw_only=True)
    assumed: bool | None = field(default=None, kw_only=True)
    assumptionBasis: str | None = field(default=None, kw_only=True)


@dataclass
class MSSQLLoginProperties(NodeProperties):
    """A server-level login (an account that can connect to an `MSSQL_Server`).

    Attributes:
        collectionSource: Which collection method(s) produced this login's data (e.g.
            ``SQL``), as a list of tags.
        loginType: The kind of login this is. Always ``"Windows"`` today — only
            Windows-authenticated logins (mapped to an AD user or computer) are
            collected, not native SQL logins.
        memberOfRoles: The server-role membership key(s) this login holds, written as
            ``"sysadmin@<server node id>"`` for each server role it belongs to.
        SCCMInfra: Always true for a login node — every login this collector records
            belongs to a server reached through SCCM/AD, so it's treated as part of
            the SCCM infrastructure.
        SCCMSite: The site code of the SCCM site this login's server belongs to, if any.
        SQLServer: The node ID of the `MSSQL_Server` this login can authenticate to.
        assumed: True when this login's server rests on the SPN+SCCM inference
            (D2b/D3); omitted (null, pruned) otherwise.
        assumptionBasis: Human-readable explanation of the inference, present only
            when `assumed` is true.
    """
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    loginType: str | None = field(default=None, kw_only=True)
    memberOfRoles: list[str] = field(default_factory=list, kw_only=True)
    SCCMInfra: bool = field(default=True, kw_only=True)
    SCCMSite: str | None = field(default=None, kw_only=True)
    SQLServer: str | None = field(default=None, kw_only=True)
    assumed: bool | None = field(default=None, kw_only=True)
    assumptionBasis: str | None = field(default=None, kw_only=True)


@dataclass
class MSSQLDatabaseUserProperties(NodeProperties):
    """A database-level user (a login's identity inside one specific database).

    Attributes:
        collectionSource: Which collection method(s) produced this database-user's
            data (e.g. ``SQL``), as a list of tags.
        database: The node ID of the `MSSQL_Database` this user exists in.
        login: The node ID of the server-level `MSSQL_Login` this database user is
            mapped to.
        memberOfRoles: The database-role membership key(s) this user holds, written as
            ``"db_owner@<database node id>"`` for each database role it belongs to.
        SCCMInfra: Always true for a database-user node — every database user this
            collector records belongs to a database reached through SCCM/AD, so it's
            treated as part of the SCCM infrastructure.
        SCCMSite: The site code of the SCCM site this database user's database
            belongs to, if any.
        SQLServer: The node ID of the `MSSQL_Server` hosting this database user's
            database.
        assumed: True when this database user's database rests on the SPN+SCCM
            inference (D2b/D3); omitted (null, pruned) otherwise.
        assumptionBasis: Human-readable explanation of the inference, present only
            when `assumed` is true.
    """
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    database: str | None = field(default=None, kw_only=True)
    login: str | None = field(default=None, kw_only=True)
    memberOfRoles: list[str] = field(default_factory=list, kw_only=True)
    SCCMInfra: bool = field(default=True, kw_only=True)
    SCCMSite: str | None = field(default=None, kw_only=True)
    SQLServer: str | None = field(default=None, kw_only=True)
    assumed: bool | None = field(default=None, kw_only=True)
    assumptionBasis: str | None = field(default=None, kw_only=True)
