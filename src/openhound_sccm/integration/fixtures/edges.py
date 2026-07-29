"""mayyhem.com lab expected-edge fixtures, ported from Invoke-ConfigManBearPigUnitTests
(renamed copy). New SCCM_/MSSQL_ kind names; one EdgeCase per PS $ExpectedEdges entry.

Field mapping (see sccm/sccm/.sdd/briefs/ittest-task8.md):
  id          <- synthesized stable kebab "edge-<kind-suffix>-<discriminator>"
  kind        <- Kind
  description <- Description
  source/target <- Source/Target -> NodePattern(kinds=Kinds, properties=Properties)
  properties  <- edge-level Properties hashtable
  count       <- CountSpec(exact=Count) when Count is set, else None
  negative/reason <- Negative/Reason when present

Entries that have no Source/Target/Count/Properties in the PS kit are left
constraint-less on purpose (the PS kit skips them for the same reason).
"""
from __future__ import annotations

from openhound_collector_common.integration_testing.cases import CountSpec, EdgeCase, NodePattern

from openhound_sccm.integration.fixtures import SCCMEdgeCase

# Every *-S-1-5-11 source in the PS kit is the "Authenticated Users" domain-local group.
_AUTH_USERS = NodePattern(kinds=["Group", "Base"], properties={"id": "*-S-1-5-11"})

MAYYHEM_EDGE_CASES: list[EdgeCase] = [

    ######################################################################################################
    # SCCM_LocalAdminRequired (AdminTo, temporarily LocalAdminRequired pending OpenGraph post-processing)
    ######################################################################################################
    EdgeCase(
        id="edge-localadminrequired-cas-pss-to-cas-db",
        kind="SCCM_LocalAdminRequired",
        description="The CAS primary site server has local administrator rights on the CAS site database server",
        source=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "cas-pss.mayyhem.com"}),
        target=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "cas-db.mayyhem.com"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-localadminrequired-cas-pss-to-cas-scp",
        kind="SCCM_LocalAdminRequired",
        description="The CAS primary site server has local administrator rights on the service connection point server",
        source=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "cas-pss.mayyhem.com"}),
        target=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "cas-scp.mayyhem.com"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-localadminrequired-ps1-pss-to-ps1-db",
        kind="SCCM_LocalAdminRequired",
        description="The PS1 primary site server has local administrator rights on the site database server",
        source=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps1-pss.mayyhem.com"}),
        target=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps1-db.mayyhem.com"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-localadminrequired-ps1-pss-to-ps1-sms",
        kind="SCCM_LocalAdminRequired",
        description="The PS1 primary site server has local administrator rights on the SMS Provider server",
        source=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps1-pss.mayyhem.com"}),
        target=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps1-sms.mayyhem.com"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-localadminrequired-ps1-pss-to-ps1-mp",
        kind="SCCM_LocalAdminRequired",
        description="The PS1 primary site server has local administrator rights on the management point server",
        source=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps1-pss.mayyhem.com"}),
        target=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps1-mp.mayyhem.com"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-localadminrequired-ps1-pss-to-ps1-dp",
        kind="SCCM_LocalAdminRequired",
        description="The PS1 primary site server has local administrator rights on the distribution point server",
        source=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps1-pss.mayyhem.com"}),
        target=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps1-dp.mayyhem.com"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-localadminrequired-ps1-pss-to-ps1-psv",
        kind="SCCM_LocalAdminRequired",
        description="The PS1 primary site server has local administrator rights on the passive site server",
        source=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps1-pss.mayyhem.com"}),
        target=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps1-psv.mayyhem.com"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-localadminrequired-ps1-psv-to-ps1-pss",
        kind="SCCM_LocalAdminRequired",
        description="The PS1 passive site server has local administrator rights on the primary site server",
        source=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps1-psv.mayyhem.com"}),
        target=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps1-pss.mayyhem.com"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-localadminrequired-negative-ps2-pss-to-ps1-db",
        kind="SCCM_LocalAdminRequired",
        description="The PS2 primary site server does not have local administrator rights on the PS1 site database server",
        source=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps2-pss.mayyhem.com"}),
        target=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps1-db.mayyhem.com"}),
        negative=True,
    ),

    ################################
    # SCCM_CoerceAndRelayToAdminService
    ################################
    EdgeCase(
        id="edge-coerceandrelaytoadminservice-ps1",
        kind="SCCM_CoerceAndRelayToAdminService",
        description=(
            "Authenticated Users group can coerce the PS1 primary site server and relay authentication to the "
            "AdminService on the PS1 SMS Provider, coerce the PS1 primary site server and relay authentication "
            "to the AdminService on the PS1 passive site server, coerce the PS1 passive site server and relay "
            "authentication to the AdminService on the PS1 primary site server, and coerce the PS1 passive site "
            "server and relay authentication to the AdminService on the PS1 SMS Provider"
        ),
        source=_AUTH_USERS,
        target=NodePattern(kinds=["SCCM_Site"], properties={"id": "PS1"}),
        properties={
            "coercionVictimAndRelayTargetPairs": [
                "Coerce ps1-psv.mayyhem.com, relay to ps1-pss.mayyhem.com",
                "Coerce ps1-pss.mayyhem.com, relay to ps1-psv.mayyhem.com",
                "Coerce ps1-pss.mayyhem.com, relay to ps1-sms.mayyhem.com",
                "Coerce ps1-psv.mayyhem.com, relay to ps1-sms.mayyhem.com",
            ],
        },
        count=CountSpec(exact=1),
    ),

    #########################
    # MSSQL_CoerceAndRelayToMSSQL
    #########################
    EdgeCase(
        id="edge-coerceandrelaytomssql-cas",
        kind="MSSQL_CoerceAndRelayToMSSQL",
        description="Authenticated Users group can coerce and relay authentication to the MSSQL service on the CAS site database server",
        source=_AUTH_USERS,
        target=NodePattern(kinds=["MSSQL_Login"], properties={"id": "MAYYHEM\\CAS-PSS$@*:1433"}),
        properties={"coercionVictimAndRelayTargetPairs": ["Coerce cas-pss.mayyhem.com, relay to cas-db.mayyhem.com:1433"]},
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-coerceandrelaytomssql-ps1-pss",
        kind="MSSQL_CoerceAndRelayToMSSQL",
        description="Authenticated Users group can coerce and relay authentication to the MSSQL service on the PS1 site database server",
        source=_AUTH_USERS,
        target=NodePattern(kinds=["MSSQL_Login"], properties={"id": "MAYYHEM\\PS1-PSS$@*:1433"}),
        properties={"coercionVictimAndRelayTargetPairs": ["Coerce ps1-pss.mayyhem.com, relay to ps1-db.mayyhem.com:1433"]},
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-coerceandrelaytomssql-ps1-sms",
        kind="MSSQL_CoerceAndRelayToMSSQL",
        description="Authenticated Users group can coerce and relay authentication to the MSSQL service on the PS1 site database server",
        source=_AUTH_USERS,
        target=NodePattern(kinds=["MSSQL_Login"], properties={"id": "MAYYHEM\\PS1-SMS$@*:1433"}),
        properties={"coercionVictimAndRelayTargetPairs": ["Coerce ps1-sms.mayyhem.com, relay to ps1-db.mayyhem.com:1433"]},
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-coerceandrelaytomssql-ps1-psv",
        kind="MSSQL_CoerceAndRelayToMSSQL",
        description="Authenticated Users group can coerce and relay authentication to the MSSQL service on the PS1 site database server",
        source=_AUTH_USERS,
        target=NodePattern(kinds=["MSSQL_Login"], properties={"id": "MAYYHEM\\PS1-PSV$@*:1433"}),
        properties={"coercionVictimAndRelayTargetPairs": ["Coerce ps1-psv.mayyhem.com, relay to ps1-db.mayyhem.com:1433"]},
        count=CountSpec(exact=1),
    ),

    ###########################
    # SCCM_CoerceAndRelayToSMB
    ###########################
    EdgeCase(
        id="edge-coerceandrelaytosmb-ps1-sms",
        kind="SCCM_CoerceAndRelayToSMB",
        description="Authenticated Users group can coerce and relay authentication to the SMB service on the PS1 SMS Provider",
        source=_AUTH_USERS,
        target=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps1-sms.mayyhem.com"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-coerceandrelaytosmb-ps1-db",
        kind="SCCM_CoerceAndRelayToSMB",
        description="Authenticated Users group can coerce and relay authentication to the SMB service on the PS1 site database server",
        source=_AUTH_USERS,
        target=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps1-db.mayyhem.com"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-coerceandrelaytosmb-ps1-pss",
        kind="SCCM_CoerceAndRelayToSMB",
        description="Authenticated Users group can coerce and relay authentication to the SMB service on the PS1 primary site server",
        source=_AUTH_USERS,
        target=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps1-pss.mayyhem.com"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-coerceandrelaytosmb-ps1-psv",
        kind="SCCM_CoerceAndRelayToSMB",
        description="Authenticated Users group can coerce and relay authentication to the SMB service on the PS1 passive site server",
        source=_AUTH_USERS,
        target=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps1-psv.mayyhem.com"}),
        count=CountSpec(exact=1),
    ),

    ##############
    # HasSession #
    ##############
    EdgeCase(
        id="edge-hassession-cas-db",
        kind="HasSession",
        description="The MSSQL service account has an active session on the CAS site database server",
        source=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "cas-db.mayyhem.com"}),
        target=NodePattern(kinds=["User", "Base"], properties={"samAccountName": "sqlsccmsvc", "id": "S-1-5-21-*"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-hassession-ps1-db",
        kind="HasSession",
        description="The MSSQL service account has an active session on the PS1 site database server",
        source=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps1-db.mayyhem.com"}),
        target=NodePattern(kinds=["User", "Base"], properties={"samAccountName": "sqlsccmsvc", "id": "S-1-5-21-*"}),
        count=CountSpec(exact=1),
    ),

    ##################
    # MSSQL_Contains #
    ##################
    EdgeCase(
        id="edge-contains-cas-server-cm-cas-database",
        kind="MSSQL_Contains",
        description="The CAS site database MSSQL server contains the CM_<SiteCode> database",
        source=NodePattern(kinds=["MSSQL_Server"], properties={"id": "*:1433"}),
        target=NodePattern(kinds=["MSSQL_Database"], properties={"name": "CM_CAS"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-contains-cas-server-cas-pss-login",
        kind="MSSQL_Contains",
        description="The CAS site database MSSQL server contains the CAS-PSS$ login",
        source=NodePattern(kinds=["MSSQL_Server"], properties={"id": "*:1433", "name": "CAS-DB*"}),
        target=NodePattern(kinds=["MSSQL_Login"], properties={"id": "*cas-pss$@*:1433"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-contains-cas-database-db-owner-role",
        kind="MSSQL_Contains",
        description="The CAS site database contains the db_owner database role",
        source=NodePattern(kinds=["MSSQL_Database"], properties={"id": "*:1433\\CM_CAS"}),
        target=NodePattern(kinds=["MSSQL_DatabaseRole"], properties={"id": "db_owner@*:1433\\CM_CAS"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-contains-cas-database-cas-pss-user",
        kind="MSSQL_Contains",
        description="The CAS site database contains the CAS-PSS$ user",
        source=NodePattern(kinds=["MSSQL_Database"], properties={"id": "*:1433\\CM_CAS"}),
        target=NodePattern(kinds=["MSSQL_DatabaseUser"], properties={"id": "*cas-pss$@*:1433\\CM_CAS"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-contains-ps1-server-cm-ps1-database",
        kind="MSSQL_Contains",
        description="The PS1 site database MSSQL server contains the CM_<SiteCode> database",
        source=NodePattern(kinds=["MSSQL_Server"], properties={"id": "*:1433"}),
        target=NodePattern(kinds=["MSSQL_Database"], properties={"name": "CM_PS1"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-contains-ps1-server-ps1-pss-login",
        kind="MSSQL_Contains",
        description="The PS1 site database MSSQL server contains the PS1-PSS$ login",
        source=NodePattern(kinds=["MSSQL_Server"], properties={"id": "*:1433"}),
        target=NodePattern(kinds=["MSSQL_Login"], properties={"id": "*ps1-pss$@*:1433"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-contains-ps1-database-db-owner-role",
        kind="MSSQL_Contains",
        description="The PS1 site database contains the db_owner database role",
        source=NodePattern(kinds=["MSSQL_Database"], properties={"id": "*:1433\\CM_PS1"}),
        target=NodePattern(kinds=["MSSQL_DatabaseRole"], properties={"id": "db_owner@*:1433\\CM_PS1"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-contains-ps1-database-ps1-pss-user",
        kind="MSSQL_Contains",
        description="The PS1 site database contains the PS1-PSS$ user",
        source=NodePattern(kinds=["MSSQL_Database"], properties={"id": "*:1433\\CM_PS1"}),
        target=NodePattern(kinds=["MSSQL_DatabaseUser"], properties={"id": "*ps1-pss$@*:1433\\CM_PS1"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-contains-servers-sysadmin-role",
        kind="MSSQL_Contains",
        description="The MSSQL servers (cas-db, ps1-db, and ps1-psv) contain the sysadmin server role",
        source=NodePattern(kinds=["MSSQL_Server"], properties={"id": "*:1433"}),
        target=NodePattern(kinds=["MSSQL_ServerRole"], properties={"id": "sysadmin@*:1433"}),
        count=CountSpec(exact=3),
    ),

    ###################
    # MSSQL_ControlDB #
    ###################
    EdgeCase(
        id="edge-controldb-db-owner-site-databases",
        kind="MSSQL_ControlDB",
        description="The db_owner MSSQL database role controls the site database on cas-db and ps1-db",
        source=NodePattern(kinds=["MSSQL_DatabaseRole"], properties={"id": "db_owner@*:1433\\CM_*"}),
        target=NodePattern(kinds=["MSSQL_Database"], properties={"id": "*:1433\\CM_*"}),
        count=CountSpec(exact=2),
    ),

    #######################
    # MSSQL_ControlServer #
    #######################
    EdgeCase(
        id="edge-controlserver-sysadmin-server-instances",
        kind="MSSQL_ControlServer",
        description="The sysadmin MSSQL server role controls the server instance on cas-db, ps1-db, and ps1-psv",
        source=NodePattern(kinds=["MSSQL_ServerRole"], properties={"id": "sysadmin@*:1433"}),
        target=NodePattern(kinds=["MSSQL_Server"], properties={"id": "*:1433"}),
        count=CountSpec(exact=3),
    ),

    #######################
    # MSSQL_ExecuteOnHost #
    #######################
    EdgeCase(
        id="edge-executeonhost-servers-hosts",
        kind="MSSQL_ExecuteOnHost",
        description="The MSSQL servers (cas-db, ps1-db, and ps1-psv) can execute commands on their hosts",
        source=NodePattern(kinds=["MSSQL_Server"], properties={"id": "*:1433"}),
        target=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*"}),
        count=CountSpec(exact=3),
    ),

    #####################
    # MSSQL_GetAdminTGS #
    #####################
    EdgeCase(
        id="edge-getadmintgs-service-account-server-instance",
        kind="MSSQL_GetAdminTGS",
        description="The site database MSSQL service account can request a TGS for any domain login on the server instance",
        source=NodePattern(kinds=["User", "Base"], properties={"samAccountName": "sqlsccmsvc", "id": "S-1-5-21-*"}),
        target=NodePattern(kinds=["MSSQL_Server"], properties={"id": "*:1433"}),
        count=CountSpec(exact=2),
    ),

    ################
    # MSSQL_GetTGS #
    ################
    EdgeCase(
        id="edge-gettgs-service-account-logins",
        kind="MSSQL_GetTGS",
        description=(
            "The site database MSSQL service account can request a TGS for any domain login on the server "
            "instance (CAS-PSS, PS1-PSS, PS1-PSV, and PS1-SMS)"
        ),
        source=NodePattern(kinds=["User", "Base"], properties={"samAccountName": "sqlsccmsvc", "id": "S-1-5-21-*"}),
        target=NodePattern(kinds=["MSSQL_Login"], properties={"id": "*$@*:1433"}),
        count=CountSpec(exact=4),
    ),

    ##################
    # MSSQL_HasLogin #
    ##################
    EdgeCase(
        id="edge-haslogin-computers-logins",
        kind="MSSQL_HasLogin",
        description=(
            "The primary and passive site server and SMS Provider computers have logins on the MSSQL server "
            "instances (CAS-PSS -> CAS-DB, PS1-PSS -> PS1-DB, PS1-SMS -> PS1-DB, PS1-PSV -> PS1-DB)"
        ),
        source=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*"}),
        target=NodePattern(kinds=["MSSQL_Login"], properties={"id": "*$@*:1433"}),
        count=CountSpec(exact=4),
    ),

    #################
    # MSSQL_HostFor #
    #################
    EdgeCase(
        id="edge-hostfor-servers-computers",
        kind="MSSQL_HostFor",
        description="The MSSQL server computers (cas-db, ps1-db, and ps1-psv) host the MSSQL server instances",
        source=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*"}),
        target=NodePattern(kinds=["MSSQL_Server"], properties={"id": "*:1433"}),
        count=CountSpec(exact=3),
    ),

    ####################
    # MSSQL_IsMappedTo #
    ####################
    EdgeCase(
        id="edge-ismappedto-mssql-logins-dbusers",
        kind="MSSQL_IsMappedTo",
        description=(
            "The primary and passive site server and SMS Provider MSSQL server logins (CAS-PSS, PS1-PSS, "
            "PS1-PSV, and PS1-SMS) are mapped to database users in the site databases"
        ),
        source=NodePattern(kinds=["MSSQL_Login"], properties={"id": "*$@*:1433"}),
        target=NodePattern(kinds=["MSSQL_DatabaseUser"], properties={"id": "*$@*:1433\\CM_*"}),
        count=CountSpec(exact=4),
    ),

    ##################
    # MSSQL_MemberOf #
    ##################
    EdgeCase(
        id="edge-memberof-dbusers-db-owner-role",
        kind="MSSQL_MemberOf",
        description=(
            "The primary and passive site server and SMS Provider MSSQL database users (CAS-PSS, PS1-PSS, "
            "PS1-PSV, and PS1-SMS) are members of the db_owner database role in the site databases"
        ),
        source=NodePattern(kinds=["MSSQL_DatabaseUser"], properties={"id": "*$@*:1433\\CM_*"}),
        target=NodePattern(kinds=["MSSQL_DatabaseRole"], properties={"id": "db_owner@*:1433\\CM_*"}),
        count=CountSpec(exact=4),
    ),
    EdgeCase(
        id="edge-memberof-logins-sysadmin-role",
        kind="MSSQL_MemberOf",
        description=(
            "The primary and passive site server and SMS Provider MSSQL server logins (CAS-PSS, PS1-PSS, "
            "PS1-PSV, and PS1-SMS) are members of the sysadmin server role on the MSSQL server instances"
        ),
        source=NodePattern(kinds=["MSSQL_Login"], properties={"id": "*$@*:1433"}),
        target=NodePattern(kinds=["MSSQL_ServerRole"], properties={"id": "sysadmin@*:1433"}),
        count=CountSpec(exact=4),
    ),

    ###########################
    # MSSQL_ServiceAccountFor #
    ###########################
    EdgeCase(
        id="edge-serviceaccountfor-server-instances",
        kind="MSSQL_ServiceAccountFor",
        description="The site database MSSQL service account is the service account for the MSSQL server instances (CAS and PS1 primary and passive)",
        source=NodePattern(kinds=["User", "Base"], properties={"samAccountName": "sqlsccmsvc", "id": "S-1-5-21-*"}),
        target=NodePattern(kinds=["MSSQL_Server"], properties={"id": "*:1433"}),
        count=CountSpec(exact=2),
    ),

    ##############
    # SameHostAs #
    ##############
    EdgeCase(
        id="edge-samehostas-clientdevice-to-computer-ps1-dev",
        kind="SCCM_SameHostAs",
        description="The PS1 client device is the same host as the domain joined computer (bi-directional)",
        source=NodePattern(kinds=["SCCM_ClientDevice"], properties={"id": "GUID:*"}),
        target=NodePattern(kinds=["Computer"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps1-dev.mayyhem.com"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-samehostas-computer-to-clientdevice-ps1-dev",
        kind="SCCM_SameHostAs",
        description="The PS1 client device is the same host as the domain joined computer (bi-directional)",
        source=NodePattern(kinds=["Computer"], properties={"id": "S-1-5-21-*", "dNSHostName": "ps1-dev.mayyhem.com"}),
        target=NodePattern(kinds=["SCCM_ClientDevice"], properties={"id": "GUID:*"}),
        count=CountSpec(exact=1),
    ),

    ###########################
    # SCCM_AdminsReplicatedTo #
    ###########################
    EdgeCase(
        id="edge-adminsreplicatedto-ps1-to-cas",
        kind="SCCM_AdminsReplicatedTo",
        description="The PS1 primary site has the same admins as the CAS primary site",
        source=NodePattern(kinds=["SCCM_Site"], properties={"id": "PS1"}),
        target=NodePattern(kinds=["SCCM_Site"], properties={"id": "CAS"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-adminsreplicatedto-cas-to-ps1",
        kind="SCCM_AdminsReplicatedTo",
        description="The PS1 primary site has the same admins as the CAS primary site (both directions)",
        source=NodePattern(kinds=["SCCM_Site"], properties={"id": "CAS"}),
        target=NodePattern(kinds=["SCCM_Site"], properties={"id": "PS1"}),
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-adminsreplicatedto-negative-sec-not-replicated",
        kind="SCCM_AdminsReplicatedTo",
        description="Admin users in secondary sites are NOT replicated to primary sites (no replication from SEC to PS1 or CAS)",
        source=NodePattern(kinds=["SCCM_Site"], properties={"id": "SEC"}),
        target=NodePattern(kinds=["SCCM_Site"], properties={"id": "*"}),
        negative=True,
    ),

    #######################
    # SCCM_AllPermissions #
    #######################
    SCCMEdgeCase(
        # SCCM admin user has all permissions in CAS and PS1
        id="edge-allpermissions-domainadmin-all-sites",
        kind="SCCM_AllPermissions",
        description="The Full Administrator with all collections has all permissions to all primary sites in the hierarchy",
        source=NodePattern(kinds=["SCCM_AdminUser"], properties={"id": "mayyhem\\domainadmin@*"}),
        target=NodePattern(kinds=["SCCM_Site"]),
        count=CountSpec(exact=2),
        # Tier D (design spec S:5): SCCM RBAC has no AD/LDAP/RemoteRegistry
        # representation, so this case can only be checked against a privileged
        # (AdminService/WMI) collection.
        requires_privilege=True,
    ),

    #############################
    # SCCM_AssignAllPermissions #
    #############################
    EdgeCase(
        # CAS-PSS, PS1-PSS, PS1-PSV, and PS1-SMS all have this permission
        id="edge-assignallpermissions-smsprovider-hosts",
        kind="SCCM_AssignAllPermissions",
        description="Domain computers hosting the SMS Provider role (CAS-PSS, PS1-PSS, PS1-PSV, PS1-SMS) can assign all permissions to any primary site in the hierarchy (CAS, PS1)",
        source=NodePattern(kinds=["Computer", "Base"], properties={"id": "S-1-5-21-*"}),
        target=NodePattern(kinds=["SCCM_Site"]),
        count=CountSpec(exact=8),
    ),
    EdgeCase(
        id="edge-assignallpermissions-site-databases",
        kind="SCCM_AssignAllPermissions",
        description="SCCM primary site databases (CAS-DB\\CM_CAS and PS1-DB\\CM_PS1) can assign all permissions to their primary site in the hierarchy (CAS, PS1)",
        source=NodePattern(kinds=["MSSQL_Database"], properties={"id": "*:1433\\CM_*"}),
        target=NodePattern(kinds=["SCCM_Site"]),
        count=CountSpec(exact=2),
    ),

    ##################################
    # SCCM_AssignSpecificPermissions #
    ##################################
    EdgeCase(
        # PS kit entry carries no Source/Target/Count -> constraint-less, so it SKIPs (kind existence not asserted)
        id="edge-assignspecificpermissions-constraintless",
        kind="SCCM_AssignSpecificPermissions",
        description="SCCM_AssignSpecificPermissions edges (constraint-less in the PS kit; presence is not asserted)",
    ),

    #################
    # SCCM_Contains #
    #################
    EdgeCase(
        id="edge-contains-sites-admin-user",
        kind="SCCM_Contains",
        description="The CAS and PS1 primary sites contain an SCCM admin user",
        source=NodePattern(kinds=["SCCM_Site"], properties={"id": "*"}),
        target=NodePattern(kinds=["SCCM_AdminUser"], properties={"id": "mayyhem\\domainadmin@*"}),
        count=CountSpec(exact=2),
    ),
    EdgeCase(
        id="edge-contains-sites-full-admin-role",
        kind="SCCM_Contains",
        description="The CAS and PS1 primary sites contain the Full Administrator security role",
        source=NodePattern(kinds=["SCCM_Site"], properties={"id": "*"}),
        target=NodePattern(kinds=["SCCM_SecurityRole"], properties={"id": "SMS0001R@*"}),
        count=CountSpec(exact=2),
    ),
    EdgeCase(
        id="edge-contains-sites-sms00001-collection",
        kind="SCCM_Contains",
        description="The CAS and PS1 primary sites contain the SMS00001 collection",
        source=NodePattern(kinds=["SCCM_Site"], properties={"id": "*"}),
        target=NodePattern(kinds=["SCCM_Collection"], properties={"id": "SMS00001@*"}),
        count=CountSpec(exact=2),
    ),

    ##########################
    # SCCM_FullAdministrator #
    ##########################
    SCCMEdgeCase(
        id="edge-fulladministrator-domainadmin-client-devices",
        kind="SCCM_FullAdministrator",
        description="The domainadmin SCCM admin user has the Full Administrator security role over all client devices in the hierarchy",
        source=NodePattern(kinds=["SCCM_AdminUser"], properties={"id": "mayyhem\\domainadmin@*"}),
        target=NodePattern(kinds=["SCCM_ClientDevice"], properties={"id": "GUID:*"}),
        count=CountSpec(exact=14),
        # Tier D (design spec S:5): AdminService/WMI-only RBAC fan-out.
        requires_privilege=True,
    ),

    ###########################
    # SCCM_HasADLastLogonUser #
    ###########################
    EdgeCase(
        id="edge-hasadlastlogonuser-ps1-dev-domainuser",
        kind="SCCM_HasADLastLogonUser",
        description="The PS1 client device has domainuser as the last logged on user in Active Directory",
        source=NodePattern(kinds=["SCCM_ClientDevice"], properties={"name": "PS1-DEV@PS1"}),
        target=NodePattern(kinds=["User", "Base"], properties={"samAccountName": "domainuser", "id": "S-1-5-21-*"}),
        count=CountSpec(exact=1),
    ),

    ##################
    # SCCM_HasClient #
    ##################
    EdgeCase(
        id="edge-hasclient-ps1-site-ps1-dev",
        kind="SCCM_HasClient",
        description="PS1-DEV is a client of the PS1 site",
        source=NodePattern(kinds=["SCCM_Site"], properties={"id": "PS1"}),
        target=NodePattern(kinds=["SCCM_ClientDevice"], properties={"id": "GUID:*", "name": "PS1-DEV@PS1"}),
        count=CountSpec(exact=1),
    ),

    #######################
    # SCCM_HasCurrentUser #
    #######################
    EdgeCase(
        id="edge-hascurrentuser-ps1-dev-domainuser",
        kind="SCCM_HasCurrentUser",
        description="The PS1 client device has domainuser as the current logged on user (requires manual addition of user device affinity after Ludus lab build)",
        source=NodePattern(kinds=["SCCM_ClientDevice"], properties={"id": "GUID:*", "name": "PS1-DEV@PS1"}),
        target=NodePattern(kinds=["User", "Base"], properties={"samAccountName": "domainuser", "id": "S-1-5-21-*"}),
        count=CountSpec(exact=1),
    ),

    ##################
    # SCCM_HasMember #
    ##################
    EdgeCase(
        id="edge-hasmember-sms00001-ps1-dev",
        kind="SCCM_HasMember",
        description="The SMS00001 collection contains the PS1 client device",
        source=NodePattern(kinds=["SCCM_Collection"], properties={"id": "SMS00001@*"}),
        target=NodePattern(kinds=["SCCM_ClientDevice"], properties={"id": "GUID:*", "name": "PS1-DEV@PS1"}),
        count=CountSpec(exact=1),
    ),

    #######################
    # SCCM_HasPrimaryUser #
    #######################
    EdgeCase(
        id="edge-hasprimaryuser-ps1-dev-domainuser",
        kind="SCCM_HasPrimaryUser",
        description="The PS1 client device has domainuser as the primary user",
        source=NodePattern(kinds=["SCCM_ClientDevice"], properties={"id": "GUID:*", "name": "PS1-DEV@PS1"}),
        target=NodePattern(kinds=["User", "Base"], properties={"samAccountName": "domainuser", "id": "S-1-5-21-*"}),
        count=CountSpec(exact=1),
    ),

    ###################
    # SCCM_IsAssigned #
    ###################
    SCCMEdgeCase(
        id="edge-isassigned-domainadmin-full-admin-role",
        kind="SCCM_IsAssigned",
        description="The domainadmin SCCM admin user is assigned the Full Administrator security role in the CAS root site (plus one dupe that BloodHound dedupes)",
        source=NodePattern(kinds=["SCCM_AdminUser"], properties={"id": "mayyhem\\domainadmin@*"}),
        target=NodePattern(kinds=["SCCM_SecurityRole"], properties={"id": "SMS0001R@*"}),  # Full Administrator role ID
        count=CountSpec(exact=2),
        # Tier D (design spec S:5): security-role assignment is AdminService/WMI-only.
        requires_privilege=True,
    ),

    ###################
    # SCCM_IsMappedTo #
    ###################
    SCCMEdgeCase(
        id="edge-ismappedto-sccm-domainadmin-adminuser",
        kind="SCCM_IsMappedTo",
        description="The domainadmin user is mapped to an SCCM admin user in the CAS primary site (plus one dupe that BloodHound dedupes)",
        source=NodePattern(kinds=["User", "Base"], properties={"id": "S-1-5-21-*", "samAccountName": "domainadmin"}),
        target=NodePattern(kinds=["SCCM_AdminUser"], properties={"id": "mayyhem\\domainadmin@*"}),
        count=CountSpec(exact=2),
        # Tier D (design spec S:5): admin-user-to-domain-account mapping is
        # AdminService/WMI-only. Not to be confused with MSSQL_IsMappedTo, an
        # unrelated (low-priv reachable) MSSQL scaffolding edge kind.
        requires_privilege=True,
    ),
    SCCMEdgeCase(
        id="edge-ismappedto-sccm-negative-domainuser-not-mapped",
        kind="SCCM_IsMappedTo",
        description="The domainuser user is NOT mapped to an SCCM admin user in any primary site",
        source=NodePattern(kinds=["User", "Base"], properties={"id": "S-1-5-21-*", "samAccountName": "domainuser"}),
        target=NodePattern(kinds=["SCCM_AdminUser"], properties={"id": "domainuser@*"}),
        negative=True,
        requires_privilege=True,
    ),
]
