from dataclasses import asdict

from openhound_sccm.graph import (
    MSSQLDatabaseProperties,
    MSSQLDatabaseRoleProperties,
    MSSQLDatabaseUserProperties,
    MSSQLLoginProperties,
    MSSQLServerProperties,
    MSSQLServerRoleProperties,
)


def test_server_props_cmbp_keys():
    p = MSSQLServerProperties(
        name="SQL01:1433", displayname="SQL01:1433", environmentid="S-1-5-21-1-2-3",
        dnsHostName="SQL01.lab", SQLServicePort="1433", SCCMInfra=True, SCCMSite="PS1",
        forceEncryption=True, extendedProtection="Required", strictEncryption=False,
        databases=["CM_PS1"], instanceNames=["MSSQLSERVER"],
        SQLServiceAccountName="svc_sql", SQLServiceAccountDomainSID="S-1-5-21-1-2-3-1200",
    )
    d = asdict(p)
    # CMBP-cased keys must be present verbatim.
    for key in ("dnsHostName", "SQLServicePort", "SCCMInfra",
                "SCCMSite", "forceEncryption", "extendedProtection", "databases"):
        assert key in d
    # port-added keys (no CMBP equivalent) are present too.
    assert d["strictEncryption"] is False
    assert d["instanceNames"] == ["MSSQLSERVER"]


def test_role_and_login_keys():
    sr = MSSQLServerRoleProperties(name="sysadmin", displayname="sysadmin",
                                   environmentid="S-1-5-21-1-2-3", isFixedRole=True,
                                   members=["lab\\srv$@S-1-5-21-1-2-3-1:1433"],
                                   SCCMSite="PS1", SQLServer="SQL01.lab")
    assert asdict(sr)["isFixedRole"] is True
    lg = MSSQLLoginProperties(name="LAB\\SRV$", displayname="LAB\\SRV$",
                              environmentid="S-1-5-21-1-2-3", loginType="Windows",
                              memberOfRoles=["sysadmin@S-1-5-21-1-2-3-1:1433"],
                              SCCMInfra=True, SCCMSite="PS1", SQLServer="SQL01.lab")
    assert asdict(lg)["loginType"] == "Windows"
    du = MSSQLDatabaseUserProperties(name="LAB\\SRV$", displayname="LAB\\SRV$",
                                     environmentid="S-1-5-21-1-2-3", database="CM_PS1",
                                     login="LAB\\SRV$",
                                     memberOfRoles=["db_owner@S-1-5-21-1-2-3-1:1433\\CM_PS1"],
                                     SCCMInfra=True, SCCMSite="PS1", SQLServer="SQL01.lab")
    assert asdict(du)["login"] == "LAB\\SRV$"
    dbr = MSSQLDatabaseRoleProperties(name="db_owner", displayname="db_owner",
                                      environmentid="S-1-5-21-1-2-3", database="CM_PS1",
                                      isFixedRole=True, members=[], SCCMSite="PS1",
                                      SQLServer="SQL01.lab")
    assert asdict(dbr)["database"] == "CM_PS1"
    db = MSSQLDatabaseProperties(name="CM_PS1", displayname="CM_PS1",
                                 environmentid="S-1-5-21-1-2-3", isTrustworthy=True,
                                 SCCMInfra=True, SCCMSite="PS1", SQLServer="SQL01.lab")
    assert asdict(db)["isTrustworthy"] is True
