from openhound_sccm.models.mssql_server import MSSQLServer
from openhound_sccm.models.mssql_database import MSSQLDatabase
from openhound_sccm.models.mssql_server_role import MSSQLServerRole
from openhound_sccm.models.mssql_database_role import MSSQLDatabaseRole
from openhound_sccm.models.mssql_login import MSSQLLogin
from openhound_sccm.models.mssql_database_user import MSSQLDatabaseUser
from openhound_sccm.kinds import nodes as nk


def test_server_node():
    n = MSSQLServer(server_id="S-1-5-21-1-2-3-9:1433", host_sid="S-1-5-21-1-2-3-9",
                    port="1433", dns_host_name="SQL01.lab", sccm_site="PS1", sccm_infra=True,
                    databases=["CM_PS1"], force_encryption=True, extended_protection="Required").as_node
    assert n.id == "S-1-5-21-1-2-3-9:1433"
    assert nk.MSSQL_SERVER in n.kinds
    assert n.properties.environmentid == "S-1-5-21-1-2-3"     # domain SID of the host
    assert n.properties.dnsHostName == "SQL01.lab"
    assert n.properties.SCCMSite == "PS1"


def test_server_drops_row_without_id():
    assert MSSQLServer(server_id=None).as_node is None


def test_login_and_dbuser_nodes():
    lg = MSSQLLogin(login_id="LAB\\X$@S-1-5-21-1-2-3-9:1433", login_name="LAB\\X$",
                    host_sid="S-1-5-21-1-2-3-9", server_id="S-1-5-21-1-2-3-9:1433",
                    sql_server="SQL01.lab", sccm_site="PS1").as_node
    assert lg.id == "LAB\\X$@S-1-5-21-1-2-3-9:1433"
    assert nk.MSSQL_LOGIN in lg.kinds
    assert lg.properties.loginType == "Windows"
    assert lg.properties.memberOfRoles == ["sysadmin@S-1-5-21-1-2-3-9:1433"]
    du = MSSQLDatabaseUser(dbuser_id="LAB\\X$@S-1-5-21-1-2-3-9:1433\\CM_PS1", dbuser_name="LAB\\X$",
                           login_name="LAB\\X$", database_id="S-1-5-21-1-2-3-9:1433\\CM_PS1",
                           database="CM_PS1", host_sid="S-1-5-21-1-2-3-9",
                           server_id="S-1-5-21-1-2-3-9:1433", sql_server="SQL01.lab", sccm_site="PS1").as_node
    assert nk.MSSQL_DATABASE_USER in du.kinds
    assert du.properties.memberOfRoles == ["db_owner@S-1-5-21-1-2-3-9:1433\\CM_PS1"]
    assert du.properties.login == "LAB\\X$"


def test_role_nodes():
    sr = MSSQLServerRole(role_id="sysadmin@S-1-5-21-1-2-3-9:1433", server_id="S-1-5-21-1-2-3-9:1433",
                         host_sid="S-1-5-21-1-2-3-9", name="sysadmin",
                         members=["LAB\\X$@S-1-5-21-1-2-3-9:1433"], sccm_site="PS1", sql_server="SQL01.lab").as_node
    assert nk.MSSQL_SERVER_ROLE in sr.kinds
    assert sr.properties.isFixedRole is True
    assert sr.properties.members == ["LAB\\X$@S-1-5-21-1-2-3-9:1433"]
    dbr = MSSQLDatabaseRole(role_id="db_owner@S-1-5-21-1-2-3-9:1433\\CM_PS1",
                            database_id="S-1-5-21-1-2-3-9:1433\\CM_PS1", host_sid="S-1-5-21-1-2-3-9",
                            name="db_owner", database="CM_PS1", members=[], sccm_site="PS1",
                            sql_server="SQL01.lab").as_node
    assert nk.MSSQL_DATABASE_ROLE in dbr.kinds
    db = MSSQLDatabase(database_id="S-1-5-21-1-2-3-9:1433\\CM_PS1", host_sid="S-1-5-21-1-2-3-9",
                       name="CM_PS1", sccm_site="PS1", sql_server="SQL01.lab").as_node
    assert nk.MSSQL_DATABASE in db.kinds
    assert db.properties.isTrustworthy is True


def test_models_exported_from_package():
    from openhound_sccm.models import (MSSQLDatabase, MSSQLDatabaseRole, MSSQLDatabaseUser,
                                       MSSQLLogin, MSSQLServer, MSSQLServerRole)
    assert all(m is not None for m in
               (MSSQLServer, MSSQLDatabase, MSSQLServerRole, MSSQLDatabaseRole, MSSQLLogin, MSSQLDatabaseUser))


def test_mssql_node_specs_hold_mssql_tables_and_sccm_specs_do_not():
    from openhound_sccm.main import MSSQL_NODE_SPECS, SCCM_NODE_SPECS
    mssql_tables = [t for t, _ in MSSQL_NODE_SPECS]
    sccm_tables = [t for t, _ in SCCM_NODE_SPECS]
    for t in ("node_mssql_server", "node_mssql_database", "node_mssql_server_role",
              "node_mssql_database_role", "node_mssql_login", "node_mssql_database_user"):
        assert t in mssql_tables            # MSSQL nodes are their own source_kind="MSSQL" payload
        assert t not in sccm_tables         # ...and no longer live under the SCCM payload
