"""Preproc: HTTP-fingerprinted version fills node_site.version when privileged is null."""
import duckdb

from openhound_sccm.transforms import _coalesce_http_site_version


def _setup(con, schema):
    con.execute(f"CREATE SCHEMA {schema}")
    con.execute(f"CREATE TABLE {schema}.node_site (site_code VARCHAR, version VARCHAR)")


def test_http_version_fills_null_privileged_version():
    con = duckdb.connect()
    _setup(con, "s")
    con.execute("INSERT INTO s.node_site VALUES ('PS1', NULL), ('PS2', '5.00.9135.1013')")
    con.execute("CREATE TABLE s.http_site_versions (site_code VARCHAR, sccm_version VARCHAR)")
    con.execute("INSERT INTO s.http_site_versions VALUES ('PS1', '5.00.9141.1015'), ('PS2', '5.00.9999.0000')")
    _coalesce_http_site_version(con, "s")
    rows = dict(con.execute("SELECT site_code, version FROM s.node_site").fetchall())
    assert rows["PS1"] == "5.00.9141.1015"   # HTTP filled the null
    assert rows["PS2"] == "5.00.9135.1013"   # privileged preferred; HTTP ignored


def test_missing_http_table_is_safe():
    con = duckdb.connect()
    _setup(con, "s")
    con.execute("INSERT INTO s.node_site VALUES ('PS1', '5.00.9135.1013')")
    _coalesce_http_site_version(con, "s")  # no http_site_versions table -> must not raise
    assert con.execute("SELECT version FROM s.node_site").fetchone()[0] == "5.00.9135.1013"


def test_coalesce_does_not_create_dlt_owned_table_when_absent():
    # Regression: http_site_versions is a dlt-managed resource. The helper must NOT create
    # it when absent -- a bare hand-made table (lacking dlt's constrained _dlt_id column)
    # makes the NEXT dlt load crash with "Adding columns with constraints not yet supported"
    # when dlt tries to ALTER in _dlt_id. So when absent, the helper skips and leaves the
    # table absent for dlt to own.
    con = duckdb.connect()
    _setup(con, "s")
    con.execute("INSERT INTO s.node_site VALUES ('PS1', '5.00.9135.1013')")
    _coalesce_http_site_version(con, "s")
    made = con.execute(
        "SELECT count(*) FROM information_schema.tables "
        "WHERE table_schema = 's' AND table_name = 'http_site_versions'"
    ).fetchone()[0]
    assert made == 0, "helper must not create the dlt-owned http_site_versions table"


def test_dropped_site_code_column_is_safe():
    # dlt drops an all-NULL column: a collection where every http_site_versions row
    # had a null site_code loads the table with only sccm_version. The WHERE/GROUP BY
    # on site_code must not raise a BinderException, and the privileged version must
    # survive untouched (no site_code means nothing to match against it).
    con = duckdb.connect()
    _setup(con, "s")
    con.execute("INSERT INTO s.node_site VALUES ('PS1', '5.00.9135.1013')")
    con.execute("CREATE TABLE s.http_site_versions (sccm_version VARCHAR)")
    con.execute("INSERT INTO s.http_site_versions VALUES ('5.00.9141.1015')")
    _coalesce_http_site_version(con, "s")  # must not raise
    assert con.execute("SELECT version FROM s.node_site").fetchone()[0] == "5.00.9135.1013"
