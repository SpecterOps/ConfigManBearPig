"""Resolved-principal values must survive dlt persistence and AD preprocessing."""
import tempfile
from pathlib import Path

import dlt
import duckdb
from dlt.destinations import filesystem

from openhound_sccm.context import SourceContext
from openhound_sccm.source import ldap_resolved_principals
from openhound_sccm.transforms import _derive_ad_props


def test_mixed_spns_survive_dlt_and_ad_props():
    ctx = SourceContext.__new__(SourceContext)
    ctx.resolved_principals = {}
    principals = [
        ("S-1-5-21-1-2-3-3", ["top", "computer"],
         ["HOST/two.example.com", "MSSQLSvc/two.example.com:1433"]),
        ("S-1-5-21-1-2-3-2", ["top", "computer"], "HOST/one.example.com"),
        ("S-1-5-21-1-2-3-1", ["top", "user"], None),
    ]
    for sid, classes, spns in principals:
        ctx._record_resolved_principal({
            "object_sid": sid,
            "object_class": classes,
            "service_principal_name": spns,
            "user_account_control": 512,
            "cn": sid,
            "domain": "example.com",
        })

    # Short system-temp paths avoid dlt's MAX_PATH failure on Windows.
    with tempfile.TemporaryDirectory(prefix="oh12-") as temp:
        root = Path(temp)
        pipeline = dlt.pipeline(
            pipeline_name="spn_regression",
            destination=filesystem(bucket_url=str(root / "out")),
            dataset_name="sccm",
            pipelines_dir=str(root / "p"),
        )
        # Match the production source so list values stay in the parent JSONL.
        @dlt.source(name="sccm", max_table_nesting=0)
        def resolved_source():
            return ldap_resolved_principals(ctx)

        load = pipeline.run(
            resolved_source(),
            write_disposition="append",
            loader_file_format="jsonl",
        )
        assert not load.has_failed_jobs

        raw_dir = root / "out" / "sccm" / "ldap_resolved_principals"
        files = list(raw_dir.glob("*.jsonl*"))
        assert files, "resolved principals did not persist"

        con = duckdb.connect()
        con.execute("CREATE SCHEMA sccm")
        con.execute(
            "CREATE TABLE sccm.ldap_resolved_principals AS "
            "SELECT * FROM read_json_auto(?)",
            [str(files[0])],
        )
        assert con.execute(
            "SELECT count(*) FROM sccm.ldap_resolved_principals"
        ).fetchone()[0] == 3

        _derive_ad_props(con, "sccm")
        rows = con.execute(
            "SELECT sid, object_class, service_principal_name "
            "FROM sccm.ad_props ORDER BY sid"
        ).fetchall()
        assert rows == [
            ("S-1-5-21-1-2-3-1", ["top", "user"], []),
            ("S-1-5-21-1-2-3-2", ["top", "computer"], ["HOST/one.example.com"]),
            ("S-1-5-21-1-2-3-3", ["top", "computer"],
             ["HOST/two.example.com", "MSSQLSvc/two.example.com:1433"]),
        ]
