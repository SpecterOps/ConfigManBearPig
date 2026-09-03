"""Tests for the ``ldap_resolved_principals`` raw-table persistence.

Covers two things:
1. ``SourceContext.resolve_principal`` accumulates every successful resolution
   into ``ctx.resolved_principals``, deduped by SID (context.py).
2. ``"ldap_resolved_principals"`` is wired into ``_preproc_table_map()`` so
   preprocess actually loads the table (main.py).
"""
from openhound_sccm import source as _source_mod  # noqa: F401  (import side effect: registers @app.resource on app.dlt_resources)
from openhound_sccm.context import SourceContext


def test_resolve_principal_accumulates_row(monkeypatch):
    ctx = SourceContext.__new__(SourceContext)   # bypass full init
    ctx.ad_resolution_cache = {}
    ctx.discovered_domains = set()
    ctx.resolved_principals = {}
    # Stub the LDAP layer to return one AD object with the new attrs.
    obj = {"object_sid": "S-1-5-21-1-2-3-1104", "object_class": ["top", "person", "user"],
           "user_account_control": 512, "service_principal_name": [],
           "cn": "Bob", "dns_host_name": None, "sam_account_name": "bob",
           "user_principal_name": "bob@corp.local", "distinguished_name": "CN=Bob,DC=corp,DC=local"}
    monkeypatch.setattr(ctx, "_build_domains_to_try", lambda hint: ["corp.local"])
    monkeypatch.setattr(ctx, "_ldap_resolve", lambda name, domain: obj)
    got = ctx.resolve_principal("corp.local\\bob")
    assert got is obj
    # The successful resolution was recorded for persistence, keyed by SID.
    assert "S-1-5-21-1-2-3-1104" in ctx.resolved_principals
    row = ctx.resolved_principals["S-1-5-21-1-2-3-1104"]
    assert row["user_account_control"] == 512 and row["sam_account_name"] == "bob"


def test_resolve_principal_stamps_resolving_domain(monkeypatch):
    """The per-domain loop's LDAP hit must be stamped with the domain it was
    actually resolved in, so the recorded row's "domain" column is populated
    (not always None). Exercises the real ``_ldap_resolve`` (only the LDAP
    transport underneath it is stubbed) so this actually covers the stamping
    fix rather than re-implementing it in the test double."""
    ctx = SourceContext.__new__(SourceContext)
    ctx.ad_resolution_cache = {}
    ctx.discovered_domains = set()
    ctx.resolved_principals = {}
    obj = {"object_sid": "S-1-5-21-1-2-3-1105", "object_class": ["top", "person", "user"],
           "user_account_control": 512, "service_principal_name": [],
           "cn": "Carol", "dns_host_name": None, "sam_account_name": "carol",
           "user_principal_name": "carol@corp.local", "distinguished_name": "CN=Carol,DC=corp,DC=local"}

    class _FakeAD:
        def paged_search(self, *args, **kwargs):
            yield obj

    ctx.ad = _FakeAD()
    monkeypatch.setattr(ctx, "_build_domains_to_try", lambda hint: ["corp.local"])
    got = ctx.resolve_principal("corp.local\\carol")
    assert got["domain"] == "corp.local"
    row = ctx.resolved_principals["S-1-5-21-1-2-3-1105"]
    assert row["domain"] == "corp.local"


def test_resolve_principal_dn_path_stamps_domain_parsed_from_dn():
    """The DN branch has no separate "domain" parameter, so ``_ldap_resolve_dn``
    must derive it from the DN's own DC= components before recording. Exercises
    the real ``_ldap_resolve_dn`` with only the LDAP transport stubbed."""
    ctx = SourceContext.__new__(SourceContext)
    ctx.ad_resolution_cache = {}
    ctx.resolved_principals = {}
    obj = {"object_sid": "S-1-5-21-1-2-3-2001", "object_class": ["top", "user"],
           "user_account_control": 512, "service_principal_name": [],
           "cn": "x", "dns_host_name": None, "sam_account_name": "x",
           "user_principal_name": None, "distinguished_name": "CN=x,DC=corp,DC=local"}

    class _FakeAD:
        def paged_search(self, *args, **kwargs):
            yield obj

    ctx.ad = _FakeAD()
    got = ctx.resolve_principal("CN=x,DC=corp,DC=local")
    assert got["domain"] == "corp.local"
    row = ctx.resolved_principals["S-1-5-21-1-2-3-2001"]
    assert row["domain"] == "corp.local"


def test_resolve_principal_dn_path_accumulates_row(monkeypatch):
    """The distinguished-name branch (BASE-scope lookup) is a separate return
    path from the per-domain loop and must record its hit too."""
    ctx = SourceContext.__new__(SourceContext)
    ctx.ad_resolution_cache = {}
    ctx.resolved_principals = {}
    obj = {"object_sid": "S-1-5-21-1-2-3-2000", "object_class": ["top", "computer"],
           "user_account_control": 4096, "service_principal_name": ["HOST/foo"],
           "cn": "FOO", "dns_host_name": "foo.corp.local", "sam_account_name": "FOO$",
           "user_principal_name": None, "distinguished_name": "CN=FOO,DC=corp,DC=local"}
    monkeypatch.setattr(ctx, "_ldap_resolve_dn", lambda dn: obj)
    got = ctx.resolve_principal("CN=FOO,DC=corp,DC=local")
    assert got is obj
    assert "S-1-5-21-1-2-3-2000" in ctx.resolved_principals


def test_resolve_principal_does_not_duplicate_on_repeat_lookup(monkeypatch):
    """A second lookup that hits the ad_resolution_cache (not LDAP again) must
    not overwrite or duplicate the already-recorded row."""
    ctx = SourceContext.__new__(SourceContext)
    ctx.ad_resolution_cache = {}
    ctx.discovered_domains = set()
    ctx.resolved_principals = {}
    obj = {"object_sid": "S-1-5-21-1-2-3-3000", "object_class": ["top", "user"],
           "user_account_control": 512, "service_principal_name": [],
           "cn": "Alice", "dns_host_name": None, "sam_account_name": "alice",
           "user_principal_name": "alice@corp.local", "distinguished_name": "CN=Alice,DC=corp,DC=local"}
    calls = {"n": 0}

    def _resolve(name, domain):
        calls["n"] += 1
        return obj

    monkeypatch.setattr(ctx, "_build_domains_to_try", lambda hint: ["corp.local"])
    monkeypatch.setattr(ctx, "_ldap_resolve", _resolve)
    ctx.resolve_principal("corp.local\\alice")
    ctx.resolve_principal("corp.local\\alice")
    assert calls["n"] == 1  # second call served from ad_resolution_cache
    assert len(ctx.resolved_principals) == 1


def test_resolve_principal_records_none_safely(monkeypatch):
    """A failed resolution (no domain matches) must not add anything, and must
    not raise trying to record a None result."""
    ctx = SourceContext.__new__(SourceContext)
    ctx.ad_resolution_cache = {}
    ctx.discovered_domains = set()
    ctx.resolved_principals = {}
    monkeypatch.setattr(ctx, "_build_domains_to_try", lambda hint: ["corp.local"])
    monkeypatch.setattr(ctx, "_ldap_resolve", lambda name, domain: None)
    got = ctx.resolve_principal("corp.local\\ghost")
    assert got is None
    assert ctx.resolved_principals == {}


def test_service_principal_name_scalar_is_normalized_to_list(monkeypatch):
    """``ADClient._entry_to_dict`` collapses a single-valued LDAP attribute to a
    bare scalar (``values[0] if len(values) == 1 else values``), so a
    principal with exactly one SPN arrives here as a plain string, not a list.
    Recording it as-is would make ``service_principal_name`` take different
    Python types across different principals in the same run (None / str /
    list) -- exactly what triggered dlt's variant-column schema-freeze crash
    against a real environment (ldap_resolved_principals' contract is frozen,
    so a later row needing a different inferred type fails the whole load,
    not just that row). Must always be recorded as a list."""
    ctx = SourceContext.__new__(SourceContext)
    ctx.ad_resolution_cache = {}
    ctx.discovered_domains = set()
    ctx.resolved_principals = {}
    obj = {"object_sid": "S-1-5-21-1-2-3-4001", "object_class": ["top", "computer"],
           "user_account_control": 4096, "service_principal_name": "HOST/onespn.corp.local",
           "cn": "ONESPN", "dns_host_name": "onespn.corp.local", "sam_account_name": "ONESPN$",
           "user_principal_name": None, "distinguished_name": "CN=ONESPN,DC=corp,DC=local"}
    monkeypatch.setattr(ctx, "_build_domains_to_try", lambda hint: ["corp.local"])
    monkeypatch.setattr(ctx, "_ldap_resolve", lambda name, domain: obj)
    ctx.resolve_principal("corp.local\\ONESPN$")
    row = ctx.resolved_principals["S-1-5-21-1-2-3-4001"]
    assert row["service_principal_name"] == ["HOST/onespn.corp.local"]


def test_service_principal_name_none_is_normalized_to_empty_list(monkeypatch):
    """An absent attribute arrives as ``None`` from ``_entry_to_dict``; must
    still be recorded as a list (empty), not None, for the same type-
    consistency reason as the scalar case above."""
    ctx = SourceContext.__new__(SourceContext)
    ctx.ad_resolution_cache = {}
    ctx.discovered_domains = set()
    ctx.resolved_principals = {}
    obj = {"object_sid": "S-1-5-21-1-2-3-4002", "object_class": ["top", "person", "user"],
           "user_account_control": 512, "service_principal_name": None,
           "cn": "NoSpn", "dns_host_name": None, "sam_account_name": "nospn",
           "user_principal_name": "nospn@corp.local", "distinguished_name": "CN=NoSpn,DC=corp,DC=local"}
    monkeypatch.setattr(ctx, "_build_domains_to_try", lambda hint: ["corp.local"])
    monkeypatch.setattr(ctx, "_ldap_resolve", lambda name, domain: obj)
    ctx.resolve_principal("corp.local\\nospn")
    row = ctx.resolved_principals["S-1-5-21-1-2-3-4002"]
    assert row["service_principal_name"] == []


def test_object_class_scalar_is_normalized_to_list(monkeypatch):
    """Same collapsing behavior applies to ``object_class`` -- rare in
    practice (objectClass is almost always multi-valued) but the same bug
    class, and transforms.py's ad_props builder already expects an array
    for this column too (``_ensure_columns``/``_arr()``), so guard it the
    same way for consistency."""
    ctx = SourceContext.__new__(SourceContext)
    ctx.ad_resolution_cache = {}
    ctx.discovered_domains = set()
    ctx.resolved_principals = {}
    obj = {"object_sid": "S-1-5-21-1-2-3-4003", "object_class": "top",
           "user_account_control": 512, "service_principal_name": [],
           "cn": "Solo", "dns_host_name": None, "sam_account_name": "solo",
           "user_principal_name": "solo@corp.local", "distinguished_name": "CN=Solo,DC=corp,DC=local"}
    monkeypatch.setattr(ctx, "_build_domains_to_try", lambda hint: ["corp.local"])
    monkeypatch.setattr(ctx, "_ldap_resolve", lambda name, domain: obj)
    ctx.resolve_principal("corp.local\\solo")
    row = ctx.resolved_principals["S-1-5-21-1-2-3-4003"]
    assert row["object_class"] == ["top"]


def test_resolved_principals_have_consistent_spn_type_across_mixed_cardinality(monkeypatch):
    """Direct regression test for the real-environment crash: record three
    principals whose SPN attribute has different cardinality (none / one /
    many -- the normal spread across a real domain's users, service accounts,
    and site servers) and assert every recorded row's service_principal_name
    is a Python list, so a real collect would never hand dlt mixed types for
    this column and trip the variant-column schema-freeze error."""
    ctx = SourceContext.__new__(SourceContext)
    ctx.ad_resolution_cache = {}
    ctx.discovered_domains = set()
    ctx.resolved_principals = {}
    objs = {
        "none": {"object_sid": "S-1-5-21-1-2-3-5001", "object_class": ["top", "user"],
                 "user_account_control": 512, "service_principal_name": None,
                 "cn": "None", "dns_host_name": None, "sam_account_name": "none_",
                 "user_principal_name": None, "distinguished_name": "CN=None,DC=corp,DC=local"},
        "one": {"object_sid": "S-1-5-21-1-2-3-5002", "object_class": ["top", "computer"],
                "user_account_control": 4096, "service_principal_name": "HOST/one.corp.local",
                "cn": "One", "dns_host_name": "one.corp.local", "sam_account_name": "ONE$",
                "user_principal_name": None, "distinguished_name": "CN=One,DC=corp,DC=local"},
        "many": {"object_sid": "S-1-5-21-1-2-3-5003", "object_class": ["top", "computer"],
                 "user_account_control": 4096,
                 "service_principal_name": ["HOST/many.corp.local", "MSSQLSvc/many.corp.local:1433"],
                 "cn": "Many", "dns_host_name": "many.corp.local", "sam_account_name": "MANY$",
                 "user_principal_name": None, "distinguished_name": "CN=Many,DC=corp,DC=local"},
    }
    monkeypatch.setattr(ctx, "_build_domains_to_try", lambda hint: ["corp.local"])
    for key, obj in objs.items():
        monkeypatch.setattr(ctx, "_ldap_resolve", lambda name, domain, obj=obj: obj)
        ctx.resolve_principal(f"corp.local\\{key}")
    for row in ctx.resolved_principals.values():
        assert isinstance(row["service_principal_name"], list)


def test_ldap_resolved_principals_in_preproc_table_map():
    from openhound_sccm.main import _preproc_table_map
    tables = _preproc_table_map()
    assert "ldap_resolved_principals" in tables
    assert tables["ldap_resolved_principals"] == "sccm/ldap_resolved_principals"


def test_ldap_resolved_principals_resource_is_registered_and_conformant():
    """The new resource must be an @app.resource with a validated raw-table
    model (the framework's conformance guard checks app.dlt_resources)."""
    from dlt.extract.validation import PydanticValidator

    from openhound_sccm.main import app

    matches = [r for r in app.dlt_resources if r.name == "ldap_resolved_principals"]
    assert len(matches) == 1, "ldap_resolved_principals must be registered exactly once via @app.resource"
    resource = matches[0]
    assert resource.columns and isinstance(resource.validator, PydanticValidator)


def test_ldap_resolved_principals_resource_yields_accumulator_contents():
    """The resource itself is a thin wrapper: called with a context, it must
    yield exactly ctx.resolved_principals' current values.

    dlt validates each yielded dict against the raw_table_asset's Pydantic
    model before handing it back (same as every other @app.resource in this
    extension), so the rows come back as model instances, not plain dicts —
    assert on the fields rather than dict equality.
    """
    from openhound_sccm.source import ldap_resolved_principals

    ctx = SourceContext.__new__(SourceContext)
    ctx.resolved_principals = {
        "S-1-5-21-1-2-3-1104": {"sid": "S-1-5-21-1-2-3-1104", "sam_account_name": "bob"},
    }
    rows = list(ldap_resolved_principals(ctx))
    assert len(rows) == 1
    assert rows[0].sid == "S-1-5-21-1-2-3-1104"
    assert rows[0].sam_account_name == "bob"


def test_raw_table_is_populated_after_a_full_collect_shaped_run(tmp_path):
    """The gate from the design spec (§8 "Risks"): the raw table must be
    non-empty after a full collect, not just present in an in-memory dict.

    Drives the real ``_run_per_host_stage`` (Stage 2) against a real, isolated
    dlt filesystem pipeline — the same shape ``test_per_host_integration.py``
    uses — with ``ctx.resolved_principals`` pre-seeded to stand in for
    whatever Stage-1 discovery and the per-host phases would have accumulated
    into it by the time this function is called. Confirms the JSONL file this
    function's trailing pipeline.run writes actually lands on disk with the
    row's fields intact.

    Seed values are scalars, not lists: a list-valued column (e.g.
    ``object_class``/``service_principal_name`` in real rows) makes dlt
    normalize it into a child table named ``ldap_resolved_principals__<col>``,
    which combined with pytest's ``tmp_path`` nesting can push dlt's internal
    pipeline-state path past Windows' 260-char MAX_PATH — a test-harness
    path-depth artifact unrelated to this feature, reproduced independently
    of ``_run_per_host_stage`` (a single bare ``pipeline.run`` hits the same
    ``FileNotFoundError`` for a long enough tmp path). Keeping the seed flat
    avoids it without touching production code.
    """
    import json
    import threading

    import dlt
    from dlt.destinations import filesystem

    from openhound_sccm import main as main_mod
    from openhound_sccm.phased_pipeline import WorkQueue
    from tests.stub_per_host_phases import PER_HOST_PHASES

    wq = WorkQueue()
    wq.submit("hostA")
    ctx = SourceContext(ad=None, domain="example.com", work_queue=wq, collection_methods="All")
    # Stands in for resolutions made during Stage-1 discovery (which always
    # runs, and finishes, before collect_sccm ever calls _run_per_host_stage)
    # plus anything the per-host phases below resolve — both funnel into this
    # same dict via resolve_principal, regardless of which stage called it.
    ctx.resolved_principals = {
        "S-1-5-21-1-2-3-9999": {
            "sid": "S-1-5-21-1-2-3-9999", "object_class": "computer",
            "user_account_control": 4096, "service_principal_name": None,
            "cn": "HOSTA", "dns_host_name": "hosta.example.com", "sam_account_name": "HOSTA$",
            "user_principal_name": None, "distinguished_name": "CN=HOSTA,DC=example,DC=com",
            "domain": None,
        },
    }
    pipeline = dlt.pipeline(
        pipeline_name="e2e",
        destination=filesystem(bucket_url=str(tmp_path)),
        dataset_name="sccm",
        pipelines_dir=str(tmp_path / "p"),
    )

    done = threading.Event()
    errbox = {}

    def run():
        try:
            main_mod._run_per_host_stage(pipeline, wq, ctx, threads=2, phases=PER_HOST_PHASES)
        except Exception as exc:  # pragma: no cover - surfaced via errbox
            errbox["exc"] = exc
        finally:
            done.set()

    runner = threading.Thread(target=run, daemon=True)
    runner.start()
    finished = done.wait(timeout=60)
    assert finished, "per-host stage did not finish in time (possible deadlock)"
    assert "exc" not in errbox, f"per-host stage raised: {errbox.get('exc')}"

    table_dir = tmp_path / "sccm" / "ldap_resolved_principals"
    assert table_dir.is_dir(), f"ldap_resolved_principals was never written; found {list((tmp_path / 'sccm').iterdir())}"
    rows = []
    for f in sorted(table_dir.glob("*.jsonl*")):
        opener = __import__("gzip").open if f.suffix == ".gz" else open
        with opener(f, "rt", encoding="utf-8") as fh:
            rows.extend(json.loads(line) for line in fh if line.strip())
    assert len(rows) == 1
    assert rows[0]["sid"] == "S-1-5-21-1-2-3-9999"
    assert rows[0]["sam_account_name"] == "HOSTA$"
    assert rows[0]["user_account_control"] == 4096
