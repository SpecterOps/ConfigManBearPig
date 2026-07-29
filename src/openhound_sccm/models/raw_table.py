"""Raw-table placeholder assets.

Some DLT resources stage raw data that other models consume but never emit
their own graph nodes or edges directly (e.g. ``adminservice_collection_members``
is read by ``SCCMCollection`` to produce ``SCCM_HasMember`` edges, but the
collection-member rows themselves don't show up in the BloodHound output).

The framework's conformance tests (``tests/test_extension_methods.py``)
require every ``@app.resource`` to declare ``columns=<BaseAsset subclass>``
and for that asset to be registered with the app. For raw-data resources
this is bookkeeping only — no schema validation matters. To satisfy the
contract without inventing a separate Pydantic model for each table, this
module factories one zero-edge, no-emit placeholder asset per resource
name. Each placeholder ends up in ``app.assets`` so the conformance tests
pass; the registered model is what the harness's resource-validator
binds to.

If a raw table later grows real downstream meaning (a node it should
become, a property layout that needs validation), replace its
placeholder use site with a fully-typed asset.
"""

from __future__ import annotations

from typing import ClassVar, Optional

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset
from pydantic import ConfigDict

from openhound_sccm.main import app


def raw_table_asset(name: str, description: str = "") -> type[BaseAsset]:
    """Create and register a zero-edge placeholder asset.

    ``name`` is used as the class name (so the resource conformance test's
    error messages stay informative). ``description`` defaults to a
    formulaic string when the caller doesn't supply one.

    The placeholder pre-declares a couple of fields every raw resource may want
    (see below), but that is a convenience, not a requirement: with
    ``extra="allow"``, dlt maps a pydantic model to ``column_mode="evolve"`` for
    keys outside ``model_fields``, so any key a resource yields — declared here
    or not — still reaches its own column on disk (verified empirically against
    a live dlt pipeline + DuckDB destination during the orphaned-role-sources
    task; a source table's undeclared columns get created and populated exactly
    like declared ones). ``extra="allow"`` exists so a row with extra keys
    doesn't fail pydantic validation, not to gate what dlt persists. The real
    reason a column can still go missing is unrelated: dlt drops a column that
    is all-NULL across an entire load (see ``_ensure_columns`` in
    ``transforms.py``, which backfills exactly that case). Adding a field here
    is still safe: it's ``Optional`` and defaults to ``None`` for resources that
    don't yield it.
    """

    @app.asset(
        description=description or f"Raw staging table {name!r} (no graph emission)",
        edges=[],
    )
    class _RawTable(BaseAsset):
        model_config = ConfigDict(populate_by_name=True, extra="allow")
        dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

        raw_marker: Optional[str] = None
        # ``resource_id`` is needed by Computer.SCCMResourceIDs which falls
        # back to ``adminservice_r_system`` for non-client
        # AD-pushed hosts. PS1 emission at ConfigManBearPig.ps1:7363.
        resource_id: Optional[int] = None

        @property
        def as_node(self):
            return None

        @property
        def edges(self):
            return iter(())

    _RawTable.__name__ = name
    _RawTable.__qualname__ = name
    return _RawTable
