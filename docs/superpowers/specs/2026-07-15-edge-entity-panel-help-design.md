# Design: Per-edge entity-panel help content

- **Date:** 2026-07-15
- **Ticket:** ope-aa39
- **Area:** SCCM extension graph output (`sccm/sccm`)
- **Status:** Design approved; ready for implementation-plan.

## Problem

When an operator clicks an SCCM edge in BloodHound, the entity panel should explain
what the edge means and how to abuse it — the familiar **General / Windows Abuse /
Linux Abuse / OPSEC / References** content BloodHound ships for its built-in edges.
BloodHound does **not** provide that content for OpenGraph custom edges, and we cannot
add it through the graph schema (a relationship-kind definition only supports
`name` / `description` / `is_traversable`).

The one channel that reaches the entity panel with no BloodHound-side or OpenHound-core
change is the **edge property bag**: BloodHound renders an edge's properties in the panel,
and this project already treats edge/node properties as the way to enrich panels
(CLAUDE.md: "Port all node/edge properties ... so the entity panel is populated with
additional context"). So the help content becomes **properties on each edge**.

## Goal

Attach five help properties — `general`, `windowsAbuse`, `linuxAbuse`, `opsec`,
`references` — to every SCCM-emitted custom edge kind that BloodHound lacks native help
for, with the content authored **bespoke per edge kind** (no shared/templated prose).

## Locked decisions

1. **Where it lives:** in each edge's **property bag** (not a BloodHound schema file, not
   generated docs, not OpenHound core). No changes to OpenHound core.
2. **Structure:** a **per-kind content map** (`edge_help.py`) plus a tiny shared lookup in
   the existing edge emitter. Each kind's block is self-contained; only ~5 lines of
   plumbing are shared. This is the "as little code reuse as possible" intent: the *content*
   is never reused across edges, only the field definitions and the lookup are.
3. **Scope:** every custom kind the SCCM collector emits that BloodHound has **no** native
   help for. Excludes `MemberOf`, `AdminTo`, `HasSession` (native BloodHound help).
   `SameHostAs` and `LocalAdminRequired` have no native help page and are included.
4. **Content author:** the user provides all prose. `SCCM_AdminsReplicatedTo` is provided
   now; the rest are scaffolded as stubs.
5. **Block shape:** five flat keys — `general`/`windowsAbuse`/`linuxAbuse`/`opsec` as
   plain (multi-line) strings, `references` as a list of URL strings. Keys mirror
   BloodHound's own edge-info vocabulary.
6. **Delivery/staging:** vertical slice — build the mechanism, wire the one provided block
   end-to-end and validate it in `sccm_edges-1.json`, and scaffold `# TODO` stubs for the
   rest for the user to fill (or hand over for transcription).

## Scope: edge kinds

Content blocks are scaffolded for these **35** kinds (all keyed by the constants in
`kinds/edges.py`):

| Group | Kinds |
|---|---|
| SCCM RBAC / topology (19) | `SCCM_AdminsReplicatedTo`, `SCCM_IsMappedTo`, `SCCM_IsAssigned`, `SCCM_HasMember`, `SCCM_HasClient`, `SCCM_HasPrimaryUser`, `SCCM_HasCurrentUser`, `SCCM_HasADLastLogonUser`, `SCCM_HasStoredAccount`, `SCCM_Contains`, `SCCM_FullAdministrator`, `SCCM_ApplicationAuthor`, `SCCM_ApplicationAdministrator`, `SCCM_ComplianceSettingsManager`, `SCCM_OSDManager`, `SCCM_OperationsAdministrator`, `SCCM_SecurityAdministrator`, `SCCM_AllPermissions`, `SCCM_AssignAllPermissions` |
| Coerce-and-relay (3) | `CoerceAndRelayToAdminService`, `CoerceAndRelayToMSSQL`, `CoerceAndRelayToSMB` |
| MSSQL (11) | `MSSQL_Contains`, `MSSQL_ControlServer`, `MSSQL_ControlDB`, `MSSQL_HostFor`, `MSSQL_ExecuteOnHost`, `MSSQL_HasLogin`, `MSSQL_IsMappedTo`, `MSSQL_MemberOf`, `MSSQL_ServiceAccountFor`, `MSSQL_GetAdminTGS`, `MSSQL_GetTGS` |
| Host / local-admin (2) | `SameHostAs`, `LocalAdminRequired` |

**Excluded (native BloodHound help):** `MemberOf`, `HasSession`, `AdminTo`.

Note: `MSSQL_ServiceAccountFor` is defined but CMBP marks it non-traversable
(ps1:2233) and it may not be emitted; its stub is harmless if the kind never appears
(the lookup is keyed on kinds actually emitted).

## Data contract

`edge_help.py` defines:

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class EdgeHelp:
    """One edge kind's entity-panel help content.

    Attributes:
        general: What the edge means and why it matters (the "General" tab).
        windowsAbuse: How to abuse it from Windows (the "Windows Abuse" tab).
        linuxAbuse: How to abuse it from Linux (the "Linux Abuse" tab).
        opsec: Detection / operational-security considerations (the "OPSEC" tab).
        references: Source URLs shown under the "References" tab.
    """
    general: str
    windowsAbuse: str | None = None
    linuxAbuse: str | None = None
    opsec: str | None = None
    references: list[str] | None = None
```

`general` is required (every block needs at least a description); the other four are
optional so a kind that genuinely has, say, no Linux abuse simply omits that key (the
value stays `None` and is pruned on emit — see Data flow).

```python
from .kinds import edges as ek

EDGE_HELP: dict[str, EdgeHelp] = {
    ek.SCCM_ADMINS_REPLICATED_TO: EdgeHelp(...),   # fully populated (below)
    ek.SCCM_IS_MAPPED_TO: EdgeHelp(general="TODO"),  # stub
    # ...one entry per scoped kind
}
```

The map is keyed by the imported kind **constants**, not string literals, so a renamed
edge kind breaks the module at import time instead of silently dropping content.

## Architecture — three touch-points (all under `sccm/sccm/`)

### 1. NEW `src/openhound_sccm/edge_help.py`

The `EdgeHelp` dataclass and `EDGE_HELP` map above.

### 2. EDIT `src/openhound_sccm/graph.py`

Add five nullable fields to the shared `SCCMEdgeProperties` (inherited by
`SCCMRelayEdgeProperties`), documented in the `Attributes` docstring:

```python
general: str | None = field(default=None, kw_only=True)
windowsAbuse: str | None = field(default=None, kw_only=True)
linuxAbuse: str | None = field(default=None, kw_only=True)
opsec: str | None = field(default=None, kw_only=True)
references: list[str] | None = field(default=None, kw_only=True)
```

Defaults are `None` (not `""` / `[]`) so unset keys prune cleanly.

### 3. EDIT `src/openhound_sccm/models/graph_edge.py`

In `edges`, after computing `traversable`, look up the block and spread its non-`None`
fields into whichever property class is built:

```python
from dataclasses import asdict
from ..edge_help import EDGE_HELP

help_ = EDGE_HELP.get(self.kind)
if help_:
    help_fields = {k: v for k, v in asdict(help_).items() if v is not None}
    logger.debug("GraphEdge: attached help content for kind %r", self.kind)
else:
    help_fields = {}
    logger.debug("GraphEdge: no help content for kind %r", self.kind)
# ...
properties = SCCMRelayEdgeProperties(..., **help_fields)   # relay branch
# or
properties = SCCMEdgeProperties(..., **help_fields)        # non-relay branch
```

The help fields live on the base class, so both branches accept them.

## Data flow

`graph_edges` preproc row → `GraphEdge.edges` → `EDGE_HELP.get(kind)` → non-`None` fields
set on the property dataclass → `asdict(edge)` → existing `_without_null_properties`
([convert_pipeline.py:29-42](../../../src/openhound_sccm/convert_pipeline.py)) drops the
still-`None` keys → `sccm_edges-1.json` → uploaded → BloodHound entity panel renders the
help properties. Edges whose kind has no block emit **none** of the five keys, with no new
pruning code.

## Reference content block (provided) — `SCCM_AdminsReplicatedTo`

```python
ek.SCCM_ADMINS_REPLICATED_TO: EdgeHelp(
    general=(
        "SCCM security roles assigned to users are replicated to every other site "
        "in the hierarchy. As a result, an administrative user created and/or granted "
        "permissions in one site will have the same permissions in every other site in "
        "the hierarchy. An attacker with control of any site gains control of every site "
        "in the hierarchy and as a result, control of every client device managed by the "
        "hierarchy."
    ),
    windowsAbuse=(
        "There is no specific abuse required to follow this attack path. As SCCM admin "
        "users are replicated between sites in the same hierarchy by design, an admin user "
        "created in any site in the hierarchy will have the same permissions in every other "
        "site in the hierarchy.\n"
        "To leverage SCCM administrative user permissions from a Windows machine, execute "
        "`SharpSCCM.exe <command> <subcommand> -sms <sms_provider_ip> -sc <site_code>` or "
        "leverage the Microsoft Configuration Manager Console software in the context of the "
        "admin user to connect to an SMS Provider for any site in the hierarchy."
    ),
    linuxAbuse=(
        "There is no specific abuse required to follow this attack path. As SCCM admin "
        "users are replicated between sites in the same hierarchy by design, an admin user "
        "created in any site in the hierarchy will have the same permissions in every other "
        "site in the hierarchy.\n"
        "To leverage SCCM administrative user permissions from a Linux machine, execute "
        "`python3 sccmhunter.py admin -u <username> -p <password> -ip <sms_provider_ip>` to "
        "connect to an SMS Provider for any site in the hierarchy."
    ),
    opsec=(
        "An EDR product may detect your attempt to run SharpSCCM and alert a SOC analyst. "
        "Proxying in SCCMHunter or the Configuration Manager Console software are less likely "
        "to be detected. Most actions in SCCM are logged to files in "
        "C:\\Program Files\\Microsoft Configuration Manager\\Logs. However, these logs are "
        "primarily for diagnostics/troubleshooting and it is uncommon for them to be forwarded "
        "to a SIEM. For more information, see the References tab."
    ),
    references=[
        "https://learn.microsoft.com/en-us/intune/configmgr/core/understand/fundamentals-of-role-based-administration",
        "https://posts.specterops.io/sccm-hierarchy-takeover-41929c61e087",
        "https://github.com/Mayyhem/SharpSCCM/wiki",
        "https://github.com/garrettfoster13/sccmhunter/wiki",
        "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-file",
    ],
),
```

## Testing

New `sccm/sccm/tests/test_edge_help.py`:

1. A `SCCM_AdminsReplicatedTo` row emits all five keys with the exact provided content.
2. An excluded kind (`MemberOf`) emits **none** of the five keys.
3. A relay kind (`CoerceAndRelayToSMB`) with a block carries **both** the help keys and its
   `coercionVictim*` context keys (help fields sit on the base, so relay edges get them too).
4. Every `EDGE_HELP` key is a valid edge-kind constant defined in `kinds/edges.py`
   (guards against typos / renamed kinds).
5. A kind whose block omits an optional section (e.g. no `linuxAbuse`) does not emit that key.

End-to-end validation per `references/validate-extension.md`: run the convert phase on the
sample dataset and confirm the help keys appear on `SCCM_AdminsReplicatedTo` edges and are
absent from `MemberOf` edges in `sccm_edges-1.json`.

## Documentation

Update the SCCM README **Edge Reference** section to note that scoped edges carry
`general`/`windowsAbuse`/`linuxAbuse`/`opsec`/`references` help properties surfaced in the
BloodHound entity panel.

## Flagged (not decided here)

- **Cross-extension reuse:** the `MSSQL_*` blocks also apply to the standalone MSSQL
  extension's output. Per the "as little code reuse as possible" directive, blocks stay
  **SCCM-local** (duplicated), not promoted to `openhound-collector-common`. If desired,
  open a ticket for the MSSQL agent to mirror the `MSSQL_*` blocks in its own extension.

## Out of scope

- BloodHound-side rendering of properties into literal tabs (BloodHound shows them as
  properties; this design does not change BloodHound).
- The "Composition" cypher panel (BloodHound generates that natively for traversable edges).
- Authoring the remaining 34 content blocks (the user provides prose; stubs are scaffolded).
- Any change to OpenHound core or the MSSQL extension.
