---
id: Ope-15m7
status: closed
deps: []
links: []
created: 2026-05-28T13:31:54Z
type: task
priority: 1
assignee: Mayyhem
tags: [sccm, graph, audit]
---

# Seed Nodes / Edges Audit

Audit whether all attack-path seed nodes (Authenticated Users, Everyone, Domain Computers) and their baseline edges are properly seeded in the graph, or if they rely on BloodHound pre-existing AD collection data. SCCM attack paths often originate from Authenticated Users -> coerce site server -> relay to MP. For these paths to be traversable in BloodHound, the Authenticated Users node must exist with its standard membership edges.

## Design

Two halves. The first (written decision) is what remains of the original audit; the second
(AD node naming + endpoint integrity) is the implementation that satisfies this ticket's
"no broken/dangling edges in standalone mode" criterion.

### Half 1 — written decision on the remaining seed principals

Authenticated Users shipped with Stage 6 (see the 2026-07-31 note). Produce the equivalent
written decision for **Everyone** and **Domain Computers**: seeded by this extension, or
expected from a prior AD collection. Document in README + ARCHITECTURE.

`ldap_group_memberships` is **dropped** from this ticket. It was the original plan for giving
seeded groups real membership, but `ad_props` (built from `ldap_resolved_principals`, which
`ctx.resolve_principal` already populates unprivileged) carries `sam_account_name`, `cn`,
`distinguished_name` and `domain` for every principal the collector resolves. Reading that is
strictly cheaper than a new collector and needs no additional privilege.

### Half 2 — AD nodes must merge cleanly with SharpHound

Root cause found 2026-08-01 while reading an unprivileged graph in which four Group nodes
rendered as bare SIDs. `_node_group` has **no LDAP arm** — its only six sources are
AdminService/WMI `R_System`/`R_User` `SecurityGroupName` lists and the SCCM admins tables. All
six need SCCM privilege. Unprivileged, `node_group` had exactly 1 row, so the groups on the
System Management container attack path fell through to `_node_backfill`, and
`StubNode.as_node` set `name = displayname = self.id` (the SID).

The names were never missing: all four groups, and all three principals on dangling `MemberOf`
starts, were already in `sccm.ad_props` with `sam_account_name` and `distinguished_name`. The
`ad_props` join at transforms.py only enriches rows that already exist in `node_group`, so a
SID with no row gets nothing.

Work items:

1. **`_domain_fqdn_by_sid`** — new transform mapping domain SID prefix to uppercase FQDN,
   derived from `ad_props`. Lets externally-discovered principals (e.g. the MSSQL service
   account `sqlsccmsvc`, which enters via `mssql_server_instances` and is never LDAP-resolved)
   be domain-qualified. Closes 100% of the naming gaps in both the priv8 and unpriv8 datasets.
2. **`ad_props` arms on `_node_group` and `_node_user`** — any LDAP-resolved principal becomes a
   real, named node instead of a stub. Restores CMBP's `Upsert-Node -PSObject $domainObject`
   spread, which the port dropped for Group. `node_computer` verified at 0 gap; no arm needed.
3. **SharpHound-format names for all AD kinds** — `Group`/`User` `SAMACCOUNTNAME@FQDN`,
   `Computer` `HOSTNAME.FQDN`, `Container` `NAME@FQDN`, all uppercase. These nodes are emitted
   untagged (ARCHITECTURE 11f) specifically to merge into BloodHound's native AD graph by
   id, so whatever `name` we ship **overwrites SharpHound's label** on the merged node. The
   port currently ships bare short names (`PS1-MP`, `domainuser`, `mayyhem\Domain Admins`, and
   the container's full DN), all of which degrade a merged graph.
   Where the SharpHound form cannot be built, **omit `name`/`displayname` entirely** (null is
   pruned at convert) so BloodHound falls back to the objectid and any SharpHound label
   survives. Never assert a label we cannot put in SharpHound form.
4. **`StubNode` omits `name`/`displayname`** — ARCHITECTURE 11e already documents StubNode as
   emitting "just `id`, `kinds` ... and `environmentid`". The code contradicts its own spec.
5. **Backfill edge STARTs** — `BACKFILL_END_KIND` only covers ends. unpriv8 ships 5 `MemberOf`
   edges whose start has no node (`domainadmin`, `Administrator`, `rvazarkar`); those edges are
   dropped at ingest, hiding real members of Domain Admins / Enterprise Admins / IT Helpdesk.
   Item 2 fixes all 5 in the current data; the start backfill is the residual net.
6. **Warn when `ad_props` builds empty** — `_derive_ad_props` uses `_safe()`, which logs-and-
   skips a missing table and leaves `ad_props` created-but-empty. There is a warning at the
   emission site (`_emit_resolved_principals`) but none at the consumption site, so a run can
   silently produce a graph with no AD names or attributes at all.

Explicitly **not** doing: carrying names inline out of `_expand_group_targets`. It would create
a second naming path needing its own precedence rule against `ad_props`, to guard a failure
mode that is all-or-nothing, has never fired in 12 recorded runs, and is already better
mitigated by item 3's omit rule.

Naming diverges from CMBP parity (`$obj.samAccountName`) by explicit decision — record it as a
new divergence category in ARCHITECTURE.md.

## Acceptance Criteria

- Written decision documented for Everyone and Domain Computers: seeded here vs. expected from
  AD collection.
- No AD node renders as a bare SID when the collector holds the name. Verified by replaying
  `preprocess` + `convert` over the recorded unpriv8 and priv8 raw data.
- Zero dangling edge endpoints (start or end) in the emitted payloads.
- Every emitted AD node name is either SharpHound-format or absent — never a bare or
  `DOMAIN\`-prefixed name.
- `ad_props` building empty produces a warning.
- README and ARCHITECTURE updated, including the CMBP naming divergence.

## Notes

**2026-07-31T15:37:02Z**

Status audit 2026-07-31: CORRECTLY IN PROGRESS -- partially satisfied. DONE: the Authenticated Users seed node is built, by preproc rather than by asking operators to run SharpHound first -- _node_authenticated_users (transforms.py:4853) synthesises one Group node per domain that actually produces a coerce-and-relay edge, keyed in SharpHound's well-known-SID form UPPER(FQDN)-S-1-5-11 (transforms.py:676-678) so it merges with any SharpHound-collected node, with environmentid resolved from a co-occurring domain computer because S-1-5-11 has no domain part of its own. That decision is documented (9 'Authenticated Users' references in README.md, 4 in ARCHITECTURE.md, incl. the explanatory block at README:1025), and edge-endpoint dangling is separately handled by _node_backfill. NOT DONE: the ldap_group_memberships collector named in the acceptance criteria does not exist -- zero references anywhere in src/ -- so the synthetic node carries no real membership edges; and the audit's central deliverable, a written decision covering the OTHER two seed principals the ticket names (Everyone and Domain Computers), has not been produced. Suggest narrowing this ticket to just that written decision, since the Authenticated Users half shipped with Stage 6 (ope-d820).

**2026-08-02T00:31:26Z**

Scope folded 2026-08-01. Root-caused an unprivileged graph rendering four Group nodes as bare SIDs: _node_group has no LDAP arm (all six sources need SCCM privilege), so groups on the System Management container path fell through to _node_backfill, whose StubNode sets name=displayname=SID. The names were already in sccm.ad_props the whole time -- the join only enriches rows node_group never created. Absorbed six work items covering domain-FQDN recovery, ad_props arms, SharpHound-format naming for all AD kinds, StubNode omitting name, start-side backfill, and an empty-ad_props warning. Dropped ldap_group_memberships (ad_props supersedes it). Kept the Everyone / Domain Computers written decision. Naming intentionally diverges from CMBP samAccountName parity so untagged AD nodes merge cleanly with SharpHound instead of overwriting its labels.

**2026-08-02T01:24:53Z**

Implemented 2026-08-01. All six work items landed plus the Everyone / Domain Computers written decision. Verified by replaying preprocess+convert over the recorded out/unpriv8 and out/priv8 raw data: unprivileged went from 4 SID-named AD nodes and 5 dangling endpoints to 0 and 0 (AD nodes 23->26 as Administrator, domainadmin and rvazarkar became real named User nodes; edge count unchanged at 148); privileged went from 35 DOMAIN-backslash-prefixed names to 0 with nodes and edges unchanged at 150/454. node_backfill is now 0 rows on both datasets, so the start-side backfill is a pure residual net. Two bugs were caught during the replay rather than by reasoning: the ad_props user arm initially swallowed all 13 computers because AD's machine-account objectClass chain includes 'user' (node_user 5->18), and _stamp_sharphound_name skipped silently when domain_fqdn_by_sid did not exist, leaving node tables with no sharphound_name column. Both are now regression-tested. Authenticated Users needed the column set in its own builder since it inserts into node_group after the stamp has run. New tests/sharphound_naming_test.py (26 cases); tests/smc_container_test.py updated for the deliberate container-naming change. Suite 1017 passed / 5 skipped; ruff + mypy clean. ARCHITECTURE 11e rewritten, new 11m divergence section, changelog entry, README AD-node-naming + seed-principals sections + 2 limitations.
