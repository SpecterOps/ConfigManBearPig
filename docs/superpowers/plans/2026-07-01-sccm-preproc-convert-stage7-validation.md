# Stage 7 (Docs + Validation) — Manual-Validation Harness

**Stage:** 7 (final) of the CMBP→OpenHound preproc/convert port. **Ticket:** `ope-255b`.
**Plan:** [`2026-07-01-sccm-preproc-convert-stage7.md`](2026-07-01-sccm-preproc-convert-stage7.md).

Stage 7 changed **documentation only** (README, ARCHITECTURE.md, and non-behavioral `graph.py`
docstrings) plus non-behavioral `ruff --fix` cleanups. There is no new runtime behavior to step through
in a debugger, so — unlike the earlier stages' code-tour harnesses — this harness is a **reproduction
guide**: a set of copy-pasteable checks that prove the docs match code-truth, plus the validation-suite
commands and their expected outcomes. Run all of it from `sccm/sccm/`.

The governing principle (Stage 7 acceptance bar): **the README matches the emitted nodes/edges exactly**,
where "emitted" is defined by the code — `kinds/*.py` + each model's `NodeDef`/`EdgeDef` + the
`graph_edges` builders in `transforms.py`. The authoritative enumeration is the code-truth matrix built
in Task 1 (`.sdd/reports/2026-07-01-stage7-code-truth-matrix.md`).

---

## 1. Re-derive the code-truth counts (source of truth)

These regenerate the headline numbers straight from source. Everything else is checked against them.

```bash
cd sccm/sccm
# 37 edge-kind constants:
grep -cE '^[A-Z_]+ = "' src/openhound_sccm/kinds/edges.py            # expect: 37
# node kind constants (15 incl BASE; BASE is a secondary label, leaving 14 emitted kinds):
grep -oE '^[A-Z_]+ = "[^"]+"' src/openhound_sccm/kinds/nodes.py | wc -l   # expect: 15
```
Expected: **37** edge constants; **15** node constants of which one (`BASE`) is a secondary label
applied to the 3 AD-native kinds, leaving **14 emitted node kinds**. (See the matrix Section 1/2 for
the full lists and the `graph_edges` builder → kind mapping.)

---

## 2. README self-consistency gate (black-box)

This is the check that must stay green for the docs to be "true to the code." Copy-paste the whole block.

```bash
cd sccm/sccm

echo "== banners present =="
grep -nE 'fourteen node kinds|14 node kinds|thirty-seven edge kinds|37 edge kinds' README.md
# expect matches (intro + Limitations + Graph Model + Node/Edge Reference banners);
# NO surviving "8 ... emitted today" or "10 from Stages 1-2".

echo "== every edge kind appears as a label in the full Mermaid diagram =="
grep -oE '^[A-Z_]+ = "([A-Za-z]+)"' src/openhound_sccm/kinds/edges.py | sed -E 's/.*"(.*)"/\1/' \
  | while read k; do grep -q "|$k|" README.md || echo "MISSING EDGE IN DIAGRAM: $k"; done
# expect: no output (all 37 present).

echo "== every node kind appears in the diagrams =="
for n in Computer User Group SCCM_Site SCCM_ClientDevice SCCM_Collection SCCM_AdminUser \
         SCCM_SecurityRole MSSQL_Server MSSQL_Database MSSQL_ServerRole MSSQL_DatabaseRole \
         MSSQL_Login MSSQL_DatabaseUser; do grep -q "$n" README.md || echo "MISSING NODE: $n"; done
# expect: no output (all 14 present).

echo "== intra-doc anchor integrity (ToC / intro / cross-refs) =="
python - <<'PY'
import re
md=open('README.md',encoding='utf-8').read()
def slug(h):
    s=h.strip().lower(); s=re.sub(r'[^\w\s-]','',s); return s.replace(' ','-')
heads=[l.lstrip('#').strip() for l in md.splitlines() if re.match(r'^#{1,6}\s',l)]
seen={}; valid=set()
for h in heads:
    b=slug(h); a=b if b not in seen else f"{b}-{seen[b]}"; seen[b]=seen.get(b,0)+1; valid.add(a)
bad=sorted({l for l in re.findall(r'\]\(#([^)]+)\)',md) if l not in valid})
print("ALL ANCHOR LINKS RESOLVE" if not bad else "BROKEN: "+", ".join('#'+b for b in bad))
PY
# expect: ALL ANCHOR LINKS RESOLVE

echo "== property parity: README node tables vs graph.py emitted fields (all 14 kinds) =="
python - <<'PY'
import re
src=open('src/openhound_sccm/graph.py',encoding='utf-8').read()
pairs={'ComputerProperties':'Computer','UserProperties':'User','GroupProperties':'Group',
 'SCCMSiteProperties':'SCCM_Site','SCCMClientDeviceProperties':'SCCM_ClientDevice',
 'SCCMCollectionProperties':'SCCM_Collection','SCCMAdminUserProperties':'SCCM_AdminUser',
 'SCCMSecurityRoleProperties':'SCCM_SecurityRole','MSSQLServerProperties':'MSSQL_Server',
 'MSSQLDatabaseProperties':'MSSQL_Database','MSSQLServerRoleProperties':'MSSQL_ServerRole',
 'MSSQLDatabaseRoleProperties':'MSSQL_DatabaseRole','MSSQLLoginProperties':'MSSQL_Login',
 'MSSQLDatabaseUserProperties':'MSSQL_DatabaseUser'}
code={}
for c in re.split(r'(?m)^class ',src):
    name=c.split('(')[0].split(':')[0].strip()
    if name in pairs:
        body=re.sub(r'""".*?"""','',c,flags=re.S)   # strip docstrings so Attributes lines aren't counted
        code[pairs[name]]=sorted({f for f in re.findall(r'(?m)^    ([A-Za-z_][A-Za-z0-9_]*)\s*:',body)})
md=open('README.md',encoding='utf-8').read().splitlines()
nr=md.index('# Node Reference'); er=md.index('# Edge Reference')
readme={}; cur=None
for i in range(nr,er):
    m=re.match(r'^## (\S+)',md[i])
    if m and m.group(1) in code: cur=m.group(1); readme[cur]=[]
    elif m: cur=None
    if cur and md[i].startswith('| `'):
        km=re.match(r'^\| `([^`]+)`',md[i])
        if km: readme[cur].append(km.group(1))
bad=0
for k in code:
    miss=sorted(set(code[k])-set(readme.get(k,[]))); extra=sorted(set(readme.get(k,[]))-set(code[k]))
    if miss or extra: bad+=1; print(f"GAP {k}: missing={miss} extra={extra}")
print("ALL 14 KINDS PARITY-CLEAN" if not bad else f"{bad} kinds have gaps")
PY
# expect: ALL 14 KINDS PARITY-CLEAN
```

If any check prints a `MISSING`/`BROKEN`/`GAP` line, the docs have drifted from code — fix the README
(not the check) and re-run.

---

## 3. Validation-suite reproduction (validate-extension)

Run in an **isolated** uv environment outside the repo so the user's local `.venv` deps are not touched.
`openhound` is an unpinned git dev dep pinned by `uv.lock`, so `uv sync` is deterministic (first sync
may take a minute; if the network / git is unreachable, fall back to the existing `.venv` for the RUN
only — running tests/linters does not modify deps — and note the fallback).

```bash
cd sccm/sccm
export UV_PROJECT_ENVIRONMENT=/tmp/openhound-sccm-stage7-venv   # or a scratch path outside the repo
uv sync --group dev
uv run pytest
uv run ruff check src/
uv run mypy src/
```

Expected outcomes (from the Task 6 run — see `.sdd/reports/2026-07-01-stage7-validation-report.md`):

| Check | Expected |
|---|---|
| `pytest` | **582 passed / 5 skipped / 0 failed** |
| `ruff check src/` | **4 findings** remain — all pre-existing `F841` unused-locals in `collectors/ldap.py`'s SD/ACL parser; **not** introduced by Stage 7. Folded into `ope-1f0f`. (Stage 7 applied only non-behavioral `--fix`: one `F541` f-string + three `F401` unused imports.) |
| `mypy src/` | **223 errors**, all pre-existing (missing third-party stubs for `openhound`/`impacket`/`ldap3`/`sspi`, the custom `Logger.verbose` level, ~15 logic-shaped) — **zero** in Stage-7-touched code. Folded into `ope-1f0f`. |

Structural checklist (all pass): kind strings only via `nk.`/`ek.` imports (no hardcoded kind literals
in `models/`); every node model sets `environmentid` (3 documented exceptions: the edge asset, the
no-emit placeholder, a non-graph internal dataclass); all 16 `Attributes:` docstrings present in
`graph.py`; `models/__init__.py` exports every model.

**Scope note:** Stage 7 makes no behavioral code change. Failing lint/type checks are reported and
ticketed (`ope-1f0f`), never hand-fixed with logic changes.

**Known limitation (documented, not fixed):** `ope-3dbc` — convert can emit null OpenGraph properties
that BloodHound's schema validation rejects. This is a code bug tracked separately; Stage 7 documents it
as a limitation rather than fixing it.

**Mermaid caveat:** the three README diagrams were syntax-reviewed by hand (balanced `subgraph`/`end`,
quoted special-character labels, no reserved-word ids) but **not** validated by a Mermaid parser (no
`mmdc`/node toolchain in the dev environment). Do a final visual check by opening the README on GitHub
or pasting each fence into https://mermaid.live before relying on them.

---

## 4. Optional lab cross-check

Code-static truth is authoritative; a live lab run is a confidence check only. A single lab exercises
only the **subset** of kinds its data triggers (no MSSQL sysadmin path → no MSSQL edges; no relay victim
→ no coerce-and-relay edges), so a missing kind in the output is expected, not a doc bug.

```bash
# one-time collect against the lab (or reuse an existing <raw> tree)
openhound collect     sccm <raw> ...
openhound preprocess  sccm <raw> <raw>/lookup.duckdb
openhound convert     sccm <raw>/sccm <graph> --lookup-file <raw>/lookup.duckdb

# enumerate emitted kinds and confirm they are a SUBSET of the documented 14 / 37:
grep -ho '"kind":[^,]*' <graph>/*.json | sort -u        # edge kinds present in this run
grep -ho '"kinds":\[[^]]*\]' <graph>/*.json | sort -u   # node kind sets present in this run
```

---

## Last run — 2026-07-01 (Stage 7, ticket `ope-255b`)

All gates PASS:

- **Counts:** 37 edge constants; 14 emitted node kinds (+`Base` label). ✅
- **Banners:** present in README at lines 14 (intro), 238 (Limitations), 409/460/574 (Graph Model /
  Node Reference), 935 (Edge Reference); intro enumerates 11 + 10 + 2 + 11 + 3 = 37. No stale
  "8 emitted" / "10 from Stages 1–2". ✅
- **Diagram coverage:** every edge kind → 0 MISSING; all 14 node kinds present. ✅
- **Anchor integrity:** ALL ANCHOR LINKS RESOLVE (the 4 previously-broken —
  `#coerceandrelaytosmbedge` and the three individual `Has*User` anchors — were repointed in the Task 2
  dead-ref follow-up). ✅
- **Property parity:** ALL 14 KINDS PARITY-CLEAN (12 rows —
  `collectionSource`/`rootSiteCode`/`SCCMInfra` × the 4 SCCM-native kinds — added in the Task 2 parity
  fix). ✅
- **Suite:** pytest 582 passed / 5 skipped / 0 failed; ruff 4 pre-existing `F841` → `ope-1f0f`;
  mypy 223 pre-existing → `ope-1f0f`. ✅
- **Lab cross-check (`C:\tmp\redo` prior output):** 14/14 node kinds and 30/37 edge kinds present — a
  subset, as expected (that lab's data doesn't exercise all 7 of the remaining edge kinds). ✅
