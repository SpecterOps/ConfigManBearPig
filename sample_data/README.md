# Sample data

Real collections from the **mayyhem.com** SCCM lab, captured 2026-08-01 for the 2.0 release. They exist
so you can see what this collector produces — and load a graph into BloodHound — without first building
an SCCM hierarchy of your own.

Four runs cover the two axes that change the output most:

- **Privilege** — local administrator on the site systems vs. a plain domain user (`MAYYHEM\lowpriv`).
  See [Collection privilege tiers](../README.md#collection-privilege-tiers).
- **Possible edges** — the default, vs. `--disable-possible-edges`, which drops the *assumed* node and
  edge families. See [Assumed vs. confirmed graph content](../README.md#assumed-vs-confirmed-graph-content).

| Run | Nodes | Edges | AD | MSSQL | SCCM |
|---|---|---|---|---|---|
| privileged, all possible edges | 150 | 454 | 72n / 209e | 24n / 45e | 54n / 200e |
| privileged, `--disable-possible-edges` | 149 | 451 | 72n / 207e | 24n / 45e | 53n / 199e |
| unprivileged, all possible edges | 60 | 148 | 26n / 100e | 17n / 30e | 17n / 18e |
| unprivileged, `--disable-possible-edges` | 46 | 106 | 26n / 72e | 17n / 30e | 3n / 4e |

The two axes read straight off that table: privilege roughly triples the graph, and
`--disable-possible-edges` only ever removes — it is tightening-only, in both tiers.

## Files

Each run contributes two files sharing one timestamp:

- **`configmanbearpig_collection_<tier>_<mode>_<timestamp>.zip`** — the OpenGraph payload. Six flat
  `*.json` files (`sccm_`, `mssql_`, `ad_` × nodes/edges), which is exactly the shape BloodHound File
  Ingest accepts. Drag one straight in — but register the schemas first, or the `SCCM_*` and `MSSQL_*`
  kinds render as generic nodes (see [Upload to BloodHound](../README.md#3-upload-to-bloodhound)).
- **`configmanbearpig_collect_full_<tier>_<mode>_<timestamp>.log`** — the complete DEBUG trace for that
  run, grouped host-by-host and resource-by-resource. Useful for reading how a collection actually
  proceeds: phase ordering per host, the credential ladders, and what a low-privilege run does and does
  not get. The two unprivileged logs are the clearest illustration of the per-host access-denied
  summaries — one warning per host naming what local administrator would have unlocked, instead of a
  hundred access-denied errors.

## How they were produced

```powershell
# privileged: integrated auth as a domain admin
uv run openhound collect sccm .\out\<dir> -m All -d mayyhem.com --dc dc.mayyhem.com `
    --clean --run-all --run-integration-tests --integration-privilege high [--disable-possible-edges]

# unprivileged: a plain domain user
uv run openhound collect sccm .\out\<dir> -m All -d mayyhem.com --dc dc.mayyhem.com `
    --clean --run-all --run-integration-tests --integration-privilege low `
    -u "MAYYHEM\lowpriv" -p "<password>" [--disable-possible-edges]
```

`--clean` is not optional when re-running into a used directory: dlt *appends* a load package and
preprocess reads every `.jsonl.gz` per table, so a previous run's rows would be unioned into this run's
graph. See [`--clean` and re-running](../README.md#--clean-and-re-running-into-a-used-output-directory).

## Provenance and caveats

- **Verified, not just captured.** Every pairing was diffed with `openhound-compare` and reported
  **0 regressions**: the privileged run reproduces the prior known-good collection exactly (0 additions,
  differing only in timestamps), and each `pe-on` payload is a strict superset of its `pe-off` counterpart.
- **Real lab data, not synthetic.** These carry the lab's actual domain SID, hostnames, service accounts
  and site codes. mayyhem.com is a purpose-built SCCM test lab that exists only to exercise this
  collector — nothing here touches a production environment. No credential material appears in the logs
  (the collector never echoes `-p`; the only "password" hits are the built-in
  `Denied/Allowed RODC Password Replication Group` AD groups).
- **The unprivileged `--disable-possible-edges` run is the sparsest sample by design.** At low privilege
  most client devices are *inferred* rather than confirmed, and that flag suppresses inferred content —
  which is why its SCCM payload drops to 3 nodes / 4 edges. The built-in integration suite reports four
  failures for that specific combination; the graph is correct and the fixture set simply cannot yet
  express "this case depends on possible edges" (tracked in `con-0289`).
