# Keep SQL instance evidence separate

The approved November 17 connection fallback is implemented in
`collectors/mssql.py:_resolve_endpoints` and `collect_mssql`. Unknown-name rows
remain separate from one anonymous TCP-1433 candidate per host. The shared EPA
detector can read the instance name during its existing normal login; only a
matching name associates the original registration/account with the measurement.
A different or unread name leaves the requested engine unresolved. A completed
protection measurement is still usable for the answering host/port, but a TCP
open alone creates no fallback SQL node. This changes neither the site-database
assumption policy nor static-port classification. The shared design, alternatives
and verification are in
`openhound-collector-common/docs/changes/2026-11-17-sql-port-fallback.md`.

The owner approved extracting shared SQL address/SPN parsing and Browser
resolution, updating SCCM and MSSQL to use them, and correcting conflicting
account evidence, unread encryption values and Browser protocol handling.
The existing graph identifiers and schemas must remain unchanged.

## Problem and approach

The SQL collector previously chose one SPN/account per computer and could
substitute port 1433 for an unresolved instance. The registry collector also
selected the first readable settings key and first readable service entry.
Those first answers could belong to different engines. Graph preparation then
defaulted missing ports to 1433 and selected arbitrary nonempty protection or
account values when rows disagreed.

Common's `discovery/sql_server.py` now reads addresses and SQL registrations into
host, instance and known-port fields. Its `discovery/sql_browser.py` resolves a
specific instance with validated replies, a per-run cache and inherited read
controls. The common connection client requires a numeric port before connection
or EPA probing. These protocol helpers benefit both extensions; SCCM site
ownership, registry reads and graph rules remain here. Copying MSSQL's Browser
code would create two implementations to maintain; importing its graph-aware
target class would also impose another extension's graph identifiers.

## Collection flow

1. `collectors/registry.py:_mssql_instances` pairs each actual inventory name
   with its versioned network-settings path. `_read_mssql_service_state` reads
   exactly that engine's service key. Missing settings remain unknown, while
   positive inventory evidence is retained.
2. `_mssql_tcp_ports` honors ListenOnAllIPs. It reads IPAll when enabled, or
   only explicitly active/enabled IP entries otherwise. Both static and assigned
   dynamic numeric ports are retained. Dynamic zero is not a listening port.
   An unread Listen All choice cannot select an arbitrary IP configuration.
3. Each instance/port produces a raw registry row, including its own settings,
   service identity and network-settings key. `TargetEntry.sql_instances` carries
   those discovered endpoints into the later SQL phase on the same target.
4. `clients/ad.py:find_mssql_spn_holders` retains all accounts and their own
   matching registrations. `collectors/mssql.py` parses each registration with
   common, resolves named ports when necessary, and groups matching evidence by
   known port before probing. Different ports retain different accounts and
   protection measurements. A conflicting or unread identity cannot select an
   arbitrary inferred service account; raw candidates remain available.
5. `clients/mssql_epa.py:_select_mssql_spn` selects a registration matching this
   host and numeric port. Another instance's registration cannot bind this probe.
   A known port's failure does not prevent independent endpoints from being saved.
   After saving usable rows, unresolved Browser reads or inconclusive EPA
   measurements make the phase incomplete through existing completion reporting.
6. Graph preparation keeps existing host-SID/port IDs for known ports. Raw
   unresolved instance rows cannot become the default port's graph node.
   Conflicting protection/account/startup values remain unknown after merging.

## Approved site database choices

The owner chose to preserve useful low-privilege paths rather than suppress an
unknown site port. Graph preparation now chooses, in this order:

1. SCCM's explicit SQL port from AdminService/WMI.
2. The site-server registry mapping's explicit SQL port.
3. The port of the instance SCCM identifies, from matching registry/Browser facts.
4. The only observed static SQL listener on a suspected database host, inferred
   to be the site's instance.
5. Port 1433 as an explicitly marked fallback.

`collectors/registry.py:get_site_database` reads Server, Database Name and Port
from `SOFTWARE\Microsoft\SMS\SQL Server\Site System SQL Account`. It saves
`remoteregistry_site_databases` and the confirmed host role. This key requires
local administrator access in the lab; lowpriv was denied on all checked hosts.
The existing low-privilege Multisite Component Servers discovery can reveal CAS
and PS1 database hostnames, but its child entries were denied and supplied no
instance or port. SCCM's `CONFIGMGRSEC\CM_SEC` database value and the Identification
key's `ps1-sec.mayyhem.com\CONFIGMGRSEC` independently identify the named engine.
Only the former mapping is added to normal collection.

`collectors/sql_site.py:resolve_site_sql_port` reuses the recorded instance's
already collected ports, then uses shared Browser if needed. It respects selected
methods, the include-only list and proxy restrictions. The explicit SCCM port and
separately resolved port remain separate raw fields. A Browser failure is logged
and leaves the later fallback visible rather than changing another instance.

`site_database.py:resolve_site_databases` joins saved information during
preprocessing. Static inference requires explicitly enabled TCP and a successfully read,
explicitly empty TcpDynamicPorts setting and a SQL response at that configured port. An unread
setting, a dynamic value including zero, or TCP reachability alone cannot satisfy
that rule. Multiple eligible static ports cannot select an arbitrary engine.
Saved port fields must contain whole decimal integers in 1..65535. DuckDB
can otherwise round a decimal or accept exponent notation; a temporary SQL helper
rejects those values before they can identify an engine. Both guesses use the
existing assumed/assumptionBasis properties throughout the
SQL database and permission paths. Disabling possible edges removes those
mappings while preserving independent SQL observations with known ports.

The alternative of requiring an explicit provider port was rejected because it
would discard low-privilege paths. Treating any numeric SPN or Browser response as
proof of static configuration was rejected because neither establishes that fact.
Moving site ownership decisions into common was rejected because they are SCCM
rules. Changing IDs or schemas is unnecessary. Known ports and inferred ports use
the existing host-SID/port IDs; raw unresolved instances never become observations
of a different engine. New runs use more specific facts instead of their fallback;
previously imported BloodHound data is not automatically removed by the collector.

Microsoft states that SCCM site databases require static ports:
https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/ports#sql-server-port
Its setup documentation describes instance-qualified database names:
https://learn.microsoft.com/en-us/intune/configmgr/core/servers/deploy/install/command-line-script-file

## Dependencies and effects

No new dependency, schema, relationship kind or OpenHound core change is needed.
Source development and fresh-install checks use the local common checkout or
its locally built wheel. Published minimums and release actions remain deferred.
The common connection parser now visibly rejects unresolved names and invalid
numeric ports; collectors resolve or preserve them rather than contacting 1433.
MSSQL retains its existing named-instance graph-ID rules, separately from SCCM.

## Verification and manual review

The full outside-repository guide was exercised, with its verification-script
errors corrected and its lab step repeated successfully. It is
`C:\Users\domainadmin\commit-guide-sql-instance-evidence-2026-11-10.md` and contains
all commands, expected output, numbered manual checks, and the three separate
owner-run commit command blocks. No staging, commit or push was performed.

- Final affected tests passed on Windows and WSL: common 53, SCCM 252, MSSQL 124.
  SCCM includes all four required CI files, registry/provider collection, per-port
  accounts/protection, unknown and invalid ports, static/dynamic/TCP enablement,
  named instances, default-mode paths, strict filtering, and SQL permissions.
- Ruff 0.15.20 and native mypy passed in all three repositories on both systems:
  67 common source files, 66 SCCM source files and 62 MSSQL source files.
- Earlier full common suites passed 700 tests with one skip on Windows and 699
  with two skips on WSL. An isolated MSSQL HEAD copy with only the approved SQL
  source/tests passed 167 tests separately from unrelated integration-lab work.
- Cached graph preparation/conversion retained 99 nodes and 307 edges, with zero
  differences after excluding only last_seen. Evidence:
  `%TEMP%\sccm-completion-cache-owmxns3y`. Original collection data was untouched.
- All three packages built as wheels and source archives. Fresh Windows and WSL
  environments installed the local wheels with OpenHound 0.4.2 and impacket
  0.13.1. Imports were verified under each environment's own directory with no
  source redirects; both collectors' help commands passed. Windows Python was
  3.13.15; WSL Python was 3.13.5. Fresh wheels used DuckDB 1.5.2.
- Installed SCCM collection using only LDAP/RemoteRegistry/MSSQL identified CAS,
  PS1 and SEC database hosts/names/ports and produced one ZIP on each platform.
  All three site mappings used observed port 1433 with assumed=false. No provider
  transport was selected, so the site-server registry supplied these answers.
- Installed Windows lowpriv collection retained CAS/PS1 database paths at port
  1433 with assumed=true and the explicit default-port explanation. The live
  lowpriv account was denied the new administrator-only site mapping keys.
- Installed MSSQL collection resolved CONFIGMGRSEC through common Browser and
  emitted the unchanged ID
  `S-1-5-21-2685035784-114219579-2457378813-1117:CONFIGMGRSEC`, port 1433, and one
  graph ZIP on Windows and WSL. Independent ports/accounts and nondefault ports
  are tested offline; a second live engine was not installed.

Final local wheels and isolated environments:
`%TEMP%\sql-instance-review-a41ff617ed4a407f8d5fe86731502cbd`.
Final live Windows evidence: `%TEMP%\sql-lab-f98a7320`.
Final live WSL evidence:
`/home/collector/sccm-completion-evidence/sql-review-16d554bb6c1b42e59f943751b3ba7deb`.

One named-instance attempt collected successfully but the existing 90 percent
memory safeguard stopped graph preparation. A later retry passed with one worker
and the same safeguard. No threshold or server setting was changed. The guide
also uses short Windows output paths after a long retry path exceeded the file
writer's limits. WSL outputs use its native Linux filesystem: MSSQL's existing
raw-bucket metadata copy failed with Operation not permitted on the Windows mount.
That output-copy limitation is a separate followup; SQL protocol behavior passed
using native Linux output. The owner was asked whether to defer or include it.

Review baselines: CMBP `4213de843f0041a8d7aee6e033d9a9aa73b03515`, common
`7c39a7ba0fec704b53e6380026b80779811dc681`, MSSQL
`ba38f741199104306b544b368427ec559bc2e50d`, each plus the recorded working changes.
The isolated MSSQL proof is `%TEMP%\mssql-sql-isolated-f1445f7j\checkout`.
MSSQL's unrelated integration-lab files must remain outside these suggested
commits; its README/architecture SQL paragraphs require selective staging.
Publication, consumer minimum-version updates and verification against published
packages remain release work under the owner's existing local-copy decision.

Additional live SOCKS results, including the separately discovered closed-port
handling defect, are recorded in
[the SOCKS verification note](2026-11-16-socks-sql-verification.md).
