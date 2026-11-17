# Live SQL collection through SOCKS

This records the November 16 transport checks. The November 17 approved
connection fallback changes the no-port MSSQL case below: it now tries anonymous
TCP 1433 and verifies SQL's reported instance name. Current behavior and checks
are documented in `openhound-collector-common/docs/changes/2026-11-17-sql-port-fallback.md`.

The SQL changes and the approved shared SOCKS correction were checked against
the mayyhem.com lab on 2026-11-16, using local sources and fresh packages built
from them. Refused SQL ports no longer make an otherwise complete SCCM
collection fail through SOCKS. No collector-specific code, dependency, schema
or target configuration change was needed for that correction.

## The problem and correction

Neither cas-pss nor ps1-pss has a SQL listener on port 1433. Direct collection
handles refusal as an ordinary unsuccessful port check. Before the correction,
the shared proxy raised `SocksError` for an explicit SOCKS refusal. SCCM's
`collectors/mssql.py:_check_port` catches ordinary socket errors, so the proxy
exception escaped that handler. Administrator and lowpriv runs saved usable
graphs but exited 1 and marked those hosts' SQL phases incomplete.

The owner approved fixing the shared socket boundary. Explicit network
unreachable, host unreachable and connection refused replies now become ordinary
socket errors with the destination and original reason. The complete reply must
be valid before that decision. Proxy authentication, policy, general server
failure and malformed replies remain distinct errors. No direct retry is added.

Both collectors use this shared transport. A collector-specific catch for every
`SocksError` would hide failures of the proxy itself as facts about a SQL listener.
The complete implementation, mapping, alternatives and consumer effects are
documented in `openhound-collector-common/docs/changes/2026-11-16-socks-destination-errors.md`.

The initial forwarding helper also returned general server failure for some
refusals. That ambiguous reply remains a proxy error. Only explicit destination
replies are translated; the corrected live checks use the standard refusal reply.

## Final live checks

A working SOCKS5 forwarder carried real lab connections and recorded destination,
result and byte counts, without recording application contents or credentials.
Each destination was resolved and checked against the two authorized lab
subnets before connecting. Final runs used separate Windows and WSL forwarders
on loopback port 19080, one platform at a time to keep memory use manageable.

A Python audit hook rejected every collector connection except the proxy
listener and rejected datagram sends. All 114 audited connection attempts went
to the proxy, with no blocked direct or UDP attempt. Proxy records show actual
TCP forwarding on ports 53, 445, 636 and 1433. This proves the Python clients'
path; it is not a packet capture of operating-system traffic.

Fresh isolated environments installed all three locally built wheels with no
source redirects. Explicit lab credentials were used. SCCM selected only LDAP,
RemoteRegistry and MSSQL, one worker, and these five hosts:

- cas-pss.mayyhem.com
- ps1-pss.mayyhem.com
- ps1-sec.mayyhem.com
- cas-db.mayyhem.com
- ps1-db.mayyhem.com

MSSQL selected LDAP and MSSQL, disabled linked-server traversal, used one worker,
and included only ps1-sec.mayyhem.com.

| Case | Windows | WSL | Verified result |
|---|---|---|---|
| SCCM administrator through SOCKS | Exit 0 | Exit 0 | Definitive CAS, PS1 and SEC database mappings at port 1433 from site-server registry reads |
| SCCM lowpriv through SOCKS | Exit 0 | Exit 0 | CAS/PS1 database paths retained at assumed 1433 with their explanation |
| MSSQL CONFIGMGRSEC with supplied port 1433 | Exit 0 | Exit 0 | One graph archive and the unchanged named-instance identity |
| MSSQL CONFIGMGRSEC without a port | Expected exit 1 | Expected exit 1 | Visible UDP Browser limitation, no SQL connection and no graph archive |

The named-instance ID remains
`S-1-5-21-2685035784-114219579-2457378813-1117:CONFIGMGRSEC`. Unknown named ports are
not converted into observed port 1433.

Direct and SOCKS SCCM graphs match on each platform: 32 nodes and 60 edges, with
no differences after excluding only `last_seen`. MSSQL graphs contain 163 nodes
and 488 edges. Their only additional difference is the `SQLBrowser` evidence label
on the directly collected instance: that run discovered the port, while the
SOCKS run received it explicitly. All other node properties, identities and
relationships match. The comparison permits only that specific evidence
difference and collection timestamps.

Both temporary forwarders were stopped and their shutdown was verified.

## Other checks and manual review

Affected tests passed on both Windows and WSL: common 110, SCCM 252 and MSSQL 124
on each. All three projects passed full source/test Ruff and native mypy checks.
The cached SCCM comparison retained 99 nodes and 307 edges, with zero differences
after excluding only `last_seen`. All three projects built wheels and source
archives; both fresh environments passed installed-import and CLI help checks.

The single review guide contains the full copyable commands, exact expected
output, graph comparison, cleanup and owner-run commit commands:
C:\Users\domainadmin\commit-guide-sql-instance-evidence-2026-11-10.md.
Its complete Checks section was exercised, including the final comparison.
Nothing was staged, committed or pushed.

Several Windows attempts hit the unchanged 90 percent memory safeguard or the
verifier's preparation wait. Their incomplete results were kept, not counted as
success. Final runs separated Windows and WSL forwarding. Before each Windows
run, the disposable verifier waits up to 60 seconds for memory use below 80
percent; the collector still enforces 90 percent throughout collection. Unused
WSL file cache was also released during troubleshooting. No persistent memory
setting or target setting was changed.

Final review packages, environments, proxy logs and socks-final-summary.json:
C:\Users\domainadmin\AppData\Local\Temp\sql-instance-review-bc65db1ca2d345e0a6fb6a6683c7ba18.

Final direct collection:
- Windows: %TEMP%\sql-lab-2de378f3
- WSL: /home/collector/sccm-completion-evidence/sql-review-c29cbfc2828447ed9beb1152793dda04

Final SOCKS collection:
- Windows: %TEMP%\socks-803e89e6
- WSL: /home/collector/sccm-completion-evidence/socks-02361e12c5ab487b8e54eaffae999c79

Disposable helpers: %TEMP%\socksfix-1bdc6f65. Earlier discovery evidence remains
under %TEMP%\socks-448b5eea and the matching WSL evidence folder. The cached graph
comparison evidence is %TEMP%\sccm-completion-cache-varbtmpg.

These are real local forwarding checks, not acceptance tests of a deployed SSH
or C2 tunnel. They do not cover every collection method, proxy authentication,
native Windows authentication, a live nondefault SQL port or multiple live SQL
engines. Refusal/unreachability, authentication and malformed-reply distinctions
have focused offline coverage. The separate WSL-to-Windows output-copy issue is
not changed; Linux output stays on its native filesystem.
