# Recommendation: put SCCM WMI reads in an owned worker

Status: recommended for a separate owner review. SCCM's default has not changed.

## Problem and recommendation

The installed impacket 0.13.1 DCOM provider stores connections in process-wide
maps keyed by hostname. A second client to that hostname can replace the first
client's credential source. Separate namespace connections have the same
problem. The offline reproduction used real provider constructors and refused
all network access. Keeping a lock only around login cannot fix later calls
which read those maps again.

Adopt common's optional `WmiProcessBackend` for SCCM WMI, including both query
and complete-object reads. Each client then owns a separate local process and
provider state. A stalled read can be stopped with confirmed process cleanup.
Use `WmiProcessControl` for the agreed read/remaining-target budget. This uses
existing dependencies and requires no graph/schema, OpenHound core, or lab
configuration change.

## Concrete scope of the proposed SCCM adapter

Change `src/openhound_sccm/clients/wmi.py`, retaining its namespace/class/columns
interface, credential ordering, and SCCM-specific handling:

- Construct the worker with exactly the credential for the selected rung.
  Supply `NetworkSettings` explicitly for SCCM's existing DNS/proxy choices.
  Credentials go through a private pipe after startup, never process arguments.
- The first query currently proves a rung works inside `_open`. Worker requests
  are lazy, so the adapter must consume the first result or successful empty
  completion before accepting that rung. Retain that first row for the caller.
  Merely creating a worker request would incorrectly report authentication.
- Route `read_instance` through the worker's complete-object operation. Do not
  retain SCCM's direct `_services_for` access: administrator permissions and
  role actions are lazy properties requiring GetObject/Get.
- Preserve streaming and expose failed/partial reads. An unconfirmed owned
  process exit must escape best-effort error handlers and fail the run.
- Close one namespace connection before switching to another. Preserve binary
  and nested values. Keep current-user native WMI unavailable under SOCKS;
  explicit-credential DCOM can use the supplied Python network settings.
- Add the selected WMI timeout to the CLI/configuration and README, update the
  Windows-authentication section of ARCHITECTURE, and test the final adapter
  before changing its default. Decide its timeout alongside the remaining
  collection-controls work, rather than silently imposing a new value.

The shared worker implementation is already approved for MSSQL. That approval
explicitly left SCCM's default unchanged; this proposal is the separate SCCM
decision, not an assertion that its final adapter has already been validated.

## Evidence gathered October 26, 2026

- Forty common offline checks passed for owned WMI, COM ownership and network
  settings. They include two simultaneous identities using a deliberately
  hostname-only provider map, startup/query/result stalls, backpressure,
  cancellation, confirmed cleanup, namespace switching, complete-object
  deadlines, binary values, and secret-free bootstrap/error transfer.
- Live read-only ps1-db checks passed for current-user, password, hash, MIT
  cache-file and base64-ticket authentication. Each read a computer object,
  retrieved its complete instance and switched namespaces; every worker exited.
- Live read-only ps1-sms checks passed for current-user, password and cache-file
  authentication. Complete `SMS_Admin` objects included the lazy Permissions
  data that the SCCM adapter needs.
- SCCM's unchanged WMI, local-WMI, HTTP-auth and LDAP-auth consumer selection
  passed 46 tests. This confirms the existing selection still works; it does
  not replace tests of the proposed SCCM adapter.

Later final checks passed 52 affected SCCM tests after the shared credential
and LDAP outcome work. The real ticket-authenticated LDAP/DNS-only collector
command returned 0 with nine nodes/ten relationships and matching ZIP bytes.
Common's final feature checkpoint passed 371 tests with one Python-version
skip; SQL passed 296 with one missing-live-artifact skip. These results do not
claim the proposed SCCM WMI adapter is implemented or the complete initiative
is finished.

Local evidence is in the task directory's `extended-wmi-lab-results.json` and
the organized common tests. No lab settings were changed. Credentials used by
the live check were temporary and were not included in its result report.

## Alternatives and effects

Serializing entire same-host WMI sessions could prevent map replacement, but
every caller and namespace path would need the same lifetime lock. It would
also leave native calls unable to stop and unrelated DCOM global state shared.
Replacing the DCOM stack would require substantially more code. Separate owned
workers reuse the existing providers with a clear lifetime boundary.

Costs: one local Python process per active WMI client, process startup time,
and bounded pipe transfer. Stopping a local worker does not promise immediate
cancellation of remote provider work. No other SCCM protocol or graph rule
needs to change for this adapter.

After review and implementation, use the repository's existing validation
environment to run `tests/wmi_client_test.py` and `tests/local_wmi_ccm_test.py`,
then read the SMS Provider through the actual collector and compare its saved
graph with collection held constant where possible. Recommended future commit
message: `Isolate SCCM WMI providers in owned workers`. The final implementation
record should list exact staging commands after its actual file scope is known.
The agent has not staged, committed or pushed any changes.
