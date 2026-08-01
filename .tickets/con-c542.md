---
id: con-c542
status: open
deps: []
links: []
created: 2026-07-31T16:31:58Z
type: task
priority: 2
tags: [testing, integration, fixtures, lowpriv]
---

# Tag fixture cases from measured privileged/unprivileged A/B

Tag every fixture case that a privileged/unprivileged A/B measures as privilege-dependent. Method: run the same collection twice against the mayyhem lab -- once in an integrated SCCM-admin context, once as MAYYHEM\lowpriv -- with --run-integration-tests and possible edges enabled in both, then tag every case that PASSES privileged and FAILS unprivileged. That converts the tagging from judgement into measurement. A first A/B (before the lab hosts were all booted) measured 34 privilege-dependent cases against only 8 currently tagged, i.e. --integration-lowpriv skipped 8 of the 34 it should. Gate classes observed: AdminService/WMI device inventory, MSSQL topology inference, RemoteRegistry-derived roles/signing/sessions, Tier-D RBAC containment, SMS Provider role. Also drop the tag from edge-ismappedto-sccm-negative-domainuser-not-mapped: it is a negative assertion that passes trivially at low privilege, so tagging it is pointless. Depends on a stable full-lab baseline -- counts shift on every host boot. Worksheet for the per-case decisions lives in .sdd/ (gitignored).

## Acceptance Criteria

Every case measured as privilege-dependent carries requires_privilege; no case carries it without measurement backing it; the negative ismappedto case is untagged; a lowpriv run with --integration-lowpriv reports zero failures attributable to missing privilege.

## Notes

**2026-07-31T18:33:21Z**

@_Mayyhem's per-case calls (worksheet returned 2026-07-31). He answered a better question than 'tag or not': at which privilege level SHOULD this pass. 14 of my 20 TAG recommendations came back 'Unprivileged' -- those are collector gaps, not privilege gates, and tagging them would permanently encode 'low privilege cannot do this' for things low privilege is meant to do.
TAG (genuinely privileged): node-adminuser-count, edge-allpermissions-domainadmin-all-sites, node-collection-count, edge-contains-sites-admin-user, edge-contains-sites-full-admin-role, edge-contains-sites-sms00001-collection, edge-hasadlastlogonuser-ps1-dev-domainuser, edge-hasmember-sms00001-ps1-dev, edge-hasprimaryuser-ps1-dev-domainuser, node-securityrole-count, edge-fulladministrator-domainadmin-client-devices, edge-hascurrentuser-ps1-dev-domainuser, edge-isassigned-domainadmin-full-admin-role, edge-ismappedto-sccm-domainadmin-adminuser.
DO NOT TAG -- should work unprivileged, tracked as collector gaps: edge-hassession-cas-db + edge-hassession-ps1-db (con-2249), edge-samehostas x2 (con-5e71), edge-coerceandrelaytoadminservice-ps1 (con-6198), node-site-count + node-site-has-sitecode (con-3354), node-clientdevice-count, edge-assignallpermissions-smsprovider-hosts (con-edee).
UNRESOLVED: edge-hasclient-ps1-site-ps1-dev -- see con-5e71.
ALSO: drop the tag from edge-ismappedto-sccm-negative-domainuser-not-mapped (negative case, passes trivially at low privilege).
