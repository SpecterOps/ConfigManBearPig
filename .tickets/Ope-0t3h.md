---
id: Ope-0t3h
status: open
deps: []
links: [Ope-o6bh, ope-03f5]
created: 2026-05-28T13:29:52Z
type: feature
priority: 1
assignee: Mayyhem
tags: [sccm, cred-1, elevate-1, client-push, credentials]
---

# Client Push Installation Issues (CRED-1 / ELEVATE-1)

Collect and model client push installation configuration to surface NTLM coercion and credential exposure risks. Client push causes site servers to authenticate outbound to target computers, enabling NTLM relay (CRED-1). Automatic site-wide client push lets any new domain computer trigger outbound auth. Client push accounts are stored credentials in the site control file (ELEVATE-1).

## Design

Collect client push config via AdminService: GET /wmi/SMS_SCI_ClientComp?filter=ComponentName eq SMS_CLIENT_CONFIG_MANAGER. Extract AutomaticClientPushEnabled, InstallClientToDomainController, AllowClientPushInstall, and push account credentials. Emit EX_CoerceAndRelay edges from Authenticated Users to site servers when automatic push is enabled. Emit EX_SecretPolicy edges for client push accounts. Add finding: Automatic client push installation enabled -> HIGH severity.

## Acceptance Criteria

Client push configuration is collected and stored. Automatic push -> CoerceAndRelay edge emitted. Client push accounts -> SecretPolicy edge emitted.

