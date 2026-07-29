---
id: Ope-padv
status: open
deps: [Ope-emhc]
links: [Ope-gqwo, Ope-o6bh, Ope-t7kv]
created: 2026-05-28T13:29:37Z
type: feature
priority: 2
assignee: Mayyhem
tags: [sccm, cred-4, local, credentials, bad-opsec]
---
# CRED-4: Local CIM Repository Scraping (Bad Opsec)

Implement the CRED-4 technique: scrape the local WMI CIM repository file (OBJECTS.DATA) for historical policy secrets. SCCM clients cache policy secrets in the local WMI CIM repository. Reading C:\Windows\System32\wbem\Repository\OBJECTS.DATA directly bypasses the WMI service and recovers secrets for policies that may no longer be active. Requires admin/SYSTEM on the endpoint.

## Design

In collectors/local.py: read OBJECTS.DATA raw file. Parse CIM repository binary format to extract CCM_NetworkAccessAccount, CCM_CollectionVariable, CCM_TaskSequence instances. Decrypt extracted ciphertext using DPAPI (local machine key) or SCCM-specific derivation. Emit decrypted secrets as local_naa_secrets records. Gate behind both method_enabled(Local) AND enable_bad_opsec. Windows-only - skip with message on Linux/macOS.

## Acceptance Criteria

On Windows SCCM client with admin access and --enable-bad-opsec, historical NAA secrets are recovered and emitted as EX_SecretPolicy edges. Operation skipped without --enable-bad-opsec.

