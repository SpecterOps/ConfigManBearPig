---
id: Ope-o6bh
status: open
deps: [Ope-t7kv]
links: [Ope-gqwo, Ope-padv, Ope-t7kv, Ope-0t3h, ope-03f5]
created: 2026-05-28T13:30:23Z
type: feature
priority: 1
assignee: Mayyhem
tags: [sccm, dhcp, pxe, cred-1, credentials]
---

# DHCP Collection and PXE Credential Theft Chain (CRED-1)

Implement DHCP-based discovery of PXE-enabled distribution points and the full PXE credential theft chain. PXE boot infrastructure can be discovered without credentials by sending a DHCP Discover with option 60 (PXEClient). The DHCP response yields the TFTP server address. The boot media can be downloaded and decrypted to obtain SCCM client certificates and policy secrets. References: Misconfiguration Manager CRED-1, PXEThief, pxethiefy, Cred1py.

## Design

Phase 1 - DHCP Discovery: Send DHCP Discover with option 60=PXEClient using raw sockets. Parse response for option 66 (TFTP server) and option 67 (boot filename). Add TFTP server IP to target queue. Store in dhcp_pxe_dps. Gate on method_enabled(DHCP). Phase 2 - TFTP Download: Connect to TFTP server on UDP/69. Download boot catalog/WIM via RFC 1350 multi-block transfer. Phase 3 - Boot Media Processing: Attempt decryption with blank/default PXE password. If decrypted: extract MP address (add to targets), extract client auth cert, determine if cert is SCCM or ADCS signed. If ADCS: emit EX_ObtainCertFor from Authenticated Users to Computer node (ELEVATE-5). Use cert to auth to MP and decrypt policy secrets (reuse CRED-2 logic from TICKET-09).

## Acceptance Criteria

DHCP Discover sent and TFTP server discovered. Boot media downloaded and decryption attempted. On success: MP added to targets, ADCS cert path emits ELEVATE-5 edge, policy secrets emitted. Graceful failure with logged reason if encrypted or unreachable.

