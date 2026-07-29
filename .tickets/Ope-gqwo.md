---
id: Ope-gqwo
status: open
deps: [Ope-t7kv]
links: [Ope-o6bh, Ope-padv, Ope-t7kv]
created: 2026-05-28T13:29:26Z
type: feature
priority: 2
assignee: Mayyhem
tags: [sccm, cred-6, smb, pxe, credentials]
---
# CRED-6: PXE Media Download and Policy Decryption (SMB/TFTP)

Implement the CRED-6 technique: scan SMB distribution point shares for PXE boot media, download it via SMB or TFTP, and decrypt contained policy secrets. Distribution points expose PXE boot WIM files on the REMINST SMB share. These WIM files contain encrypted policy decryptable using the same mechanism as CRED-2.

## Design

In collectors/smb.py: enumerate \<DP>\REMINST\ share for WIM, BCD, or boot catalog files. Download PXE media (respect --socks-proxy for TFTP fallback). Attempt decryption with known default/blank PXE passwords. If decrypted: extract MP address (add to target queue), extract client auth certificate, determine if cert is SCCM or ADCS signed. Reuse CRED-2 HTTP decryption for policy secrets. Emit smb_distribution_points records.

## Acceptance Criteria

SMB collection enumerates REMINST share and finds boot media. Boot media is parsed and decryption attempted. On success: extracted MP added to target queue and policy secrets emitted.

