---
id: ope-fbb0
status: closed
deps: []
links: [ope-7da1]
created: 2026-07-17T15:49:28Z
type: task
priority: 2
tags: [sccm]
---

# Route ALL SCCM collection traffic through --socks-proxy (shared interception)

Implement --socks-proxy so ALL SCCM collection traffic (discovery + all five per-host protocols) tunnels through a SOCKS5 pivot, via shared openhound-collector-common interception. Plan: sccm/sccm/docs/superpowers/plans/2026-07-15... see 2026-07-17-socks5-proxy-all-collection-traffic.md

## Notes

**2026-07-20T17:31:09Z**

COMPLETE + committed by owner. --socks-proxy routes ALL collection traffic (discovery + every per-host protocol) through a SOCKS5 pivot via a process-wide stdlib-socket interception in openhound-collector-common (proxy/patch.py + socks.py + discovery/dns.py force_tcp). SCCM side: parse/validate (--dc or --dns required), install-around-run wrapping DC discovery->Stage2, 4 proxy-aware DNS sites. Offline spike proved ldap3/requests/impacket all funnel through it (socks5h, no DNS leak). Tests: shared-lib 18 + SCCM proxy suite 15 green. Native SSPI/OS-Kerberos not tunnelable (documented limit; use --ticket or OS-level transparent proxy). Live-lab validation pending: sccm/sccm/spike_socks_proxy.md. Plan: sccm/sccm/docs/superpowers/plans/2026-07-17-socks5-proxy-all-collection-traffic.md. Follow-up: ope-7da1 (MSSQL). Note: README/ARCHITECTURE were entangled with ope-b916 at authoring time.
