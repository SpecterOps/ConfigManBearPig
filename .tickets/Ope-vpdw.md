---
id: Ope-vpdw
status: closed
deps: []
links: []
created: 2026-05-29T14:25:26Z
type: feature
priority: 2
assignee: Mayyhem
---
# Add --resolver option for custom DNS nameserver

Add a --dns-resolver CLI flag that lets the user specify a DNS nameserver IP to use for ALL lookups, including locating a domain controller, _resolve_dc_via_dns(), etc. instead of relying on the system default (which is often the DC itself). Useful when enumerating from a machine whose DNS does not point at Active Directory.

## Acceptance Criteria

- --dns-resolver <ip> flag accepted by the CLI\n- dns.resolver.Resolver(configure=False) used with the provided nameserver when flag is set\n- System default DNS used when flag is omitted (no behavior change)

