# ConfigManBearPig - Python SCCM Collector

Python port of the ConfigManBearPig PowerShell SCCM data collector for BloodHound OpenGraph.

Translated from: PowerShell (`ConfigManBearPig.ps1`)

## Requirements

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) package manager
- Network access to Active Directory and SCCM infrastructure
- Domain credentials (explicit credentials supported for proxychains)

## Installation

```bash
cd collector_python
uv sync
```

## Usage

### Full collection with explicit credentials (proxychains compatible)

```bash
uv run python configmanbearpig.py \
    -d mayyhem.com \
    -dc 10.2.10.100 \
    -u 'MAYYHEM\domainadmin' \
    -p password
```

### Through proxychains

```bash
proxychains uv run python configmanbearpig.py \
    -d mayyhem.com \
    -dc 10.2.10.100 \
    -u 'MAYYHEM\domainadmin' \
    -p password
```

### AdminService only against specific SMS Provider

```bash
uv run python configmanbearpig.py \
    -d mayyhem.com \
    -dc 10.2.10.100 \
    -u 'MAYYHEM\domainadmin' \
    -p password \
    -m AdminService \
    -sms cas-pss.mayyhem.com
```

### Specific collection methods

```bash
uv run python configmanbearpig.py \
    -d mayyhem.com \
    -dc 10.2.10.100 \
    -u 'MAYYHEM\domainadmin' \
    -p password \
    -m LDAP,DNS,MSSQL,AdminService,HTTP,SMB
```

### Low-privilege user (limited collection)

```bash
uv run python configmanbearpig.py \
    -d mayyhem.com \
    -dc 10.2.10.100 \
    -u 'MAYYHEM\domainuser' \
    -p password
```

### Generate custom node types JSON

```bash
uv run python configmanbearpig.py --custom-nodes
```

## Configuration

| Argument | Description | Default |
|----------|-------------|---------|
| `-d`, `--domain` | Domain name | Required |
| `-dc`, `--domain-controller` | DC hostname/IP | Auto-discovered |
| `-u`, `--username` | DOMAIN\\user | Current context |
| `-p`, `--password` | Password | Current context |
| `-m`, `--collection-methods` | Collection methods | All |
| `-c`, `--computers` | Target computers | None |
| `-cf`, `--computer-file` | File of targets | None |
| `-sms`, `--sms-provider` | SMS Provider FQDN | None |
| `-sc`, `--site-codes` | Site codes for DNS | None |
| `--disable-possible-edges` | Conservative edges | False |
| `--enable-bad-opsec` | Enable risky ops | False |
| `-o`, `--output` | Output directory | Current dir |
| `--log-file` | Log file path | ConfigManBearPig_output.log |
| `-v`, `--verbose` | Verbose output | False |

## Collection Methods

| Method | Type | Description |
|--------|------|-------------|
| LDAP | Once | System Management container, SPNs, naming patterns |
| Local | Once | Local SCCM client detection, log parsing |
| DNS | Once | SRV records for management points |
| DHCP | Once | PXE/DHCP discovery (stub) |
| RemoteRegistry | Per-host | Registry queries for site config, EPA, signing |
| MSSQL | Per-host | TDS PRELOGIN for EPA detection |
| AdminService | Per-host | REST API for full SCCM data collection |
| WMI | Per-host | WMI queries (stub, fallback for AdminService) |
| HTTP | Per-host | HTTP endpoint probing for MP/DP/SMS Provider |
| SMB | Per-host | Share enumeration for SCCM roles |

## Output

Produces BloodHound OpenGraph JSON files packed into a ZIP archive:

- `computers.json` - Computer nodes
- `groups.json` - Group nodes
- `users.json` - User nodes
- `sccm.json` - SCCM-specific nodes + all edges
- `seed_data.json` - Edge kind declarations

Output file: `bloodhound-sccm-YYYYMMDD-HHMMSS.zip`

## Translation Notes

### Key differences from PowerShell version

1. **Authentication**: Uses `ldap3` with NTLM auth instead of .NET AD module/ADSI. Supports explicit credentials for proxychains.

2. **MSSQL EPA Detection**: Uses raw TDS PRELOGIN packet construction (pure Python) instead of the C# SSPI hooking approach. This is more portable and doesn't require Windows-specific APIs.

3. **SMB Operations**: Uses `impacket` for share enumeration and SMB signing detection instead of .NET NetAPI32 P/Invoke.

4. **Remote Registry**: Uses `impacket` RRP (Remote Registry Protocol) instead of PowerShell remote registry cmdlets.

5. **HTTP Probing**: Uses `requests` with `requests-ntlm` for NTLM auth instead of `Invoke-RestMethod`.

6. **Local Collection**: Limited on non-Windows platforms (SCCM client detection requires Windows). Log parsing works cross-platform.

7. **DHCP/WMI**: Stub implementations matching the PowerShell version's in-progress status.

8. **Output Format**: Produces identical BloodHound OpenGraph JSON format with streaming writers.

### Library mapping

| PowerShell | Python |
|-----------|--------|
| `Invoke-RestMethod` | `requests` + `requests_ntlm` |
| `[System.DirectoryServices]` | `ldap3` |
| `NetAPI32` P/Invoke | `impacket.smbconnection` |
| `Resolve-DnsName` | `dns.resolver` |
| Remote Registry cmdlets | `impacket.dcerpc.v5.rrp` |
| TDS + SSPI C# interop | Pure Python TDS PRELOGIN |
| `ConvertTo-Json` | `json.dump()` |
| `Add-Type` (C#) | Not needed (pure Python) |

## Architecture

```
configmanbearpig.py          # Main entry point (argparse, orchestration)
lib/
    __init__.py
    logging_utils.py         # Colored console + file logging
    graph.py                 # GraphStore with upsert node/edge merge semantics
    ad_resolver.py           # LDAP-based AD object resolution
    targets.py               # Target management with dedup and allow-list
    pipeline.py              # Phase orchestration (once + per-host)
    post_processing.py       # Hierarchy detection, edge creation
    output.py                # Streaming JSON writer, ZIP packaging
    collectors/
        __init__.py
        ldap_collector.py    # System Management container, SPNs
        local_collector.py   # Local SCCM client detection
        dns_collector.py     # SRV record queries
        dhcp_collector.py    # DHCP discovery (stub)
        registry_collector.py # Remote registry queries
        mssql_collector.py   # TDS PRELOGIN, MSSQL node hierarchy
        adminservice_collector.py # REST API collection
        wmi_collector.py     # WMI queries (stub)
        http_collector.py    # HTTP endpoint probing
        smb_collector.py     # Share enumeration
```
