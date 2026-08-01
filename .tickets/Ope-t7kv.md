---
id: Ope-t7kv
status: open
deps: []
links: [Ope-gqwo, Ope-o6bh, Ope-padv]
created: 2026-05-28T13:29:08Z
type: feature
priority: 1
assignee: Mayyhem
tags: [sccm, cred-2, http, credentials]
---

# CRED-2: Machine Account Registration and Policy Decryption (HTTP)

Implement the CRED-2 technique: register a machine account with SCCM and use the obtained certificate to request and decrypt device policy secrets (NAA credentials, collection variables, task sequence secrets). CLI flags for CRED-2 are defined but marked not yet implemented: --machine-name, --machine-pass, --client-name, --create-machine-account, --use-altauth, --registration-sleep.

## Design

Implement machine account creation via LDAP/AD (--create-machine-account). POST DDR record to http://<MP>/ccm_system/request for SCCM client registration. Obtain self-signed client identity certificate. Request device policy via http://<MP>/ccm_system_windowsauth/request. Decrypt policy body using SCCM key derivation. Extract NAA credentials, collection variables, task sequence variables. Yield as http_naa_secrets and http_collection_secrets records. Gate on method_enabled(HTTP).

## Acceptance Criteria

With valid machine account and reachable MP, NAA credentials are decrypted and emitted as EX_SecretPolicy edges. Machine account creation is optional. --registration-sleep introduces delay between registration and policy request.

## Notes

**2026-07-22T16:24:19Z**

CLI flags removed (2026-07-22) during the collect-sccm --help panel reorg. The six inert CRED-2 flags (--machine-name, --machine-pass, --client-name, --create-machine-account, --use-altauth, --registration-sleep) were deleted from the CLI because they did nothing. When implementing CRED-2, re-add them: (1) typer.Option definitions in main.py collect_sccm() — put them in a dedicated 'Machine Account' rich_help_panel; (2) _FLAG_TO_ENV entries (machine_name/machine_pass/client_name/create_machine_account/use_altauth/registration_sleep -> SOURCES__SCCM__*); (3) _TYPED_DLT_ENV entries for USE_ALTAUTH + REGISTRATION_SLEEP; (4) the matching --machine-*/--client-name/--create-machine-account/--registration-sleep entries in _LONG_OPTIONS_WITH_VALUES; (5) the source() factory params + coercion in source.py. The description above still lists them as 'defined but not yet implemented' — that is now stale; they are undefined until re-added.

**2026-07-31T15:38:22Z**

Status audit 2026-07-31: CORRECTLY OPEN, with one leftover to sweep when this is picked up. Confirmed the 2026-07-22 note: five of the six CRED-2 flags are genuinely gone from the CLI -- no --machine-name, --client-name, --create-machine-account, --use-altauth or --registration-sleep anywhere in main.py. But '--machine-pass' still survives as a string in _SENSITIVE_OPTIONS (main.py:222), the set that masks values as <value> in the split-value CLI warnings. It is harmless today (you cannot pass a flag that does not exist, so the entry can never fire) but it is a false signal that the flag is still supported, and it should either be deleted now or be the anchor you re-add the other five around. The rest of the re-add checklist in the 2026-07-22 note stands: typer.Option definitions under a dedicated 'Machine Account' rich_help_panel, _FLAG_TO_ENV entries, _TYPED_DLT_ENV entries for USE_ALTAUTH + REGISTRATION_SLEEP, _LONG_OPTIONS_WITH_VALUES entries, and the source() factory params plus coercion.
