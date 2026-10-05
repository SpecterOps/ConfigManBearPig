---
id: con-46f6
status: closed
deps: []
links: []
created: 2026-09-08T00:00:00Z
type: bug
priority: 1
tags: [real-env, ldap, dlt]
---

# ldap_resolved_principals failed to persist entirely against a real environment

Found during a real-environment (non-lab) assessment: `dlt.common.schema.exceptions.DataValidationError`:
`In schema sccm: In Table: ldap_resolved_principals Column: service_principal_name__v_text .
Contract on data_type with contract_mode=freeze is violated. Can't add variant column
service_principal_name__v_text for table ldap_resolved_principals because data_types are frozen.`

Reproduced identically across two separate, fresh (non-reused) output directories, ruling
out stale pipeline state. dlt infers a JSONL column's type from the rows it sees and, when
a later row needs a different type, normally just adds a `<col>__v_<type>` variant column
to hold it. `ldap_resolved_principals`'s schema contract is `contract_mode=freeze`
(deliberately, to catch data-shape regressions early), so the promotion is rejected and the
**entire load job fails, not just the offending row**, meaning zero rows land for the whole
table.

Root cause: `ADClient._entry_to_dict` (`clients/ad.py:201`,
`values if len(values) > 1 else values[0]`) collapses any LDAP multi-valued attribute to a
bare scalar when there's exactly one value (an absent attribute is set to `None` earlier).
`servicePrincipalName` is inherently multi-valued and its cardinality varies per-principal
in any real domain (a user often has 0 or 1, a site server carries many), so across one
real collect, `context.py`'s `_record_resolved_principal` was handing dlt `None`, a bare
string, and a list for the same column across different rows. Wiped AD node naming
(44/50 AD nodes emitted as bare stubs) and the SPN-based MSSQL-server discovery fallback.

## Fix

New `_as_multivalued_list()` helper in `context.py`, applied to both `service_principal_name`
and `object_class` in `_record_resolved_principal`, coercing `None`/scalar/list to
always-a-list before the row is recorded. Matches what `transforms.py`'s `ad_props` builder
already assumed for both columns. `contract_mode=freeze` itself is left untouched; the bug
was upstream data-shape inconsistency, not an over-strict contract.

## Notes

**2026-09-08T00:00:00Z**

Fixed and tested. New tests in `tests/ldap_resolved_principals_test.py`:
`test_service_principal_name_scalar_is_normalized_to_list`,
`test_service_principal_name_none_is_normalized_to_empty_list`,
`test_object_class_scalar_is_normalized_to_list`,
`test_resolved_principals_have_consistent_spn_type_across_mixed_cardinality` (the direct
regression guard: records principals with 0/1/many SPNs in one run and asserts every
recorded row's type is a list).
