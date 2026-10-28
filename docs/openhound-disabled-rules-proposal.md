# Proposal: honor disabled privilege-zone rules in OpenHound uploads

Status: **proposal only; owner approval required before OpenHound edits**.
Prepared on 2026-10-22. No OpenHound or collector-common files were changed.

## Problem and observed evidence

ConfigManBearPig's optional administrator rule has `enabled: false`. Its purpose
is to let users preview broad SCCM administration without automatically moving
those sources into Tier Zero and hiding their access to protected targets.

OpenHound reads this flag in
`src/openhound/core/models/privilege_zone.py:16`, but
`src/openhound/destinations/bloodhound/destination.py:93` builds a selector request
containing only its name, description, and query seeds. Both create and overwrite
use that body. Neither `enabled` nor BloodHound's `disabled` setting is sent.

This was checked against installed OpenHound **0.2.12** and the local checkout
at commit `86770f0d336b0a6b5fa6683974aa10577cddc301`. An offline call to the
installed uploader captured both create and overwrite requests for the actual
SCCM rule. Both omitted the state despite an input value of `enabled: false`.
The check made zero network requests. Captured evidence is outside the repository
at `C:\Users\domainadmin\.tmp\cmbp-pz-uploader-evidence.json`.

The previous SCCM live tests used enabled rules, so they did not establish that
disabled defaults were honored. A successful upload is not proof of a disabled
installed rule.

## Why OpenHound is the right place

The shared OpenHound uploader owns conversion from every extension's rule file
to BloodHound requests. Fixing it once gives every collector the same behavior.
Changing ConfigManBearPig collection, its graph schema, or collector-common would
put upload policy in an unrelated layer and leave other extensions affected.

The proposed edit is limited to `C:\Users\domainadmin\OpenHound`. There is no
collector-common change and no new dependency.

## Verified BloodHound contract

The official API definitions were read on 2026-10-22:

- [Create request](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/openapi/src/schemas/model.asset-group-tags-selector-create-request.yaml)
  inherits the selector's base fields and requires name and seeds. The
  [base fields](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/openapi/src/schemas/model.asset-group-tags-selector-base.yaml)
  do not include a disabled setting.
- [Update request](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/openapi/src/schemas/model.asset-group-tags-selector-request.yaml)
  accepts `disabled: boolean` along with the base fields.
- [Update endpoint](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/openapi/src/paths/asset-isolation.asset-group-tags.id.selectors.id.yaml)
  uses PATCH and updates only supplied properties.
- [Selector response](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/openapi/src/schemas/model.asset-group-tags-selector-response.yaml)
  exposes `disabled_at`; a disabled selector has a disable timestamp. The earlier
  lab response used null for an enabled selector.

Adding `enabled: false` to a create request would therefore not implement the
documented contract. Forwarding `disabled: true` on creation alone is also not
supported by that contract. The installed lab reports version `v999.999.999`.
A subsequent owner-requested manual upload on 2026-10-22 confirmed that PATCH
accepts the real query together with `disabled: true`, stores the disabled state,
and excludes the rule from analysis. Its membership endpoint returns HTTP 409
with `selector is disabled`. The shared uploader implementation and its full
failure/retry behavior still require validation after approval and implementation.

## Proposed behavior

| Rule and upload situation | Result |
|---|---|
| New rule with `enabled: true` | Create normally and verify it is enabled. |
| New rule with `enabled: false` | Create with a query that selects nothing, then PATCH the real query and `disabled: true` together. Verify the disabled state. |
| Existing rule with the default skip strategy | Leave its query and enabled state unchanged. |
| Existing rule with overwrite strategy | PATCH the reviewed name, description, real query, and `disabled: not enabled` together. Verify the requested state. |

For a new disabled rule, the temporary query would be:

```cypher
MATCH (n) WHERE false RETURN n
```

The create API cannot express a disabled rule, so creating the real query first
and disabling it afterward could allow analysis to classify objects between
those requests. Creating a query that selects nothing avoids that gap. The
subsequent PATCH installs the real query while disabling the selector in the
same request. This uses the existing supported API rather than adding a second
collector-specific uploader.

If the final PATCH fails, report the upload as failed and leave the new empty
selector for inspection. It must not select the actual administrator objects or
silently report success. A retry with overwrite should finish the operation;
a retry with skip should report that the existing selector was left unchanged.
No analysis request is added to the uploader.

State verification must check that the returned selector ID and disabled state
match the request. If an API version does not return enough information, retrieve
the selector or fail clearly rather than treating an unknown state as success.
Validate the response at the client boundary; do not spread unchecked response
dictionaries throughout upload logic. Log creation, overwrite, skip, state
verification, and every failure in plain English.

`allow_disable` is separate from the requested enabled state. The public API
exposes it as response metadata, with no corresponding writable field in the
create/update definitions above. This change must not claim to enforce that
flag. Every SCCM rule currently sets it to true. Supporting other values should
be discussed separately rather than sending an undocumented property.

## Files to change after approval

- `src/openhound/destinations/bloodhound/destination.py`: honor the flag, handle
  new disabled rules without briefly installing their active query, and surface
  failures and verified state.
- `src/openhound/core/clients/models/asset_groups.py` and, if necessary,
  `src/openhound/core/clients/bloodhound.py`: validate the relevant selector
  response fields and expose only the small response/read operation needed for
  verification. Keep other BloodHound behavior unchanged.
- `tests/test_pz_selector_sync.py` and its existing fixtures: model the real
  disabled-state contract, assert outgoing bodies and call ordering, and cover
  failure/retry behavior.
- OpenHound's rule-upload documentation: explain new versus existing rules,
  skip versus overwrite, and the disabled-state guarantee and errors.

The rule-file format and command-line options remain unchanged. No query
rewriting, automatic removal of renamed rules, or automatic analysis is added.

## Effects on other extensions and users

Enabled rules retain their current normal creation behavior. Disabled rules
will finally stay out of zone membership when newly installed. Existing rules
remain unchanged under skip. Overwrite explicitly applies the file's enabled
state: it can disable an active rule or re-enable a manually disabled rule when
the file says `enabled: true`. That consequence must be clear in the command's
documentation and logs.

A failed new-disabled-rule upload can leave a named selector whose query matches
nothing. The error must identify that selector and explain retrying with
overwrite. This is preferable to leaving an active real query or silently
discarding the optional rule. Normal create and successful overwrite do not
change other selectors.

## Alternatives considered

- **Skip every disabled file:** avoids activating it, but the optional rule is
  absent from Zone Builder and existing active copies remain active. Suitable
  only as a temporary filtered-upload workaround, not complete state handling.
- **Create the real rule, then disable it:** allows a period in which analysis
  can use the real query. Rejected for the disabled-default guarantee.
- **Put a false condition in the shipped SCCM query:** makes ordinary previews
  and subsequent enabling misleading. Rejected.
- **Add an SCCM upload script:** duplicates shared behavior and leaves the same
  issue in other collectors. Rejected.
- **Send undocumented create fields:** assumes server behavior outside the
  verified API. Rejected.

## Validation before considering the fix complete

The implementation should pass focused OpenHound tests for enabled/disabled
creation, both overwrite directions, skip preserving existing state, a failed
second request leaving an empty selector, verification failures, and successful
retry. Tests must inspect state after the first create request to establish that
no real matching query was installed during the gap.

Then, against the authorized BloodHound lab, install a uniquely named test rule
whose real query matches a known object. Confirm that it is stored as disabled
and that analysis does not classify that object through it. Explicitly enable
it and verify membership, then disable it through overwrite and verify removal.
Remove only that test rule and restore the prior test state. Do not clear the
owner's restored sample data or unrelated selectors.

Those are proposed implementation checks, not tests already completed. This
proposal's completed evidence is source inspection, authoritative API review,
the offline captured-request reproduction, and the subsequent manual disabled-rule
installation. The collector's revised rule
tests are documented separately in the sample validation report.

## Approval requested

Approve the bounded OpenHound uploader, response validation, focused tests, and
documentation changes above. Approval to prepare this proposal did not authorize
editing OpenHound. The workspace's AGENTS.md requires the owner's review and
approval before any shared-repository edits.
