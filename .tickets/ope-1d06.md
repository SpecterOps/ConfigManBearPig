---
id: ope-1d06
status: closed
deps: []
links: [ope-60fe]
created: 2026-07-29T19:21:09Z
type: bug
priority: 2
tags: [logging, adminservice, sccm]
---

# AdminService read timeout silently reported as 'Collected 0'

An AdminService read timeout was reported to the user as an accurate empty result. In collectors/privileged.py, _http_get_value logged ErrorClass.CONNECT_FAILURE (which per clients/http.py covers dead socket, DNS, refused AND timeout) at VERBOSE, while every other failure class logged WARNING. The caller then reported 'Collected 0 <things>' at INFO. Net effect: a timed-out query produced a silently incomplete graph indistinguishable from a complete one, with nothing in the issues log. Observed live 2026-07-29: SMS_SCI_Reserved timed out on all three site servers (cas-pss, ps1-sms, ps1-pss) at the 5-second read timeout, silently dropping two SCCM_HasStoredAccount edges and emptying SCCM_Site.storedAccounts and User.storedInSCCMSite. Also violates the project rule requiring an appropriately-levelled log for every branch. FIXED three ways: (1) CONNECT_FAILURE now logs WARNING when collecting, with a new probing=True parameter that keeps it VERBOSE for _http_identify -- that function's entire job is testing whether a host is an AdminService provider, so a connect failure there is an expected negative and a warning per candidate host would be pure noise (this asymmetry is why the level was too low in the first place); (2) the _http_fetch paging loop now distinguishes None (request failed) from [] (genuinely no rows) and warns with how many rows it did manage, since a partial page is more misleading than a total failure -- the count looks plausible; (3) the HTTP client connect/read timeout raised 5s -> 10s at owner's direction, since SMS_SCI_Reserved exceeded 5s on every site server in a healthy lab. Found while validating openhound 0.2.12 under ope-60fe; version-independent and pre-existing.

## Acceptance Criteria

A timed-out AdminService collection produces a WARNING in the issues log naming the URL, plus a WARNING naming the class and the row count reached. Provider identification (_http_identify) still logs connect failures at VERBOSE so non-provider hosts produce no warnings. Timeout is 10s.
