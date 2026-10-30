# Stop the whole run after one rejected sign-in

Status: approved by the owner on October 30, 2026 ("Go ahead and implement").
The owner's rule is to bail after a single invalid attempt. The shared parts and
the alternatives considered are in the shared library's
`docs/changes/2026-10-30-one-rejected-sign-in-per-run.md`. This note covers
what changed in SCCM.

## The problem

A lab run as `MAYYHEM\lowpriv` with a wrong password, one computer at a time:

| Run | Failed sign-ins | Run reported |
|---|---|---|
| ps1-sms, all collection methods | 42 | success |
| ps1-sms and ps1-mp, all methods | 82 | success |
| Both, per-computer methods only | 23 | success |

The logs showed where they came from. In the one-computer run, 18 directory
searches each signed in twice, which made 36. The shared directory client's
one-step bind dropped the `data 52e` reason code, so its stop rule never
fired. The other 6 came from ps1-sms itself. The logs show a Kerberos ticket request
for the AdminService web page, then NTLM for the same page, two WMI methods and
SMB. The sixth was not named in the logs. Nothing stopped the run, and every
computer repeated the pattern. The run then reported success.

## The fix

1. **Check the password once, first.**
   [`main.py`](../../src/openhound_sccm/main.py)
   `_check_credentials_before_collection` signs in to the domain controller once
   before discovery, through the shared `AdClient.confirm_credentials()`. A
   refusal ends the run with exit code 1 before anything else runs. The
   successful sign-in stays open and discovery reuses it.
2. **One record per run.** `SourceContext.credential_guard`
   ([context.py](../../src/openhound_sccm/context.py)) holds the shared
   library's `CredentialGuard`. [source.py](../../src/openhound_sccm/source.py)
   gives the same record to the directory client. `main.py` registers a stop
   action that stops the work queue, so no computer that has not started is
   visited. The shared engine then skips the remaining steps on computers
   already running.
3. **Every sign-in checks it first and reports definite refusals.**
   - SMB and remote registry: `connect_smb` in
     [clients/smb_sso.py](../../src/openhound_sccm/clients/smb_sso.py). A
     refused anonymous session is not reported, because it uses no account.
   - WMI: `_open` in [clients/wmi.py](../../src/openhound_sccm/clients/wmi.py).
     A refused Kerberos request ends the ladder, so NTLM never resubmits the
     same password.
   - AdminService: `_get_negotiate` in
     [clients/http.py](../../src/openhound_sccm/clients/http.py), with a new
     `ErrorClass.SIGN_IN_REFUSED` result. Again, Kerberos refusal ends the
     ladder.
   - SQL: `collect_mssql` in
     [collectors/mssql.py](../../src/openhound_sccm/collectors/mssql.py) skips
     its EPA probes after a refusal, because each probe is a sign-in.
4. **The run reports failure.** `_stop_if_credentials_rejected` ends the run
   with exit code 1 after discovery, after the per-computer stage, or when the
   stopped queue surfaces as an error. It names where the refusal happened.

"Access denied" and an AdminService `401` do not stop a run: a correct account
without access gets them too. Passwordless current-user runs have no typed-in
password, so they skip the first check.

## Checks

- SCCM: **1,265 passed**, 65 skipped, the same optional-tool skips as before
  (Go compiler, test database, HTTP target, SSO). Ruff and mypy found no problems.
- New [`tests/credential_stop_test.py`](../../tests/credential_stop_test.py),
  15 tests: SMB refusal stops the run, SMB is not attempted after another
  refusal, a refused anonymous session does not stop it, WMI and web Kerberos
  refusals never fall back to NTLM, WMI and web are not attempted after a
  refusal, EPA probes are skipped, the first check's four outcomes, the
  failure report, the queue stop, and the shared record's wiring through
  `source()`.
- [`tests/principal_resolution_referral_test.py`](../../tests/principal_resolution_referral_test.py):
  its stand-in for the directory library now accepts the step-by-step bind.
  What it checks, that referrals are never chased, is unchanged.

Lab, after the fix, same account, password and computers:

| Run | Failed sign-ins | Exit code |
|---|---|---|
| ps1-sms, all collection methods | 1 | 1 |
| ps1-sms and ps1-mp, all methods | 1 | 1 |
| Both, per-computer methods only | 1 | 1 |

With the correct password, ps1-sms collected 11 tables, the run reported
success, and the failed sign-in counter stayed at 0.

## Manual verification

```powershell
uv run pytest tests/credential_stop_test.py tests/ad_rejection_test.py tests/principal_resolution_referral_test.py -q
# In the lab: one failed sign-in and exit code 1.
uv run openhound collect sccm .\out-wrong -d mayyhem.com --dc dc.mayyhem.com -u "MAYYHEM\lowpriv" -p "deliberately-wrong" -c ps1-sms.mayyhem.com
$LASTEXITCODE
```

Evidence in the private feature work folder: `sccm-wrong-password-run-count-lab.txt`
(before), `sccm-wrong-password-run-count-after-fix-lab.txt` (after) and
`correct-password-run-check-lab.txt`, from `tests/sccm_wrong_password_run_count.ps1`
and `tests/correct_password_run_check.ps1`.
