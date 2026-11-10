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

Last run exactly as written: November 4, 2026, on ps1-dev as
`MAYYHEM\domainadmin`. The commands were copied from this section and run in
order in one fresh PowerShell session. Every result matched what is shown here.
Step 5 took about 20 seconds.

### Before you start

- Use ps1-dev, signed in to Windows as `MAYYHEM\domainadmin`, and open a new
  PowerShell window. Paste the steps in order into that one window, because
  later steps reuse what earlier steps saved, such as `$out`.
- The collection runs as `MAYYHEM\lowpriv`, first with a wrong password. The
  lab domain never locks accounts, so this is safe. The counter checks run as
  you, `domainadmin`.
- Every `uv run` command includes
  `--with-editable C:\Users\domainadmin\openhound-collector-common`. That tells
  uv to use your local copy of the shared library for that one command. This
  change needs shared-library code that hasn't been published yet. Without it,
  uv uses the published copy, and the commands fail with
  `ModuleNotFoundError: No module named 'openhound_collector_common. ...'`.
  Once the shared library is published with these changes, that part can be
  dropped.
- Each run saves its results in a new folder in your Windows temp folder, named
  with the time. So runs never mix, and nothing is added to the repository.

### Step 1: Run the wrong-password tests

```powershell
Set-Location C:\Users\domainadmin\ConfigManBearPig
uv run --locked --with-editable C:\Users\domainadmin\openhound-collector-common pytest tests\credential_stop_test.py tests\ad_rejection_test.py tests\principal_resolution_referral_test.py -q
```

**You should see** `19 passed` on the last line.

### Step 2: Start lowpriv's failed sign-in count at 0

This signs in once as `lowpriv` with the correct password, which resets the
domain controller's count.

```powershell
.\tests\scripts\reset_failed_sign_in_count.ps1 -Account lowpriv -Password password
```

**You should see** `Failed sign-ins counted for lowpriv: 0`.

### Step 3: Collect two computers with a wrong password

```powershell
$out = "$env:TEMP\openhound-checks\sccm-wrong-password-$(Get-Date -Format yyyyMMdd-HHmmss)"
uv run --locked --with-editable C:\Users\domainadmin\openhound-collector-common openhound collect sccm $out -d mayyhem.com --dc dc.mayyhem.com -u "MAYYHEM\lowpriv" -p "deliberately-wrong" -c ps1-sms.mayyhem.com,ps1-mp.mayyhem.com
$LASTEXITCODE
Select-String -Path "$out\collect_full_*.log" -Pattern 'rejected' | ForEach-Object { $_.Line -replace '^.*msg=', '' }
```

**You should see** `1`, meaning the run failed, and then these lines from the
run's log:

```text
The LDAP bind was rejected
The domain controller dc.mayyhem.com rejected the supplied sign-in details; stopping the whole run so the account is not tried again
Stopping target scheduling: The supplied sign-in details were rejected; no further sign-ins were attempted
The sign-in details were rejected before any computer was visited
The supplied sign-in details were rejected or could not be used. Nothing was collected and no other sign-in was attempted. Check the user name and password, then run again.
```

### Step 4: Count the failed sign-ins

```powershell
.\tests\scripts\get_failed_sign_in_count.ps1 -Account lowpriv
```

**You should see** `Failed sign-ins counted for lowpriv: 1`. Before this
change, the same run cost 82: every collection method on both computers tried
the wrong password.

### Step 5: With the correct password, nothing is stopped and nothing is counted

This collects one computer for real, so it takes longer than step 3.

```powershell
.\tests\scripts\reset_failed_sign_in_count.ps1 -Account lowpriv -Password password
$out = "$env:TEMP\openhound-checks\sccm-correct-password-$(Get-Date -Format yyyyMMdd-HHmmss)"
uv run --locked --with-editable C:\Users\domainadmin\openhound-collector-common openhound collect sccm $out -d mayyhem.com --dc dc.mayyhem.com -u "MAYYHEM\lowpriv" -p "password" -c ps1-sms.mayyhem.com
$LASTEXITCODE
.\tests\scripts\get_failed_sign_in_count.ps1 -Account lowpriv
```

**You should see:**

- `Failed sign-ins counted for lowpriv: 0` after the reset;
- `0` when the collection finishes, meaning it succeeded;
- `Failed sign-ins counted for lowpriv: 0` again.

### What these steps prove

- **One wrong password costs one failed sign-in per run, however many
  computers and collection methods there are.** Step 4 shows 1 where there
  used to be 82.
- **The run reports failure.** Step 3 ends with `1`.
- **A correct password is not mistaken for a wrong one.** In step 5, the run
  finishes and the count stays at 0.

### Clean up

Step 5 already left the count at 0. To delete the saved check results:

```powershell
Remove-Item "$env:TEMP\openhound-checks" -Recurse -Force
```

Earlier lab evidence, from before these steps existed, is in the private
feature work folder: `sccm-wrong-password-run-count-lab.txt` (before),
`sccm-wrong-password-run-count-after-fix-lab.txt` (after) and
`correct-password-run-check-lab.txt`.
