# Visit each computer once, by its full name

Status: approved by the owner on October 30, 2026: "We shouldn't be visiting a
computer by its short name if the fqdn is successful."

## The problem

The October 30 wrong-password lab run, with ps1-sms and ps1-mp allowed, visited
ps1-mp twice: once as `ps1-mp` and once as `ps1-mp.mayyhem.com`. Each visit
signed in separately. Kerberos for the AdminService page, two WMI methods and
SMB each failed once under each name, which doubled that computer's failed
sign-ins.

`register_target` merges two names only when the directory returns the same
computer ID (SID). That run's directory lookups were failing, so there was no ID,
and the two spellings looked like two computers. Local discovery on the
collector had registered both forms.

The rejected-password fix from earlier that day stops a wrong password before
discovery, so this can no longer double failed sign-ins in that case. But it
still caused two visits, two sets of sign-ins and duplicate data whenever the
domain controller could not confirm names, even with the correct password.

## The fix

In [`context.py`](../../src/openhound_sccm/context.py) `register_target`, for a
name the directory could not confirm:

1. **A short name joins a known full name.** If exactly one registered computer
   has a full name starting with it (`ps1-mp` and `ps1-mp.mayyhem.com`), it is
   the same computer. No lookup is needed. See `_registered_full_name_for`.
2. **Otherwise the run's domain is added, if that name exists.** `ps1-mp`
   becomes `ps1-mp.mayyhem.com` when the full name is in DNS, and a later
   registration of the full name finds the same entry. If the full name is not
   in DNS, the short name is kept as given. It may belong to another domain, and
   a full name that is not in DNS could not be visited anyway. Without a known
   domain, the short name stays. See `_full_name_for_short_name`, which makes
   one lookup with the existing proxy-aware `resolve_ip`.
3. **The short name stays a known name** for the entry it joined or was expanded
   to, so code that looks computers up by either name finds one entry.
4. **Only bare computer names change.** SIDs, `DOMAIN\name`, distinguished names
   and IP addresses are never given a domain (`_is_short_computer_name`).

Names the directory confirms are unchanged: they already merge by SID and use
the directory's full name.

## Alternatives considered

- **Look up every unconfirmed short name in DNS and merge by address.**
  Rejected: different computers can share an address, such as behind a load
  balancer. It would also cost a lookup per name.
- **Always add the run's domain, with no DNS check.** Rejected: a short name
  from another domain would then be visited by a full name that does not exist.
  An earlier draft of this fix also added the domain when neither name was in
  DNS. That only renamed computers that could not be reached, and it broke two
  existing integration tests, so it was dropped.
- **Visit by short name, then skip the full name.** Rejected: the owner's rule
  is to prefer the full name.

## Limit

A short name that was kept because its full name was not in DNS is not merged
with a different full name registered later, such as `ps1-mp.child.mayyhem.com`.
That could be a different computer, so merging would be a guess.

## Checks

- New [`tests/target_name_merge_test.py`](../../tests/target_name_merge_test.py), 9 tests:
  - short name first, then full name;
  - full name first, then short name, with no lookup;
  - short name kept, with one lookup, when the full name is not in DNS;
  - no domain known;
  - a short name matching two full names;
  - SIDs, `DOMAIN\name` and addresses left alone.
- [`tests/per_host_integration_test.py`](../../tests/per_host_integration_test.py)
  uses made-up computers. A new fixture there stops their names being looked up
  in DNS. Its expectations are unchanged.
- SCCM full suite: **1,274 passed**, 65 skipped for optional test tools. Ruff
  and mypy found no problems.
- **Lab** (`sccm-double-visit-lab.txt` in the private feature work folder):
  - Setup: the domain controller was set to the collector itself, 10.10.11.10,
    which runs no directory, so lookups failed. The run used the correct
    `lowpriv` password and allowed ps1-sms and ps1-mp.
  - The log showed `Treating 'ps1-mp' as 'ps1-mp.mayyhem.com': it matches that
    computer's full name`.
  - Only `ps1-mp.mayyhem.com` and `ps1-sms.mayyhem.com` were visited.
  - The failed sign-in counter stayed at 0, and the run succeeded.

## Manual verification

Last run exactly as written: November 2, 2026, on ps1-dev as
`MAYYHEM\domainadmin`. The commands were copied from this section and run in
order in one fresh PowerShell session. Every result matched what is shown here.

### Before you start

- Use ps1-dev, signed in to Windows as `MAYYHEM\domainadmin`, and open a new
  PowerShell window. Paste the steps in order into that one window, because
  later steps reuse what earlier steps saved, such as `$out`.
- Every `uv run` command includes
  `--with-editable C:\Users\domainadmin\openhound-collector-common`. That tells
  uv to use your local copy of the shared library for that one command. The
  SCCM collector already relies on shared-library code that hasn't been
  published yet. Without it, uv uses the published copy, and the commands fail
  with `ModuleNotFoundError: No module named 'openhound_collector_common. ...'`.
  Once the shared library is published, that part can be dropped.
- Each run saves its results in a new folder in your Windows temp folder, named
  with the time. So runs never mix, and nothing is added to the repository.

### Step 1: Run the name-merging tests

```powershell
Set-Location C:\Users\domainadmin\ConfigManBearPig
uv run --locked --with-editable C:\Users\domainadmin\openhound-collector-common pytest tests\target_name_merge_test.py tests\per_host_wiring_test.py tests\per_host_integration_test.py -q
```

**You should see** `23 passed, 146 warnings` on the last line. The warnings
are a notice from a library the tests use, about a feature it will drop in a
future version. They're not failures.

### Step 2: Collect two computers while directory lookups fail

The problem only happens when the collector can't look computers up in the
directory. To cause that, this names ps1-dev itself (10.10.11.10) as the domain
controller. ps1-dev runs no directory, so every lookup fails. The password is
correct. `-t 1` visits one computer at a time, which keeps the log in order.

The command names ps1-mp by its short name, `ps1-mp`. Discovery on ps1-dev
finds it by its full name, `ps1-mp.mayyhem.com`, so the collector is given both
spellings of the same computer. On October 30, discovery happened to find the
short name by itself. On November 2 it found only the full name, so the command
supplies the short name to make the check repeatable.

```powershell
$out = "$env:TEMP\openhound-checks\sccm-one-visit-$(Get-Date -Format yyyyMMdd-HHmmss)"
uv run --locked --with-editable C:\Users\domainadmin\openhound-collector-common openhound collect sccm $out -d mayyhem.com --dc 10.10.11.10 -u "MAYYHEM\lowpriv" -p "password" -c ps1-sms.mayyhem.com,ps1-mp -t 1
$LASTEXITCODE
```

**You should see** `0` when it finishes, meaning it succeeded. It takes about
two minutes, because every directory lookup has to fail first.

### Step 3: Show which computers were visited

```powershell
.\tests\scripts\show_computers_visited.ps1 -OutputFolder $out
```

**You should see:**

```text
Short names treated as full names:
  Treating 'ps1-mp' as 'ps1-mp.mayyhem.com'
Computers visited:
  ps1-mp.mayyhem.com
  ps1-sms.mayyhem.com
```

**If you see** `ps1-mp` on its own under "Computers visited", the computer was
visited twice. That's the problem this change fixes.

### What these steps prove

- **A short name is joined to its full name.** In step 3, the collector
  treated `ps1-mp` as `ps1-mp.mayyhem.com`, because that full name was already
  known and the directory couldn't say otherwise.
- **Each computer is visited once, by its full name.** Step 3 lists
  `ps1-mp.mayyhem.com` and `ps1-sms.mayyhem.com` only. Before this change,
  ps1-mp was also visited a second time as `ps1-mp`, with a second set of
  sign-ins.

### Clean up

To delete the saved check results:

```powershell
Remove-Item "$env:TEMP\openhound-checks" -Recurse -Force
```
