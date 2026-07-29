---
id: ope-ec50
status: closed
deps: []
links: []
created: 2026-07-15T14:36:55Z
type: bug
priority: 1
---

# Fix SCCM_ClientDevice name missing @siteCode suffix

SCCM_ClientDevice.name was the bare netbios name (e.g. 'PS1-DEV') but the @site-suffixed form ('PS1-DEV@PS1') was only in displayname. CMBP names client devices '<netbios>@<siteCode>' (device can be a client of multiple sites), and the kit resolves devices by name, so HasClient/HasMember/HasPrimaryUser/HasADLastLogonUser all failed. FIX: models/sccm_client_device.py sets name=display (the @site form). Recovered 4 tests, 0 blast radius.
