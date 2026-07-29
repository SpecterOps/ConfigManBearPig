---
id: ope-cc0f
status: closed
deps: []
links: []
created: 2026-07-22T14:41:47Z
type: task
priority: 2
tags: [sccm]
---

# Rename --socks-proxy flag to -x / --proxy

CLI-facing rename of the SOCKS5 pivot flag: --socks-proxy becomes -x (short) / --proxy (long). Help text set to 'SOCKS5 proxy address (host:port or socks5://[user:pass@]host:port). Requires --dc or --dns.' Python param stays socks_proxy so SOURCES__SCCM__SOCKS_PROXY env var and all plumbing are untouched. -x/--proxy registered in the _SHORT_OPTIONS_WITH_VALUES/_LONG_OPTIONS_WITH_VALUES typo-detection tables. Per no-backward-compat rule, --socks-proxy no longer works. Updated main.py option + error strings, README (Network row, Limitations, Proxying/pivoting), ARCHITECTURE.md (§13 prose + changelog), spike_socks_proxy.md runbook commands, and proxy_wiring_test docstring.

## Notes

**2026-07-22T14:41:55Z**

COMPLETE. Validated with SCCM .venv: 9/9 proxy_wiring_test.py pass; introspection confirms collect_sccm param_decls == ['-x','--proxy'], --socks-proxy removed, arg-preprocessor tables + _FLAG_TO_ENV['socks_proxy']=SOURCES__SCCM__SOCKS_PROXY intact. Awaiting owner commit/push.

**2026-07-22T15:05:42Z**

Follow-ups (owner-requested): (1) added -x/--proxy to _SENSITIVE_OPTIONS so a socks5://user:pass@host:port value is masked as <value> in the split-value CLI warnings, matching -p/--password; verified masking + 5/5 test_cli_argument_warnings.py. (2) removed stale --sms reference in spike_socks_proxy.md (now just -c; --sms was deleted under ope-b1e8) -- confirmed no remaining --sms outside docs/.
