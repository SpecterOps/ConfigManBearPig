---
id: con-401c
status: closed
deps: []
links: []
created: 2026-07-31T15:07:47Z
type: bug
priority: 1
tags: [logging, diagnostics, cli]
---

# Collector console log output does not reach redirected stdout

A collection run redirected to a file produces 0 bytes on stdout while the on-disk collect_full_*.log captures the full DEBUG trace (~369KB). Reproduced 3x. Typer's own errors DO pass through the same pipe, so the process stdout is fine; the Rich-based console log handler (see _is_console_handler in main.py, which duck-types on .console) is not reaching a redirected stdout. Impact: any CI job or '> log.txt' capture gets an empty file while the command still exits non-zero. This directly caused ~3 wasted lab runs during con-c522: exit 1 with no output was mistaken for a hard process abort.

## Acceptance Criteria

Redirecting the collector's stdout to a file captures the same console lines seen on a terminal. Regression test proves it. --silent still suppresses console output while on-disk logs are still written.

## Notes

**2026-07-31T15:10:57Z**

ROOT CAUSE: this is openhound FRAMEWORK behavior, not collector code.
openhound/core/logging.py:445-457 CustomLogger.runtime_mode picks: CONTAINER if LOG_CONTAINER/KUBERNETES_SERVICE_HOST set; CLI if sys.stdout.isatty(); else SERVICE. service_handlers() (line 441) installs ONLY a file handler -- no console handler at all. So redirecting stdout makes isatty() False, selects SERVICE, and zero console output is produced. It is not a stream-binding issue; no console handler is ever installed.
Note cli_handlers() binds RichHandler to Console(stderr=True), so on a terminal the console output is on STDERR, not stdout.
VERIFIED escape hatch: LOG_CONTAINER=1 forces CONTAINER mode (stdout StreamHandler). Same --dc-only run captured 32907 bytes with it vs 0 bytes without.
BLOCKED on decision: CLAUDE.md forbids changing OpenHound code without asking. Options: (a) document LOG_CONTAINER=1 in README (zero code, uses the framework's own hatch); (b) collector-side: detect SERVICE mode during collect and attach a stdout console handler, consistent with the existing mutate-live-handlers pattern in ARCHITECTURE section 7; (c) fix runtime_mode upstream in openhound.

**2026-07-31T17:11:59Z**

Resolved by documentation per @_Mayyhem's decision (option a). README 'Logging' section gained a 'Capturing console output (CI, > log.txt, piping)' subsection covering both surprises: (1) on a terminal console logs go to STDERR via Console(stderr=True); (2) redirecting stdout makes isatty() false, selecting SERVICE mode, whose service_handlers() installs only a file handler -- so no console handler exists at all. Documents LOG_CONTAINER=1 as the framework's own escape hatch with bash and PowerShell examples (verified: 32907 bytes captured with it vs 0 without), and notes that an empty CI log beside a non-zero exit is this, not a crash. No code change -- root cause is in openhound/core/logging.py:445-457, which CLAUDE.md puts out of scope.
