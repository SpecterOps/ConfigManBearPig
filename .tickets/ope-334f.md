---
id: ope-334f
status: closed
deps: []
links: []
created: 2026-06-03T14:26:26Z
type: task
priority: 2
---

# Windows-safe core log rotation: copy+truncate + per-run timestamped openhound.log --type task --priority 2 --description OpenHound core attaches a TimedRotatingFileHandler (when=midnight) to BOTH the root and dlt loggers, each on the same openhound.log (openhound/core/logging.py). First record after midnight fires a rollover whose os.rename() fails on Windows with WinError 32 because the sibling handler still holds the file open -- so daily rotation has never worked on Windows. Core is off-limits per CLAUDE.md. Fix lives in sccm/sccm main.py startup: locate core's two RotatingFileHandler instances, repoint each to a per-run timestamped file, and replace doRollover with a Windows-safe copy+truncate. Windows-only; POSIX unchanged.

## Notes

**2026-06-03T14:28:02Z**

Fixed in sccm/sccm/src/openhound_sccm/main.py: added _make_core_rotation_windows_safe() (runs at module import) + _copytruncate_rollover(). On Windows, repoints core's root+dlt RotatingFileHandlers to a per-run timestamped openhound_<ts>.log and recomputes rolloverAt to next midnight; replaces doRollover with copy+truncate (no rename). Validated against the real core handlers: forced rollover with a sibling handle open succeeds, dated backup written, base truncated, handler still writable. No-op on POSIX.

**2026-06-03T14:30:43Z**

Follow-up: first real run hit FileNotFoundError (WinError 2). Core shouldRollover calls os.path.getsize(baseFilename) on every record (max_bytes defaults to 3GB, always active), but the repoint left stream=None and never created the new timestamped file. Fix: reopen the stream (handler._open()) right after repointing, matching core delay=False open-at-construction. Re-validated through the real emit->shouldRollover->getsize path: emit OK, rollover OK.
