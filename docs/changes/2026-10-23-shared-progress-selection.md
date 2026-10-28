# Share optional progress selection with the SQL collector

Both collectors need the same four choices: progress off by default, or an
explicit tqdm, log, or alive_progress tracker. The framework's enum has no off
choice. SCCM already solved that by passing an object whose `.value` is `None`.

The implementation now lives in common's `dlt/progress.py`.
`main.py::_resolve_progress` delegates to it while supplying the same SCCM logger.
Named choices still return OpenHound's enum members; off still returns an object
whose value is `None`. SCCM keeps its current console formatter and all existing
collection/graph rules. Copying this helper into SQL was rejected because the
two identical implementations would drift.

No third-party dependency or schema change is introduced. This source depends on
the pending shared-library release; the owner will publish it after review and
the consumer dependency floor/lock will then be updated to that actual version.
Development checks use a separate environment with local editable common/SCCM
sources and the existing locked registry package versions.

The combined command/logging/progress check is pending. Its SCCM selection will
include `tests/progress_option_test.py` and `tests/collect_run_all_test.py` alongside
existing command and logging checks. This extraction has no graph calculation,
but final consumer acceptance will still repeat preparation/conversion over
saved data. Results and exact owner staging commands will be recorded before
this feature is called complete. No files have been staged or committed.

Suggested owner message after acceptance:
`Use shared optional progress selection without changing SCCM behavior`.
