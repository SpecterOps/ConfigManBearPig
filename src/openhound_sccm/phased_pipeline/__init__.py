"""phased_pipeline — a portable engine for concurrent, recursive, ordered-phase
collection.

This sub-package is deliberately free of any project-specific imports (no SCCM,
Active Directory, or DLT). It understands only four ideas:

* **targets** — opaque identifiers (strings) of things to collect from;
* **phases** — ordered steps run against each target;
* **streams** — named output channels that phases write rows to;
* **recursion** — a phase may discover new targets, which are collected the same
  way until nothing remains.

It can therefore be lifted into its own installable package and reused by any
project that supplies its own phases and consumes the output streams.

"""

from .engine import Phase, run_one_target, run_pipeline
from .streams import DONE, broadcast_done, build_streams
from .work_queue import WorkQueue

__all__ = [
    "WorkQueue",
    "Phase",
    "run_one_target",
    "run_pipeline",
    "DONE",
    "build_streams",
    "broadcast_done",
]
