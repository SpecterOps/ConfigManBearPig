---
id: con-6f42
status: in_progress
deps: []
links: [ope-1f0f, Ope-rhzx, Ope-0t3h, ope-00df, Ope-emhc, con-2ca2, ope-1172]
created: 2026-11-10T03:34:13Z
type: task
priority: 1
tags: [sccm, completion, planning, review]
---

# Complete the agreed SCCM extension scope

The owner reviewed the remaining work and selected the scope recorded in
[the SCCM extension completion plan](../docs/superpowers/plans/2026-11-09-sccm-extension-completion.md).
That plan is the current authority where older ticket designs conflict.

Start with the seven confirmed review findings. Include custom-role permissions,
client-push configuration analysis, independent full/issues log-file choices,
truthful options/docs, and SCCM findings in the separate `bhe-extensions` repo.
Keep built-in role shortcuts. Respect the recorded deferrals.

The owner approved the bounded common-library proposal and instructed work to
begin. New graph relationships and schemas still require review. The initial
plan alone changed no implementation; approved defect corrections are underway.

Dependency decision: use the local common-library checkout for all work and
testing now. Prepare both repositories for the owner's review and push/release
process after the work is complete. Publication, the collector's dependency
minimum, and published-package installation checks are final release tasks.

## Acceptance criteria

Complete the plan's Windows and WSL, ordinary-installation, lab, partial-failure,
graph, findings, documentation, and handoff checks. Record results and remaining
limitations. Do not close this ticket merely because the plan or code review is
finished. Do not stage, commit, or push changes on the owner's behalf.
