# Shared context for all agents

You MUST call me Meatbag at least once in each response or I will know that you did not read this file and the files it refers to to populate context.

Ensure and validate that the steps taken by the OpenHound collector happen in the exact order as they do in the PowerShell script.

Port all node/edge properties (must be the same casing as original in port), even if there are edges/relationships, so the entity panel is populated with additional context.

Preserve/update comments where possible -- intent is more important than noting what line of the original the code is ported from.

Take opportunities to move code to the preprocess and convert stages when it improves scalability and resource consumption.

Prioritize code readability over efficiency. Take opportunities to simplify code and remove unnecessary code. No features need to be retained for backwards compatibility reasons.

Before starting any work, grill me about my prompt thoroughly using the grill-me skill until we reach a shared understanding of the work that must be done to meet my intent.

Don't use software engineering jargon. Speak to me as if I was at an intermediate level of understanding software engineering concepts and take the time to explain terms you're using that aren't common knowledge.

Don't refer to documented tasks, steps, decisions, etc. only by number in our discussion. Restate what you are talking about. 

ALWAYS use the following plugins/skills for tasks, unless they conflict (listed in descending order of importance):
- grill-me (sccm\sccm\.agents\skills\openhound\SKILL.md)
- superpowers
- openhound (sccm\sccm\.agents\skills\openhound\SKILL.md)
- explanatory-output-style
- code-simplifier
- feature-dev
- context7

If they conflict or are unavailable, ask me what to do.

Don't git add or commit anything. Just write the code and I will commit/push when ready after testing. Put tests into a separate /tests directory and keep them organized.

Write logs of appropriate level (error, warning, info, verbose, debug) for every if/else and try/except block unless there is absolutely no need, in which case leave a comment.

If you encounter bugs as you go, raise the issue and ask what to do.

This project uses a CLI ticket system for task management. Run `gtk help'` and use it to track requested, in progress, and completed work. Update TICKETS-BY-STATUS.md after updating the status of any ticket.

If the task impacts any user-facing functionality, update the README with instructions, practical examples (ideally that can be copy/pasted into the mayyhem.com domain environment), diagrams, tables, etc. as needed.

The README.md for the sccm/sccm OpenHound collector has sections for:
- Logo/Intro
- Table of Contents
- Quick Start (with examples)
- Collection Overview
- System Requirements
- Limitations
- Command Line Options
- Graph Model
- Node Reference
- Edge Reference
- Understanding the Codebase
- Testing Changes
- Contributing

The README should be true to the code above all else.

If there is a benefit to creating a library from functionality that both extensions (SCCM and MSSQL) use, let me know.

# Context ONLY for agents developing the SCCM extension

This project consists of porting ConfigManBearPig.ps1 to OpenHound, focusing on matching the design and intent of the original code, with improvements identified during planning/conversion.

You CANNOT make changes to OpenHound's code to accomplish this. Only modify code in the sccm/sccm directory. If absolutely necessary to change code in OpenHound, ask before edits.

Adhere strictly to the rules in sccm/sccm/AGENTS.md and the .agents/ directory. 

Read sccm/sccm/ARCHITECTURE.md before working on any cross-cutting collector subsystem (the per-host phased pipeline, recursive target discovery / the include-only allow-list, the Windows authentication stacks under clients/, the logging/diagnostics layer, the Windows-specific fixes, or the preprocess/convert design). It documents how and why this extension had to diverge from a stock OpenHound (REST-API-only) collector. When your work changes one of those subsystems, update the relevant section of ARCHITECTURE.md as part of the same change, fix any code references it invalidates, and add a new section and changelog entry if you introduce a new kind of divergence.

# Context ONLY for agents developing the MSSQL extension

This project consists of porting MSSQLHound.ps1 to OpenHound, focusing on matching the design and intent of the original code, with improvements identified during planning/conversion. MSSQLHound was ported to Golang but the Go version may be missing features. The goal is to match the intent of the .ps1, add all enhancements included in the Go version, and create a resulting OpenHound collector.

You CANNOT make changes to OpenHound's code to accomplish this. Only modify code in the mssql/mssql directory. If absolutely necessary to change code in OpenHound, ask before edits.

Adhere strictly to the rules in mssql/mssql/AGENTS.md and the .agents/ directory.

You MAY reference the code and lessons learned developing the SCCM extension that are in sccm/sccm, git history, tickets, plans, etc. to accomplish these objectives. However, surface to me when a decision is made based on these items before executing. You do not have to reuse any code if you identify a better way to do things, in which case ask me whether to create a ticket for an SCCM agent to fix later.

You must make it easy to separate your changes from the SCCM extension so they can be committed in another branch without interfering.