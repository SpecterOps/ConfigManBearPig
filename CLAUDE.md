# Shared context for all agents

Do not use technical software engineering jargon. The code needs to be well commented in plain english.

Make the code, architecture, and documentation easy to understand. This is the most important thing. I need to be able to understand every bit of it (despite limited experience) and explain it to the software engineers responsible for reviewing and merging it.

If I don't ask you to start coding, don't start coding. Request permission if you are uncertain. 

Prioritize ease of use and understanding for extension users. 

Dependencies must be Apache 2.0 compatible or we need to develop the functionality ourselves. 

Don't change the schema.json based on assumptions without my approval. 

Prioritize code readability over efficiency. Take opportunities to simplify code and remove unnecessary code. No features need to be retained for backwards compatibility reasons. This is a development environment with no other users you could interfere with. 

If you identify something that should be followed up on because it is useful but isn't part of the current initiative, bring it to my attention.

Document how and why it works in the appropriate .md files. The documentation should be true to the code. 

Do not add or commit anything to the repository. I will commit manually after review. Recommend committing where/when you think is appropriate for a development/experimental codebase with one author and provide the commands.

Each completion of a single feature should result in:
- Code that is self-explanatory (well-commented, no shorthand, jargon, etc.)
- Documentation of the problem, the proposed solution and why it was selected, alternate solutions that were considered and why they were not selected, how the solution addresses the problem, exactly how the solution works in plain english with references to the code, new dependencies, downstream effects, testing performed, how to manually verify, etc.
- Passing unit/integration tests
- A recommended git commit message, including a brief summary of the bullet items above, and commands to stage/commit/push -- I will review every finished change manually first and perform the git actions myself. I am not a software engineer, so your explanations need to be in plain english for a relatively non-technical audience. I understand that this will make development go slower.
- If I request subsequent changes, update all of the relevant documentation, dependencies, and commands.

## Subagents
Multiple subagents may work in parallel as long as they don't step on each other's toes. If they do, resolve the conflicts.

Fable is the model that will be used to architect the changes (or Opus if Fable is not available).

Use Opus as the default model for plan review, analysis, and execution.

Use Sonnet for narrowly scoped work that has:

- a clearly defined input
- a short expected output
- little ambiguity
- low need for independent judgment

Examples include:

- extracting values from logs
- summarizing a single file
- checking whether a known value exists
- validating a small configuration change

Use Fable only when Opus has failed to make progress after two well-scoped attempts or when the task clearly requires deeper reasoning than Sonnet can provide.

Turn Fast off. Flag heavy or sustained work in advance. Keep delegated tasks bounded.

When spawning a subagent, record:

- role
- bounded task
- selected available model
- one-sentence justification

Keep notes that would be helpful when handing this off to another agent.

You MUST call me Meatbag at least once in each response or I will know that you did not read this file and the files it refers to to populate context.

Take opportunities to move code to the preprocess and convert stages when it improves scalability and resource consumption.

Before starting any work, grill me about my prompt thoroughly until we reach a shared understanding of the work that must be done to meet my intent.

Don't refer to documented tasks, steps, decisions, etc. only by number in our discussion. Restate what you are talking about. 

Ask before committing each time. Never push. Put tests into a separate /tests directory and keep them organized.

Write logs of appropriate level (error, warning, info, verbose, debug) for every if/else and try/except block unless there is absolutely no need, in which case leave a comment.

If you encounter bugs as you go, raise the issue and ask what to do.

If the task impacts any user-facing functionality, update the README with instructions, practical examples (ideally that can be copy/pasted into the mayyhem.com domain environment), diagrams, tables, etc. as needed.

The README.md for this OpenHound collector has sections for:
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

If there is a benefit to moving functionality into the shared `openhound-collector-common` library, let me know. It is a separate repository and package used by more than one collector, so a change there is not part of a change here.

You CANNOT make changes to OpenHound's code. Only modify code in this repository and if potentially useful for more than one collector, openhound-collector-common. If absolutely necessary to change code in OpenHound, ask before edits.

Adhere strictly to the rules in AGENTS.md and the .agents/ directory.

Read ARCHITECTURE.md before working on any cross-cutting collector subsystem (the per-host phased pipeline, recursive target discovery / the include-only allow-list, the Windows authentication stacks under clients/, the logging/diagnostics layer, the Windows-specific fixes, or the preprocess/convert design). It documents how and why this extension had to diverge from a stock OpenHound (REST-API-only) collector. When your work changes one of those subsystems, update the relevant section of ARCHITECTURE.md as part of the same change, fix any code references it invalidates, and add a new section and changelog entry if you introduce a new kind of divergence.
