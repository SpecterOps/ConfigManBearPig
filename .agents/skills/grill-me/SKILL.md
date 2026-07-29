---
name: grill-me
description: Interview the user relentlessly about a plan or design until reaching shared understanding, resolving each branch of the decision tree. Use when the user wants to stress-test a plan, get grilled on their design, or mentions "grill me".
---

Interview me relentlessly about every aspect of this plan until we reach a shared
understanding. Walk down each branch of the design tree, resolving dependencies between
decisions one-by-one. For each question, provide your recommended answer.

Ask the questions one at a time.

If a question can be answered by exploring the codebase, explore the codebase instead.

## Why this file exists separately

This skill used to live as a second YAML frontmatter block inside
`.agents/skills/openhound/SKILL.md`. A skill loader reads the *first* frontmatter block in
a file and ignores the rest, so `grill-me` never resolved — and because a missing skill
degrades to "no instructions" rather than an error, every agent asked to use it silently
improvised instead. One skill per file.
