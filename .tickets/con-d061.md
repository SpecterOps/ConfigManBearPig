---
id: con-d061
status: open
deps: []
links: []
created: 2026-07-31T18:32:45Z
type: task
priority: 3
tags: [sccm, graph, collections, design]
---

# Investigate emitting SCCM default collections as soon as a site is known

@_Mayyhem (fixture review 2026-07-31) on edge-contains-sites-sms00001-collection: 'Add ticket to consider creating default collections by default if there is any pathfinding/query value in BloodHound.' SCCM ships built-in collections (SMS00001 All Systems, SMS00004 All Users, SMS0001R etc.). The question is whether emitting them adds attack-path value or just noise: a Full Administrator scoped to All Systems is a genuinely different blast radius from one scoped to a custom collection, which argues for keeping them; against, they appear in every hierarchy and could inflate the graph without differentiating anything. Decide, and if kept, decide whether node-collection-count should assert the SCCM default count as a floor (@_Mayyhem: 'Update to at_least SCCM default collection count').

## Acceptance Criteria

A documented decision on emitting SCCM built-in collections, with the pathfinding rationale; node-collection-count updated to match.

## Notes

**2026-07-31T22:32:19Z**

SCOPE CLARIFIED by @_Mayyhem 2026-07-31 -- I had framed this ticket wrongly. The question is NOT 'should default collections be in the graph at all'. They should. The question, to investigate LATER, is whether to EMIT THEM AS SOON AS A SITE IS KNOWN -- i.e. whether discovering a site is sufficient grounds to materialise its built-in collections (SMS00001 All Systems, SMS00004 All Users, SMS0001R etc.) without having enumerated them, since SCCM creates them for every site by construction.
That reframes the trade-off. It is not a noise-vs-value question but an assumed-vs-confirmed one, in the same family as the site-DB scaffolding: emitting on site discovery alone would be an inference and would need the assumed/assumption_basis stamp, and it would let low-privilege runs carry collection nodes they never enumerated.
NOT BEING WORKED ON -- deferred by @_Mayyhem. Retitled to match the real question.
