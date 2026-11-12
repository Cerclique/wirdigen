# Expressions, Info Templates and Framing resolve Field Paths separately

A Field Path is resolved by three different rules, and each has its own resolver.

- **Expressions** (spec §4.3, `scope.rs`) resolve nearest first, from the Structure the Expression is in outward. They run on the unchecked description. They only reach Fields read earlier, never into a Conditional Scope or an Array. Inside a Type, a name the Type does not read is resolved by each use of the Type.
- **Info Templates** (spec §3.14, `info::find`) start from the top-level Structure. They go into Cases, taking the first Case that has the next Field.
- **Framing's length** (spec §3.13, `framing::resolve`) reads only a top-level Field or one of its Sub-Fields, and only if it lies inside the header.

They look alike, but the rules differ in where a path starts, whether it may enter a Case or Conditional Field, and what it may end on. Each dialect also explains a miss in its own terms. A single resolver would need a policy parameter for every one of those points, and each of its Diagnostics would have to branch on the dialect. So the three stay separate.

What they share is a target. A resolved path records the id of the Field or Sub-Field it reaches (#160), so lowering never resolves a path a second time.

## Considered Options

- **One resolver with a dialect policy**: rejected. The policy would cover nearly every step: the starting point, whether Cases and Conditional Scopes are allowed, the allowed ends, and the wording of each miss. That moves the three rules into a single module without simplifying any of them.
- **Re-resolving paths in lowering**: replaced by #160. It was a fourth and fifth copy of the walk, guarded only by `.expect`.
