# Expressions are limited to depth 64 so the Dissector loads in Lua

An Expression nested too deeply used to abort Wirdigen with a stack overflow (#191): the parser, lowering, emit, the Field Path reference walks and `Drop` all recurse once per level. The parser now stops at depth 64 and reports the error `expression-too-deep`. Depth counts every level the parser enters: a parenthesis, a unary operator, or an operand of a binary operator, so a flat chain `a+a+…+a` of k operands has depth k.

The value comes from the target, not from Rust's stack. Operators are lowered to nested prelude helper calls (ADR 0007, ADR 0010), and Lua refuses to load a file whose calls nest past its parser's limit of 200 levels, *including* the blocks around the Expression. Measured in tshark 4.7.4:

| Inline Structures around the Expression | Deepest Expression that loads |
|---|---|
| 0 | 195 |
| 10 | 150 |
| 20 | 60 to 100 |

At 64, an Expression loads under 20 nested Structures. Since ADR 0019, a dissect function never holds more than a few levels of blocks, so it loads however deeply it is nested in the description. That is still far above anything written by hand. Parentheses alone add no Lua nesting, but they count anyway: that keeps the parser to a single counter, and no description needs 64 of them.

## Consequences

- Raising the limit later is a minor change. Lowering it rejects descriptions that used to be accepted, which is a major change (ADR 0008).
- Every pass after the parser can stay recursive, because no Expression it receives is deeper than 64.
- Lua's limits on locals, upvalues and registers were a separate constraint on how large a description could be (#199). ADR 0019 removes it.
- The Type dependency walk and the walk of the names a Type reads are made iterative. This does not make long chains of Types safe: other passes still recurse once per Type, which is left to #207. The site tables no longer nest in the generated Lua (ADR 0019), so a chain of 500 Types loads.

## Considered Options

- **Iterative passes with no limit**: rejected. Every pass that walks an Expression would need an explicit stack, as would every future pass, and any Expression deeper than about 195 still produces a Dissector Lua cannot load.
- **256, as first suggested**: rejected. Lua never loads a Dissector with an Expression that deep.
- **128**: rejected. It loads only up to about 12 nested Structures, so a description could pass validation and still produce a Dissector that fails to load.
- **Reporting it as `expression-syntax`**: rejected. The Expression is not malformed, and tools matching on `expression-syntax` would be misled. Other Expression errors that are not syntax errors already have their own names (`leading-zero-literal`, `chained-comparison`).
- **A cap on tokens or operators per Expression**: rejected. Measuring tree depth already catches flat chains with the same rule.
