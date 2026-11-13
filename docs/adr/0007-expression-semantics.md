# Expressions use Rust-style precedence, C integer arithmetic and `_` built-ins

Expressions in a Protocol Description (`size:`, `count:`, `if:`, `padding:`, the `framing:` length, `switch:` subjects) are a small infix language of Wirdigen's own (ADR 0005): integer literals, Field Paths, two built-ins, parentheses and the arithmetic, comparison, logical and bitwise operators. There are no function calls, no strings and no assignment. Every value is a signed 64-bit integer; non-zero is true.

Three choices deliberately depart from what a C reader would expect, or from what Lua would do natively:

- **Precedence is Rust/Python-style, not C.** Bitwise operators bind tighter than comparisons, so `flags & 0x80 == 0x80` means what it looks like (in C it means `flags & 1`). Tightest to loosest: unary `! ~ -`, `* / %`, `+ -`, `<< >>`, `&`, `^`, `|`, comparisons, `&&`, `||`. Comparisons are non-associative: `a < b < c` is an error.
- **Arithmetic is C's, not Lua's.** `/` truncates toward zero and `%` takes the dividend's sign, as in the protocol specs descriptions are transcribed from; Lua's floor division would silently disagree on negative values. `>>` is arithmetic.
- **Built-ins are `_offset` and `_remaining`**, and Field and Type names may not start with `_`. Real protocols have Fields called `offset` or `length`, so plain reserved words would take names away from users.

## Consequences

- The generator lowers operators to helper calls rather than native Lua operators, which also keeps the file parsing under Lua 5.2 (ADR 0006).
- Division or modulo by zero, a negative size, count, padding or framing length, and a shift count outside 0..63 are malformed-packet errors at runtime, never Lua errors (Dissector behaviour under ADR 0001). Overflow wraps silently, and a `uint64` above 2⁶³ reads as negative.
- `size: remaining` is spelled `size: "_remaining"`; new built-ins can be added under the `_` prefix without breaking any description.
- Changing precedence or division semantics later would change the meaning of existing descriptions, so it is a major release.

## Considered Options

- **Exact C precedence**: rejected; it keeps the mask-test trap in a language whose main job is mask tests.
- **C precedence, but mixing bitwise and comparison operators without parentheses is an error**: rejected; it avoids the trap by making users add parentheses the Rust order makes unnecessary.
- **Lua floor division**: rejected; it differs from C on negative operands and needs `//`, which does not parse under Lua 5.2.
- **Unprefixed built-ins (`offset`, `remaining`) as reserved words**: rejected; they collide with common Field names.
- **A separate boolean type**: rejected; every 1-bit flag check would need `== 1` for no real safety.
