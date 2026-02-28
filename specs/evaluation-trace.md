# Evaluation Trace

Annotated document tree recording why each rule matched or failed. Rendered as
a two-column display: left column shows rule structure, right column shows
evaluation evidence.

---

## R30: Annotation model

Every node in the rule's document tree is annotated during evaluation:

| Annotation       | Meaning                                          |
| :--------------- | :----------------------------------------------- |
| `CommandMatch`   | Did command name match? (bool)                   |
| `ExprVsArg`      | Expression tested against argument (arg, bool)   |
| `Quantifier`     | How many args a quantifier consumed (count, bool)|
| `Missing`        | Expected positional arg not present              |
| `Anywhere`       | Token searched across all args (args, bool)      |
| `CondBranch`     | A cond branch was selected (decision)            |
| `CondElse`       | Else branch was selected (decision)              |
| `ExactArgs`      | Exact positional match (patterns, args, bool)    |
| `ExactRemainder` | Leftover args after exact match (count)          |
| `ArgsResult`     | Overall arg matcher result (bool)                |
| `RuleEffect`     | Final rule effect (decision, reason)             |
| `DefaultAsk`     | No rule matched; default ask                     |

Structural nodes (parentheses, keywords) that are not evaluated have `None`
annotation.

**Verify:** `cargo test -- annotate`

## R31: Trace entries

Evaluation produces a trace — a list of entries:

- `SegmentHeader` — labels each pipeline/and-or segment with its command name
  and decision
- `Rule` — annotated document tree for a rule that was evaluated, with source
  line number
- `DefaultAsk` — fallback when no rule matched

**Given** a compound command (`a && b | c`) **Then** trace contains segment
headers for each simple command, followed by rule entries showing which rules
were tried.

**Verify:** `cargo test -- engine`

## R32: Two-column rendering

**Given** a trace **When** rendered to a terminal **Then** display in two
columns:

- Left: rule S-expression structure (pretty-printed, with layout hints)
- Right: evaluation evidence (annotation summaries, colorized)

Column divider is `│`. Terminal width detected from `$COLUMNS`, `terminal_size`
crate, or default 80. Below 40 chars, fall back to single-column.

**Verify:** manual `may-i eval` inspection

## R33: Colorization

| Decision/state | Color        |
| :------------- | :----------- |
| Allow / yes    | Green, bold  |
| Ask / no       | Yellow, bold |
| Deny           | Red, bold    |
| Unevaluated    | Dimmed       |

Regex matches use `~` (approximate) instead of `=` (exact) in the evidence
column.

**Verify:** manual inspection; `--json` mode for machine-readable output

## R34: Unevaluated node handling

**Given** a rule where evaluation short-circuits (e.g., command name didn't
match) **Then** unevaluated subtrees are:

1. Marked `dimmed` for muted rendering
2. Long unevaluated lists truncated with `…`

This focuses attention on the parts of the rule that were actually tested.

**Verify:** `may-i eval` with a multi-rule config

## R35: Document tree structure

The document tree uses a recursion scheme:

- `DocF<R>` — base functor: `Atom(String)` or `List(Vec<R>)`
- `Doc<A>` — fixpoint with annotation `A`, layout hint, and dimmed flag
- `fold` — bottom-up catamorphism
- `map` — annotation transformation

This enables generic traversals for rendering, annotation propagation, and
serialization without duplicating tree-walking logic.

**Verify:** `cargo test -- doc`; `tsc --noEmit` equivalent: `cargo check`

## Constraints

- Trace rendering must not allocate for rules that don't match (common case)
- ANSI escape sequences excluded from width calculations
- Pretty-printer respects `AlwaysBreak` layout hint for multi-annotation lists
