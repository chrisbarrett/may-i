## Context

`may-i`'s engine recurses into command substitutions during evaluation. The
parser emits `WordPart::Backtick { source, … }` and `WordPart::CommandSubstitution
{ source, … }` for `` `…` `` and `$(…)` respectively. `decompose` turns each
substitution into an `EvalUnit::EmbeddedCommand { source, span }`, and
`evaluate_command_inner` recurses on the inner source string
(`crates/engine/src/eval/command.rs:96`).

When the inner recursion returns `:ask` because the embedded command has no
matching rule, the reason string is generated at
`crates/engine/src/eval/entry.rs:527`:

```rust
format!("No rule for command `{}`", ctx.command)
```

That string is what the Claude Code hook surface forwards as
`permissionDecisionReason` (`src/cmd_claude_code_hook.rs:116`). The aggregator
in `evaluate_command_inner` then picks this as the most-restrictive reason and
returns it verbatim to the harness.

The result: the operator sees ``No rule for command `:rebuild` ``, with no
hint that `:rebuild` originated from a backtick inside a `grep` regex.

## Goals / Non-Goals

**Goals:**
- When the bubbled-up reason originates from an `EmbeddedCommand` unit,
  annotate the single-line reason with (a) the outer command name and (b) the
  substitution form (backtick vs `$(…)`).
- Preserve the existing reason content for non-embedded paths byte-for-byte —
  spec scenarios such as ``No rule for command `kubectl` `` must still hold for
  top-level invocations.
- Keep the annotation single-line (constraint from
  `shell-command-security-model` requires no literal newlines in reasons).

**Non-Goals:**
- Restructuring `SegmentDecision` or trace output. Segments already record
  inner spans; this change is only about the human-readable reason.
- Rewriting how reasons combine when multiple tied rules contribute distinct
  reasons. The annotation wraps the inner reason; tie aggregation is upstream.
- Distinguishing nested substitutions (substitution inside substitution). For
  the first iteration the annotation names the nearest enclosing command.

## Decisions

### Wrap at the aggregator, not at the leaf

`evaluate_command_inner` already knows which `EvalUnit` produced the
contributing decision (the loop at `command.rs:90` updates
`aggregate_reason` whenever a unit's decision is at least as strict). When the
contributing unit is `EvalUnit::EmbeddedCommand`, the aggregator wraps the
inner reason with an origin clause.

Alternative considered: emit the annotated reason from the recursive call
itself. Rejected because the recursive call doesn't know its caller's outer
command name without an extra context parameter, and threading that parameter
through `evaluate_command_inner` couples the inner evaluator to a presentation
concern.

### Carry substitution form on `EvalUnit::EmbeddedCommand`

Add a `kind: Option<EmbeddedKind>` field on `EmbeddedCommand` (variants:
`Backtick`, `Dollar`). The parser already distinguishes those two
`WordPart` shapes; the information just needs to survive into `EvalUnit`.

Process substitution (`<( … )` / `>( … )`) is a third embedded shape but
its origin is not named by the annotation — the spec only requires
naming the `` ` ` `` and `$( … )` forms. It maps to `kind = None`, which
the annotator treats the same as the dynamic-outer fallback (generic
`(embedded substitution)` clause). Modelling it as `Option<…>` keeps
the kind enum to the two variants the annotator names, while still
giving every `EmbeddedCommand` unit a well-defined kind field.

Alternative considered: re-scan the outer source slice for the leading
backtick / `$(` to recover the form. Rejected — fragile, and the parser
already has the data.

### Annotation shape

The annotated reason follows the shape:

```
No rule for command `:rebuild` (backtick substitution in `grep`)
```

`$(…)` form:

```
No rule for command `:rebuild` ($(...) substitution in `grep`)
```

When the outer command itself has a dynamic name (rare — only triggers when
the outer command's first word is itself a substitution), the annotation
falls back to `embedded substitution` without naming the outer command:

```
No rule for command `:rebuild` (embedded substitution)
```

Single-line by construction; no newline.

### Don't reformat already-annotated reasons

When recursion depth exceeds one (substitution inside substitution), the
inner reason already carries an `(… substitution in `X`)` clause. The wrapper
SHALL detect the existing clause and not re-wrap. The simplest detection is
"reason ends with `)` and contains ` substitution in `" — cheap, no regex.

This keeps a `$(echo "$(rm -rf /)")` reason from accumulating layers of
parens.

## Risks / Trade-offs

- Snapshot churn → mitigation: pre-existing snapshots covering the no-rule
  path are top-level invocations, not embedded ones, so most should be
  unaffected. Snapshots that cover embedded paths (a handful in
  `crates/engine/src/eval/command.rs` test module) need refresh.
- Localisation / formatting drift if the harness later expects a specific
  reason shape → mitigation: the reason is consumed by humans (Claude Code
  prompt UI), not parsed. Existing reason strings are already free-form
  English.
- The wrapper detection heuristic ("ends with `)` and contains
  ` substitution in `") could mis-fire if a rule author writes a reason
  literally ending in `substitution in `foo`)` → mitigation: this is a
  cosmetic mis-fire (one extra wrap skipped) and only matters at recursion
  depth ≥ 2, which is already rare.
