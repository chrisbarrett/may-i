---
audience: contributor
bucket: contributor-internals
---
# Traces Specification

## Purpose

Traces internals: how `TracingFold` implements `EvalFold` to produce
annotated `Doc` trees alongside evaluation results, and the `Ann` payloads
downstream renderers consume to lay out the human and JSON trace surfaces.
Also covers visible-character-width arithmetic in the layout renderer (for
`NoteHeading` and `ColRow` label alignment) and the var-breakout section
that surfaces `Predicate::Named` references and their expanded bodies at the
point of use.

## Requirements

### Requirement: TracingFold produces annotated Doc trees alongside results
`TracingFold` SHALL implement `EvalFold` with
`EffectOut = (EffectResult, Doc<Option<Ann>>)` and
`PredicateOut = (PredicateResult, Doc<Option<Ann>>)`. Each fold method SHALL
build an annotated Doc node that mirrors the s-expression structure of the
evaluated AST node.

#### Scenario: Terminal effect produces annotated doc
- **WHEN** evaluating `Effect::Allow(Some("safe"))`
- **THEN** the fold output contains `EffectResult::Decision(Allow, Some("safe"))`
- **AND** a `Doc` representing `(allow "safe")` with an `Ann` recording
  the decision

#### Scenario: Command match produces annotated doc
- **WHEN** evaluating `Effect::CommandPattern(Literal("git"))` against command
  `"git"`
- **THEN** the `Doc` represents `"git"` with an `Ann::CommandMatch { matched: true }`

#### Scenario: Short-circuited children appear dimmed
- **GIVEN** an `And` effect where the first child returns Nil
- **WHEN** the fold builds the doc for the And node
- **THEN** unevaluated children's docs SHALL have `dimmed = true`

### Requirement: Ann enum covers all annotation kinds
The `Ann` enum SHALL have variants for: command match (with matched flag),
argument match (with args and evidence), fact query result (with observed values
and failure reasons), effect decision (with decision and reason), and
quantifier match (with count). These correspond to the evidence needed for
the right column in two-column trace output.

#### Scenario: Arg match annotation includes evidence
- **WHEN** `(anywhere "-r")` is evaluated against args `["-r", "-f", "/"]`
- **THEN** the `Ann` records the search tokens, the full arg set, and whether
  each token was found

#### Scenario: Fact query annotation includes observed values
- **WHEN** `(fact? [:opencode/agent "build"])` is evaluated and context has
  `opencode/agent = {"plan"}`
- **THEN** the `Ann` records the expected value `"build"`, observed set
  `{"plan"}`, and `matched: false`

### Requirement: TracingFold lives outside the engine crate
The `TracingFold` struct, `Ann` enum, and all `Doc`-related types SHALL be
defined in the CLI binary (`src/`), not in the engine crate. The engine crate
SHALL NOT depend on `may-i-core::doc` for trace purposes.

#### Scenario: Engine crate compiles without Doc dependency for traces
- **WHEN** the engine crate is compiled
- **THEN** no trace-related code in the engine imports `Doc` or `Ann`

### Requirement: TracingFold handles MayI recursion
When the evaluator processes a `MayI` effect, it SHALL call `evaluate`
recursively with the same `TracingFold` instance. The inner evaluation produces
its own `(EffectResult, Doc<Option<Ann>>)`. The outer `effect_may_i` method
SHALL incorporate the inner doc as a nested trace.

#### Scenario: Wrapper command shows inner trace
- **GIVEN** a wrapper rule for `nohup` and an inner command `git push`
- **WHEN** `may-i eval 'nohup git push'` is evaluated with `TracingFold`
- **THEN** the trace shows the inner `git push` evaluation with full annotations

### Requirement: Two-column terminal trace layout
The trace renderer SHALL display rule evaluations in a two-column layout: the
left column contains the pretty-printed s-expression of the rule, and the right
column contains evaluation annotations separated by a `│` divider.

#### Scenario: Basic rule trace
- **WHEN** rendering a trace for `ls -la` matching a read-only filesystem rule
- **THEN** the left column shows the rule s-expression
- **AND** the right column shows `→ :allow "Read-only filesystem access"` on the
  effect line

#### Scenario: Layout adapts to terminal width
- **WHEN** the terminal width is detected
- **THEN** the left column occupies approximately half the usable width
- **AND** annotations in the right column are placed adjacent to their
  corresponding s-expression lines

### Requirement: Argument match annotations show evidence
When an argument pattern is evaluated, the right-column annotation SHALL show
the tested value, the argument set, and the match verdict.

#### Scenario: Anywhere match shows set membership
- **WHEN** `(anywhere "-r")` matches against args `["-r", "-f", "/"]`
- **THEN** the annotation reads `"-r" ∈ {"-r", "-f", "/"} → yes`

#### Scenario: Positional match shows equality test
- **WHEN** `(positional "push")` is tested against positional arg `"pull"`
- **THEN** the annotation reads `"pull" = "push" → no`

### Requirement: Decision keywords are colorised
Terminal trace output SHALL colorise decision keywords: `:allow` in green,
`:ask` in yellow, `:deny` in red.

#### Scenario: Each decision keyword has its colour
- **WHEN** a trace line renders `:allow`, `:ask`, or `:deny`
- **THEN** the keyword SHALL be coloured green, yellow, or red respectively

### Requirement: Unevaluated branches are dimmed
When short-circuiting skips child nodes, those nodes SHALL be rendered in dimmed
style in the left column with no right-column annotation. When a `cond` branch
matches and produces an effect (short-circuiting evaluation), all subsequent
skipped branches and any skipped fallback SHALL be collapsed into a single
dimmed `…` atom rather than rendering each skipped branch individually.

#### Scenario: Cond short-circuit collapses trailing branches
- **WHEN** a `cond` has 5 branches and the 2nd branch matches
- **THEN** branches 1-2 render normally (branch 1 shows predicate evaluation,
  branch 2 shows match and effect)
- **AND** branches 3-5 are replaced by a single `…`

#### Scenario: Skipped fallback merges into trailing ellipsis
- **WHEN** a `cond` has branches and a fallback, and a branch matches
- **THEN** the skipped fallback is NOT rendered separately
- **AND** the single trailing `…` covers both remaining branches and fallback

#### Scenario: No match evaluates all branches normally
- **WHEN** no `cond` branch matches and there is a fallback
- **THEN** all branch predicates render with their evaluation traces
- **AND** the fallback renders normally (no collapsing)

#### Scenario: All branches skipped except first match
- **WHEN** the first `cond` branch matches
- **THEN** only the matching branch and a single trailing `…` appear
- **AND** no individual `(… …)` pairs are rendered

### Requirement: Long or-lists are truncated with elision
When a `(command (or ...))` list contains many alternatives, the renderer SHALL
truncate after a reasonable number of items and show `…` for the rest.

#### Scenario: 20-alternative or-list truncates
- **WHEN** a `(command (or ...))` list contains 20 alternatives
- **THEN** the renderer SHALL print a bounded prefix followed by `…`

### Requirement: Compound commands show per-segment traces
The renderer SHALL trace each command segment of a compound command (e.g., `echo hello && rm -rf /`) separately, with a segment header showing the command text and its decision.

#### Scenario: Two-segment compound trace
- **WHEN** rendering a trace for `echo hello && rm -rf /`
- **THEN** the output SHALL show one segment header per command with that segment's decision

### Requirement: Result section shows aggregate decision
After the trace section, the renderer SHALL print a result section showing the
full command (colorised per-segment by decision), an arrow with the aggregate
decision keyword, and the config file path.

#### Scenario: Result section follows trace
- **WHEN** a trace finishes for any command
- **THEN** a result section SHALL print the full command, the aggregate decision keyword with an arrow, and the config file path

### Requirement: JSON trace serialises Doc<Ann> tree
When `--json` is passed to `may-i eval`, the output SHALL include a `trace`
array where each entry contains the rule's source line, a structured
representation of the s-expression, and an array of annotations with type,
decision, match details, and failure reasons.

#### Scenario: JSON output contains trace entries
- **WHEN** `may-i eval --json` runs on any command
- **THEN** the output SHALL contain a `trace` array whose entries record source line, s-expression structure, and annotations

### Requirement: Check command runs all embedded checks
`may-i check` SHALL evaluate all embedded `(check ...)` forms (both rule-level
and top-level) and report pass/fail results.

#### Scenario: Rule-level and top-level checks both run
- **GIVEN** a config containing both a rule-level `(check …)` and a top-level `(check …)`
- **WHEN** `may-i check` runs
- **THEN** both checks SHALL be evaluated and their pass/fail results SHALL be reported

### Requirement: Check verbose mode shows passing checks
`may-i check -v` SHALL list every check with its command and actual decision,
not just failures.

#### Scenario: Verbose lists passing and failing checks
- **WHEN** `may-i check -v` runs against a config with mixed passing and failing checks
- **THEN** the output SHALL list every check with its command and actual decision

### Requirement: Check JSON mode outputs structured results
`may-i check --json` SHALL produce a JSON object with `passed` count, `failed`
count, and a `results` array where each entry includes command,
expected/actual decisions, pass/fail flag, context, location, reason, and
trace.

#### Scenario: JSON output is structured
- **WHEN** `may-i check --json` runs
- **THEN** the output SHALL contain `passed`, `failed`, and `results` fields with the entry shape specified above

### Requirement: Dimmed nodes produce no right-column annotations
The renderer SHALL NOT produce any right-column annotation for a Doc node
(or its children) that is dimmed because it represents an unevaluated branch.

#### Scenario: Dimmed subtree has no right-column annotations
- **WHEN** a Doc node is rendered dimmed
- **THEN** neither the node nor any descendant SHALL produce a right-column annotation

### Requirement: Structural annotation placement via AnnotatedLineBuilder
The renderer SHALL use `AnnotatedLineBuilder` to collect annotations
structurally during pretty-printing, rather than string-matching rendered output
with `find_line`.

#### Scenario: AnnotatedLineBuilder is the placement path
- **WHEN** the renderer attaches an annotation to a line
- **THEN** it SHALL do so via `AnnotatedLineBuilder`, never by post-hoc `find_line` string matching

### Requirement: Multiple annotations per line use priority ordering
When multiple annotations exist on a single rendered line, the renderer SHALL
display only the highest-priority annotation.

#### Scenario: Only highest-priority annotation renders
- **WHEN** two annotations target the same rendered line
- **THEN** only the higher-priority annotation SHALL be displayed

### Requirement: Heading and label widths use visible character width
The layout renderer SHALL compute visible character width (not byte length) for NoteHeading text and ColRow label text. This ensures correct column alignment when headings or labels contain multi-byte Unicode characters or ANSI escape codes.

#### Scenario: Unicode heading alignment
- **WHEN** a NoteHeading is created from a string containing Unicode characters (e.g., "ℹ Info")
- **THEN** the visible_width field SHALL equal the number of visible characters, not the byte length

#### Scenario: ColRow label with Unicode
- **WHEN** a ColRow::kv is created with a label containing Unicode characters
- **THEN** the width used for column arithmetic SHALL equal the visible character width

### Requirement: Trace shows define name at point of use

When a rule's trace includes a `Predicate::Named` reference, the trace SHALL
display the define name (not the expanded body) at the point of use in the rule
structure.

#### Scenario: Human-readable trace shows name

- **WHEN** evaluating `"git push"` against a rule `(rule "git" (when build-mode (allow)))`
  where `build-mode` is a define
- **THEN** the human-readable trace shows `build-mode` in the rule's predicate
  position, not the expanded body

#### Scenario: JSON trace shows name

- **WHEN** evaluating the same rule with `--json`
- **THEN** the trace includes an annotation with `"type": "var_ref"` and
  `"name": "build-mode"`

### Requirement: Trace includes a breakout section for the define body

When a `Predicate::Named` is evaluated, the trace SHALL include a nested
breakout section showing the define's body with its own evaluation annotations.

#### Scenario: Breakout shows expanded body with annotations

- **WHEN** `build-mode` is defined as `(or (has [:client "claude-code"]) (has [:agent "build"]))`
  and the context has fact `[:agent "build"]`
- **THEN** the trace breakout for `build-mode` shows the `(or ...)` body with
  annotations indicating which branch matched

#### Scenario: Human-readable breakout is visually distinct

- **WHEN** a rule trace includes a var breakout
- **THEN** the breakout is rendered as an indented, labelled section beneath the
  var reference — visually distinct from the rule's own trace

#### Scenario: JSON breakout is nested

- **WHEN** a rule trace includes a var breakout in JSON mode
- **THEN** the var annotation contains a `"body"` field with the child
  predicate's annotations as a nested array

### Requirement: Unmatched var breakout is still shown

When a `Predicate::Named` reference evaluates to `NoMatch`, the trace SHALL
still show the breakout with annotations indicating why it did not match.

#### Scenario: Breakout shows non-matching body

- **WHEN** `build-mode` does not match the current context
- **THEN** the trace breakout shows the body with annotations indicating no
  branch matched
