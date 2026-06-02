---
audience: contributor
bucket: tracing-and-output
---
# traces Specification

## Purpose

Contributor-only. The trace subsystem end to end: how `TracingFold` implements `EvalFold` to produce annotated `Doc` trees alongside evaluation results, the `Ann` payloads downstream renderers consume, and the contracts governing the rendered human and JSON trace surfaces — two-column layout, fact-query evidence compaction, decisive-line annotation placement, parser kv-row rendering, source-syntax rendering of rule bodies, dimming of unevaluated branches, the var-breakout section for `Predicate::Named` references, and visible-character-width arithmetic in the layout renderer. Callers render via the `output-rendering` intent surface (`render_trace`, `render_eval_result`, `render_check_failure`); the `may_i_layout` `Layout` ADT is an implementation detail of that module.

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

### Requirement: TraceNode roles cover all annotation kinds

The trace producer SHALL emit a `TraceNode` tree whose `Role` enum covers every annotation kind a renderer needs to display: command match, argument match (with evidence), fact query result (with observed values and failure reason), effect decision (with decision and reason), quantifier / Pattern result, named-predicate reference, and captured-value annotations. These roles correspond to the evidence needed for the right column in two-column trace output.

`Role` SHALL NOT name `ArgPattern`-internal shape (no `SearchTokens`, no `MatchMode`-keyed variants). Evidence carried alongside a `Role` SHALL be a small, renderer-facing enum (`Evidence::Scalar`, `Evidence::SetMembership`, `Evidence::CapturedValue`, `Evidence::FactAbsent`, …) — not a destructured copy of the engine's `ArgPattern` payload.

#### Scenario: Arg match role carries set-membership evidence

- **WHEN** `(anywhere "-r")` is evaluated against args `["-r", "-f", "/"]`
- **THEN** the emitted `TraceNode` carries a `Role` identifying the arg-match concern
- **AND** its `Evidence` records the queried token, the observed arg set, and the match verdict — without exposing `ArgPattern`'s internal field names

#### Scenario: Fact query role carries observed-values evidence

- **WHEN** `(fact? [:opencode/agent "build"])` is evaluated and context has `opencode/agent = {"plan"}`
- **THEN** the emitted `TraceNode` carries a fact-query `Role`
- **AND** its `Evidence` records the expected value `"build"`, observed set `{"plan"}`, and `matched: false`

#### Scenario: No ArgPattern-shaped fields on the producer/renderer seam

- **WHEN** inspecting the `TraceNode`, `Role`, and `Evidence` types exposed to renderers
- **THEN** no field name or variant name reproduces a `may_i_core::pattern::ArgPattern` variant or its internal field (e.g. `search_tokens`, `arg_set`, `match_mode`, `quantifier`)

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

#### Scenario: Carrier command shows inner trace
- **GIVEN** a carrier rule for `nohup` and an inner command `git push`
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
When a command-pattern `(or …)` list at the head of a `(rule …)` contains many alternatives, the renderer SHALL truncate after a reasonable number of items and show `…` for the rest.

#### Scenario: 20-alternative or-list truncates
- **WHEN** a rule's command-pattern is `(or …)` with 20 alternatives
- **THEN** the renderer SHALL print a bounded prefix followed by `…`

### Requirement: Trace rule shape matches source DSL surface

The human-readable evaluation trace SHALL render each rule using the current source-DSL surface: a command-pattern atom (a quoted string for `CommandPattern::Literal`) or a `(or "a" "b" …)` list (for `CommandPattern::Or`) directly under `(rule …)`, followed by the rule body forms (any combination of `(when …)`, `(unless …)`, `(if …)`, `(cond …)`, `(and …)`, `(or …)`, `(not …)`, predicate atoms, and terminal decision verbs) as direct children of the `(rule …)` list.

The legacy synthetic wrappers `(command …)`, `(args …)`, and `(context …)` SHALL NOT appear in the rendered rule body. `(when …)` and `(unless …)` predicates SHALL render literally — the trace producer SHALL NOT lift either form's predicate into a synthetic sibling.

This requirement parallels the canonical decision-verb requirement: just as `(allow)`/`(ask)`/`(deny)` render in source form rather than the retired `(effect …)` form, the rule shell renders in source form rather than the retired `(command …) (args …)` form.

#### Scenario: Literal command renders as a quoted string at rule head

- **GIVEN** a rule `(rule "rm" (deny "no rm"))`
- **WHEN** the trace renders the rule
- **THEN** the rendered head reads `(rule "rm"` (the next form on the next line is `(deny "no rm")`)
- **AND** the rendered output does not contain `(command "rm")`

#### Scenario: Or-alternation command renders as `(or …)` at rule head

- **GIVEN** a rule `(rule (or "cat" "tail" "head") (allow))`
- **WHEN** the trace renders the rule
- **THEN** the rendered head reads `(rule (or "cat" "tail" "head")` (followed by `(allow)`)
- **AND** the rendered output does not contain `(command (or "cat" "tail" "head"))`

#### Scenario: `when` body renders literally

- **GIVEN** a rule `(rule "terragrunt" (when (positional "hcl") (allow "safe")))`
- **WHEN** the trace renders the rule
- **THEN** the rule body line reads `(when (positional "hcl")` with `(allow "safe")` as its body
- **AND** the rendered output contains no `(args …)` wrapper
- **AND** the rendered output contains no synthetic `(context …)` sibling

#### Scenario: `unless` body renders literally

- **GIVEN** a rule `(rule "kubectl" (unless (fact? [:env "prod"]) (allow)))`
- **WHEN** the trace renders the rule
- **THEN** the rule body line reads `(unless (fact? [:env "prod"])` with `(allow)` as its body
- **AND** the rendered output contains no synthetic `(context …)` sibling

#### Scenario: Terminal decision under rule renders as direct child

- **GIVEN** a rule `(rule "ls" (allow "Read-only"))`
- **WHEN** the trace renders the rule
- **THEN** the rendered shape is `(rule "ls" (allow "Read-only"))` (with normal pretty-print line breaks)
- **AND** the rendered output contains no `(args …)` wrapper and no `(command …)` wrapper

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

### Requirement: Human trace renders compact evidence for context fact queries
The human-readable evaluation trace SHALL preserve the written `fact?` query on the left and summarize context-fact evidence on the right using a single compact annotation. Presence queries MUST render only `yes` or `no`. Exact scalar queries MUST render `yes` on success, the observed scalar value on mismatch, and `no` when no scalar value is available. Pattern-based scalar queries MUST render the observed scalar value with the final verdict whenever a scalar value is available, and `no` otherwise.

#### Scenario: Presence query renders only the verdict
- **WHEN** a rendered trace includes `(fact? :via/ssh)` and the context contains `:via/ssh`
- **THEN** the right column for that query is `yes`

#### Scenario: Exact scalar mismatch renders the observed value
- **WHEN** a rendered trace includes `(fact? [:opencode/agent "build"])` and the context contains `:opencode/agent` = `{"plan"}`
- **THEN** the right column for that query is `"plan" -> no`

#### Scenario: Pattern-based scalar query renders the observed value on success
- **WHEN** a rendered trace includes `(fact? [:ssh/host (regex "^prod-")])` and the context contains `:ssh/host` = `{"prod-1"}`
- **THEN** the right column for that query is `"prod-1" -> yes`

#### Scenario: Missing scalar value renders plain no
- **WHEN** a rendered trace includes `(fact? [:ssh/host (regex "^prod-")])` and the context does not include `:ssh/host`
- **THEN** the right column for that query is `no`

### Requirement: Human trace places fact evidence on the decisive query line
When a `fact?` query wraps across multiple rendered lines, the human-readable trace SHALL place the single right-column annotation on the line containing the decisive leaf that finalized the query result. Unevaluated branches from short-circuited value patterns MUST remain visible and dimmed.

#### Scenario: Wrapped regex query annotates the regex line
- **WHEN** `(fact? [:ssh/host (regex "^prod-")])` wraps across multiple rendered lines and the context contains `:ssh/host` = `{"prod-1"}`
- **THEN** the annotation `"prod-1" -> yes` appears on the rendered line containing `(regex "^prod-")`

#### Scenario: Short-circuited composed pattern annotates the decisive leaf
- **WHEN** `(fact? [:opencode/agent (or "build" (regex "^plan-"))])` wraps across multiple rendered lines and the context contains `:opencode/agent` = `{"build"}`
- **THEN** the annotation `"build" -> yes` appears on the rendered line containing `"build"`
- **AND** the rendered line containing `(regex "^plan-")` is dimmed as unevaluated

#### Scenario: Missing scalar value annotates the key-value portion of the query
- **WHEN** `(fact? [:ssh/host (regex "^prod-")])` wraps across multiple rendered lines and the context does not include `:ssh/host`
- **THEN** the annotation `no` appears on the rendered line nearest the key/value part of the query rather than on the closing delimiter line

### Requirement: JSON trace remains explicit for context fact queries
Machine-readable trace output SHALL preserve full detail for `fact?` evaluation even when the human-readable trace is compressed. JSON annotations MUST distinguish presence, exact scalar, and pattern-based `fact?` queries; include canonicalized query source strings; and record explicit failure reasons such as `absent`, `no_matching_member`, and `pattern_mismatch`. Pattern-based JSON annotations MUST include both a structured pattern AST and a nested evaluation tree containing unevaluated children marked with `evaluated: false`.

#### Scenario: Exact scalar absence records an explicit failure reason
- **WHEN** JSON trace output includes evaluation for `(fact? [:opencode/agent "build"])` and the context does not include `:opencode/agent`
- **THEN** the corresponding annotation reports a failed exact-scalar `fact?` query with failure reason `absent`

#### Scenario: Pattern evaluation records unevaluated children
- **WHEN** JSON trace output includes evaluation for `(fact? [:opencode/agent (or "build" (regex "^plan-"))])` and the context contains `:opencode/agent` = `{"build"}`
- **THEN** the corresponding annotation includes the canonical source for the full query
- **AND** its nested pattern evaluation marks the `"build"` child as evaluated and matched
- **AND** its nested pattern evaluation includes the `(regex "^plan-")` child with `evaluated: false`

### Requirement: Human trace renders the resolved parser as a kv row beneath the command row
The human-readable evaluation trace SHALL render the resolved parser for the evaluated command as a key-value row using the same two-column geometry as the `command` row, with label `parser` on the left and the parser description on the right. The `parser` row SHALL appear immediately beneath the `command` row, with no intervening blank line. The right column SHALL contain the resolved style name; when the parser declares parameter spellings, they SHALL follow as ` parameters (<token> <token> …)`; when the parser declares a tail boundary, it SHALL follow as ` tail (after <spec>)`.

#### Scenario: Default gnu parser with no parameters or tail
- **WHEN** rendering a failure trace whose resolved parser has style `gnu`, no parameter spellings, and no tail
- **THEN** the trace contains a `command │ <command-string>` row
- **AND** the next rendered row is `parser │ gnu`
- **AND** there is no blank line between the `command` row and the `parser` row

#### Scenario: Parser with parameter spellings
- **WHEN** rendering a failure trace whose resolved parser has style `gnu` and parameter spellings `-X` and `--request`
- **THEN** the `parser` row's right column reads `gnu  parameters (-X --request)`

#### Scenario: Parser with a tail boundary
- **WHEN** rendering a failure trace whose resolved parser has style `gnu` and tail `Tail::AfterFlags`
- **THEN** the `parser` row's right column reads `gnu  tail (after :flags)`

#### Scenario: Parser with both parameters and a tail boundary
- **WHEN** rendering a failure trace whose resolved parser has style `gnu`, parameter spellings `-c`, and tail `Tail::AfterToken(["--"])`
- **THEN** the `parser` row's right column reads `gnu  parameters (-c)  tail (after "--")`

### Requirement: Standalone right-aligned parser banner is removed
The human-readable evaluation trace SHALL NOT render the parser as a standalone right-aligned banner row above the `command` row. The previously emitted blank line that followed the standalone banner SHALL also be removed.

#### Scenario: No top-of-trace parser banner
- **WHEN** rendering any failure trace
- **THEN** the trace does not contain a row whose left column is the entire width and whose visible text begins with `parser:` followed by the style name
- **AND** the first rendered content row of the trace is the `command` row

### Requirement: Trace renders `ArgPattern::Tail` using source syntax
The human-readable evaluation trace SHALL render `ArgPattern::Tail` as the s-expression `(tail (authorise))` in the annotated rule body.

#### Scenario: Tail authorise predicate appears in source form
- **GIVEN** a rule containing `(tail (authorise))`
- **WHEN** the trace renders the rule body
- **THEN** the corresponding line reads `(tail (authorise))`
- **AND** the trace does not contain the literal string `<unknown-arg-pattern>`

### Requirement: Trace renders `ParameterForm::MayI` as `(authorise)`
The human-readable evaluation trace SHALL render `ParameterForm::MayI` inside a `(parameter …)` predicate as `(authorise)` in the annotated rule body.

#### Scenario: Parameter authorise predicate appears in source form
- **GIVEN** a rule containing `(parameter "c" (authorise))`
- **WHEN** the trace renders the rule body
- **THEN** the corresponding line reads `(parameter "c" (authorise))`
- **AND** the rendered text does not contain `(may-i *)`

### Requirement: Trace renders terminal effects using `(allow|ask|deny "reason"?)` form
The human-readable evaluation trace SHALL render `Effect::Terminal` nodes using their canonical source syntax — `(allow)`, `(ask)`, `(deny)`, or any of the three with a quoted reason — in the annotated rule body. The legacy `(effect :allow|:ask|:deny "reason"?)` form SHALL NOT appear in the rendered rule body.

The right-column decision annotation produced from `Ann::EffectDecision` SHALL continue to use the colon-prefixed keyword form (e.g. `→ :allow "reason"`).

#### Scenario: Allow with reason
- **GIVEN** a rule whose terminal effect is `Effect::Terminal { decision: Allow, reason: Some("safe") }`
- **WHEN** the trace renders the rule body
- **THEN** the corresponding line reads `(allow "safe")`
- **AND** the right column for that line reads `→ :allow "safe"`

#### Scenario: Bare ask
- **GIVEN** a rule whose terminal effect is `Effect::Terminal { decision: Ask, reason: None }`
- **WHEN** the trace renders the rule body
- **THEN** the corresponding line reads `(ask)`
- **AND** the right column for that line reads `→ :ask`

#### Scenario: Deny with reason
- **GIVEN** a rule whose terminal effect is `Effect::Terminal { decision: Deny, reason: Some("blocked in prod") }`
- **WHEN** the trace renders the rule body
- **THEN** the corresponding line reads `(deny "blocked in prod")`
- **AND** the right column for that line reads `→ :deny "blocked in prod"`

### Requirement: Trace annotates `(tail (authorise))` with the tail slice
When `ArgPattern::Tail` matches, the human-readable evaluation trace SHALL render a right-column annotation on the `(tail (authorise))` line of the form `tail = "<value>"` where `<value>` is the captured tail slice's tokens joined by single ASCII spaces and surrounded by double-quote delimiters. The previous full-argv `(authorise) ∈ { … } → yes` form SHALL NOT appear.

#### Scenario: Single-token tail slice
- **GIVEN** evaluating `direnv exec true` against a rule containing `(tail (authorise))`, with `direnv`'s `(positional "exec")` consuming `exec`
- **WHEN** the trace renders the rule body
- **THEN** the right column for the `(tail (authorise))` line reads `tail = "true"`

#### Scenario: Multi-token tail slice
- **GIVEN** evaluating `direnv exec echo hi there` against a rule containing `(tail (authorise))`
- **WHEN** the trace renders the rule body
- **THEN** the right column for the `(tail (authorise))` line reads `tail = "echo hi there"`

#### Scenario: Tail slice is not the full argv
- **WHEN** rendering a trace whose tail slice is `["true"]` and full argv is `["exec", "true"]`
- **THEN** the right column for the `(tail (authorise))` line reads `tail = "true"`
- **AND** the rendered annotation does not contain `"exec"`

### Requirement: Trace annotates `(parameter NAME (authorise))` with the captured value
When `ArgPattern::Parameter` with `ParameterForm::MayI` captures a value, the human-readable evaluation trace SHALL render a right-column annotation on the `(parameter …)` line of the form `value = "<captured>"` where `<captured>` is the captured single-token parameter value, surrounded by double-quote delimiters. The inner recursion trace SHALL still render beneath the rule.

#### Scenario: Bash -c captures a quoted command
- **GIVEN** evaluating `bash -c "echo hi"` against a rule containing `(parameter "c" (authorise))`
- **WHEN** the trace renders the rule body
- **THEN** the right column for the `(parameter "c" (authorise))` line reads `value = "echo hi"`
- **AND** the trace also includes a child block showing the recursive evaluation of `echo hi`

#### Scenario: Multi-token captured value
- **GIVEN** evaluating `bash -c "echo hi there"` against a rule containing `(parameter "c" (authorise))`
- **WHEN** the trace renders the rule body
- **THEN** the right column for the `(parameter "c" (authorise))` line reads `value = "echo hi there"`

### Requirement: Trace producer records structural data, not display strings, and owns layout decisions

The trace producer (`TracingFold` and the `TraceNode` / `TraceEntry` types it populates) SHALL carry structural data only. Display-only formatting — parser flag-mode rendering, observed-value summarisation prose, regex literal quoting, fact-failure prose, and any other transformation whose output exists to satisfy the two-column text renderer's layout — SHALL live in the renderer, not the producer.

Concretely, a field on `TraceNode`, `Role`, `Evidence`, or `TraceEntry` MUST NOT be populated by calling a display-format helper. Field types MUST match the structural shape of the recorded value (sets, integers, enums, literal-source strings such as a regex pattern or a binding name), not a pre-rendered display string.

The producer SHALL additionally own all *structural layout decisions* that affect what the renderer outputs: truncation of long `(or …)` alternative lists, dimming of unevaluated branches, collapsing of skipped `cond` branches into a single trailing `…`, evidence compaction for context-fact queries (presence vs. exact scalar vs. pattern-based), and structural correspondence between a trace node and the rendered line that carries its right-column annotation. Renderers SHALL receive a pre-decided `TraceNode` tree and translate node shapes to bytes; they SHALL NOT re-decide truncation, dimming, collapse, or annotation placement.

The producer SHALL NOT expose `ArgPattern`-shaped fields across the producer/renderer seam. The accessor surface on `TraceNode` is the only path by which renderers read producer output; pattern matching on internal enum variants from renderer code is prohibited (see `output-rendering`).

#### Scenario: Parser entry records flag mode structurally

- **WHEN** `TracingFold` records a parser `TraceEntry` for a parser declared with `(flags until "--")`
- **THEN** the recorded flag-mode field carries the structural until-list (e.g. `Until(["--"])`), not the pre-rendered string `"until \"--\""`

#### Scenario: FactQuery records observed values structurally

- **WHEN** `TracingFold` records a fact-query trace node for a query against facts where the key has values `{"prod", "staging"}`
- **THEN** the recorded observed-values field carries the set `{"prod", "staging"}`, not a pre-rendered comma-joined string

#### Scenario: FactQuery records failure mode structurally

- **WHEN** a fact query fails because the key is absent
- **THEN** the recorded failure-mode field carries a structural variant (e.g. `Evidence::FactAbsent`), not the prose string the renderer emits

#### Scenario: Text renderer formats from structural data

- **WHEN** the text renderer renders a parser trace entry with the structural flag-mode field
- **THEN** it produces the same byte sequence the previous implementation produced from the pre-rendered string

#### Scenario: JSON renderer formats from structural data

- **WHEN** `trace_to_json` serialises a trace tree carrying structural fields
- **THEN** the JSON output preserves the user-observable invariants from this capability (presence of `type`, `decision`, and failure-reason fields; nested var-breakout shape; unevaluated children marked `evaluated: false`); the JSON field shape MAY otherwise change to drop `ArgPattern`-leaking shape (e.g. `search_tokens` + `arg_set` collapse into a single `evidence` object)

#### Scenario: Producer pre-decides truncation, dimming, and collapse

- **WHEN** the producer emits a trace for a rule whose command-pattern `(or …)` has 20 alternatives, or for a `cond` whose 2nd branch matches out of 5, or for a short-circuited `and`
- **THEN** the emitted `TraceNode` tree already carries the bounded prefix + trailing `…` for the long `or`, the single trailing `…` for the collapsed `cond`, and the `Role::Dimmed` markers for the skipped `and` children
- **AND** the renderer renders the tree it receives without re-applying truncation, collapse, or dimming logic

### Requirement: ArgPattern display rendering is exhaustive in the producer

The trace producer's `ArgPattern → TraceNode` conversion SHALL match every `ArgPattern` variant explicitly. A wildcard fallthrough that produces a placeholder atom (e.g. `<unknown-arg-pattern>`) SHALL NOT appear in this conversion. Adding a new `ArgPattern` variant in the workspace SHALL produce a compile error in the trace producer until an explicit display arm is added.

Renderers SHALL NOT see `ArgPattern` at all (see `output-rendering`); the exhaustiveness obligation lives at the producer's `ArgPattern → TraceNode` seam, which is the only call site that destructures `ArgPattern` for trace purposes.

#### Scenario: Compile-time exhaustiveness at the producer

- **WHEN** a developer adds a new `ArgPattern` variant in `crates/core/src/pattern.rs`
- **AND** runs `cargo build`
- **THEN** the build fails with a non-exhaustive-match error pointing at the trace producer's `ArgPattern` match
- **AND** no rendered output contains the literal string `<unknown-arg-pattern>`

#### Scenario: Renderers do not match on ArgPattern

- **WHEN** scanning `src/output/transform.rs`, `src/output/render_rule.rs`, and `src/output/json.rs` for `ArgPattern::` match arms
- **THEN** zero matches are found
