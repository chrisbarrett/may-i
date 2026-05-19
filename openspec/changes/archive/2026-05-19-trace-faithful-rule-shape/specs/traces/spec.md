## ADDED Requirements

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

## MODIFIED Requirements

### Requirement: Long or-lists are truncated with elision
When a command-pattern `(or …)` list at the head of a `(rule …)` contains many alternatives, the renderer SHALL truncate after a reasonable number of items and show `…` for the rest.

#### Scenario: 20-alternative or-list truncates
- **WHEN** a rule's command-pattern is `(or …)` with 20 alternatives
- **THEN** the renderer SHALL print a bounded prefix followed by `…`

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
