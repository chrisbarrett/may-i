## MODIFIED Requirements

### Requirement: TraceNode roles cover all annotation kinds

The trace producer SHALL emit a `TraceNode` tree whose `Role` enum covers every annotation kind a renderer needs to display: command match, argument match (with evidence), fact query result (with observed values and failure reason), effect decision (with decision and reason), quantifier / combinator result, named-predicate reference, and captured-value annotations. These roles correspond to the evidence needed for the right column in two-column trace output.

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

- **WHEN** the producer emits a trace for a `(command (or …))` with 20 alternatives, or for a `cond` whose 2nd branch matches out of 5, or for a short-circuited `and`
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

## REMOVED Requirements

### Requirement: Structural annotation placement via AnnotatedLineBuilder

**Reason:** The producer now pre-computes which `TraceNode` carries the right-column annotation and the renderer attaches it to the matching rendered line by structural correspondence (TraceNode → ColRow). With placement decided at producer time, the renderer has no annotation-collection or priority-arbitration job to do, so `AnnotatedLineBuilder` is no longer the placement path. The decisive-line scenarios in "Human trace places fact evidence on the decisive query line" remain in force and are now satisfied structurally rather than by post-hoc line collection.

**Migration:** Renderers stop using `AnnotatedLineBuilder` and instead walk the `TraceNode` tree alongside the rendered `Layout`, attaching each node's evidence to the ColRow produced from that node. The compile-time obligation that the placement be structural (not string-matched) is preserved in spirit by the new producer/renderer contract: renderers receive `TraceNode`s, not rendered strings to grep.

### Requirement: Multiple annotations per line use priority ordering

**Reason:** With the producer pre-deciding which trace node carries the right-column annotation, the renderer never receives multiple competing annotations for a single rendered line. Priority arbitration is unnecessary because the producer emits one evidence-bearing node per displayed annotation slot.

**Migration:** Where the old priority-ordering logic was meaningful (e.g. effect-decision annotation wins over a child predicate's annotation on the same line), the producer encodes the winner directly: only the winning node carries `Evidence`; sibling nodes carry `Role` markers without evidence. Renderers render whatever evidence they find on the node corresponding to a given rendered line, with no tie-breaking pass.
