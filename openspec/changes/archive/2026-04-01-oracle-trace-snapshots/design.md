## Context

The `may-i` tool was rewritten with a V2 config syntax. V1 configs are
transparently migrated at load time via sexpr rewrite rules. Evaluation runs on
the V2 AST, but the original V1 source text and byte spans are preserved
(`config.source_text` holds the original content; AST span offsets point into
it).

The trace output currently renders V2 AST structure (effects inlined into args,
expanded patterns, `define` instead of `defcontext`). The oracle (previous
release) renders V1 structure directly.

Oracle snapshots have been captured from the previous release binary into
`tests/snapshots/oracle_v1/` with `CLICOLOR_FORCE=1 COLUMNS=80`. A reduced V1
fixture config and test manifest exist in `tests/fixtures/v1/`.

## Goals / Non-Goals

**Goals:**

- Integration test harness that asserts dev build trace output matches oracle
  snapshots exactly (both ANSI-coloured and stripped).
- Source recovery: trace shows original V1 s-expression structure for migrated
  configs.
- Test infrastructure supports adding V2-native snapshot tests later.

**Non-Goals:**

- Fixing all trace divergences in this change — the tests are expected to fail
  initially and drive iterative fixes.
- V2-format snapshot tests (deferred to a follow-up change).
- Changing eval semantics — only display/trace rendering is affected.

## Decisions

### 1. Test harness: integration test calling Rust API, not shelling out

The test (`tests/oracle_trace_v1.rs`) will call the config loader and eval
pipeline directly via `may_i_config::load`, `engine::eval::evaluate_with_fold`,
and the `TracingFold` + `output::print_trace` rendering path.

Output capture uses an in-process string buffer rather than spawning a
subprocess, avoiding PATH/binary version issues in CI.

**Alternative considered**: Shelling out to `cargo run --`. Rejected because it
couples tests to binary availability and makes output capture fragile (stderr
mixing, exit codes).

### 2. Snapshot format: side-by-side `.raw` + `.txt` files

Each test case has two oracle snapshot files:

- `{name}.raw` — byte-exact output with ANSI escape sequences
- `{name}.txt` — ANSI-stripped for human review

The test asserts against `.txt` for the primary comparison (readable diffs) and
against `.raw` for colour correctness as a separate assertion. This way a colour
regression doesn't block seeing structural diffs.

**Alternative considered**: Single file with insta snapshots. Rejected because
insta doesn't handle raw ANSI well and we want the oracle output committed
verbatim as ground truth.

### 3. Config path normalisation

Oracle snapshots contain `config: ~/src/chrisbarrett/may-i/tests/fixtures/...`.
The test must normalise this line to a stable placeholder like
`config: <config-path>` before comparison, since the absolute path differs per
machine.

### 4. Terminal width: pinned at COLUMNS=80

Set `std::env::set_var("COLUMNS", "80")` in the test to make the layout
deterministic. The oracle snapshots were captured at this width.

### 5. Forced colour: use `colored::control::set_override(true)`

The `colored` crate respects `CLICOLOR_FORCE` or programmatic override. The test
sets `colored::control::set_override(true)` before rendering to match the oracle
capture environment.

### 6. Source recovery approach (v1-source-recovery): pre-migration CST

When a config is loaded via transparent CST-rewrite migration, the trace
renderer displays the original source structure by retaining the pre-migration
CST nodes alongside the migrated V2 AST.

The approach:

1. During `try_migrate_and_parse`, clone the parsed CstNodes **before** calling
   `migrate_forms`. Store them as `config.pre_migration_cst`.
2. When rendering a rule's trace, match the rule to its pre-migration CstNode by
   span overlap (`rule.span` indexes into `source_text`, which is the original
   content; CstNode spans point into the same content).
3. Convert the matched CstNode to `Doc<Option<Ann>>` via `CstNode::to_doc()`,
   then apply truncation/dimming and overlay TracingFold annotations using the
   existing `find_line` needle-matching approach.

This decouples display structure from eval structure. Annotations are produced by
eval on the V2 AST; display comes from original source CST.

**Why this generalises**: The migration system uses CST rewrites. Any future
migration pipeline (V2→V3, etc.) has the same structure: parse → rewrite → parse
AST. Storing the pre-rewrite CST is a one-line change in the pipeline. The
renderer doesn't need to know which rewrites happened.

**Alternative considered**: Reverse-transforming V2 Doc trees to look like V1.
Rejected — fragile, requires an inverse for every migration rule.

**Alternative considered**: Span-based source text extraction (parse
`source_text[rule.span]` into V1 text). Rejected — requires re-parsing
extracted text fragments, and the CstNodes are already available before
migration runs. Storing them directly is simpler and avoids re-parsing.

**Alternative considered**: Maintaining an ordered log of rewrites to invert.
Rejected — rule ordering/interaction makes inversion non-trivial, and some
rewrites add information (e.g. `rule_add_default_effect`), making inversion
lossy.

## Risks / Trade-offs

- **[Annotation placement]** → Overlaying annotations from V2 eval onto V1
  source lines relies on string-matching needles. Some annotations may land on
  wrong lines if V1 and V2 structures differ significantly. Mitigation: the
  existing `find_line` approach already handles this; we extend rather than
  replace.

- **[Migration rule changes break snapshots]** → If migration rules are updated,
  V1 eval semantics could change, invalidating oracle snapshots. Mitigation:
  migration rules are stable (V1 is frozen); snapshots are the regression guard.

- **[Tests fail initially]** → Expected. The snapshot tests are the spec; we
  iterate the renderer until they pass. This is intentional — not a risk but the
  design.

- **[Config path in snapshots]** → Must be normalised. If normalisation regex is
  too aggressive it could mask real differences. Mitigation: only replace the
  `config:` footer line.
