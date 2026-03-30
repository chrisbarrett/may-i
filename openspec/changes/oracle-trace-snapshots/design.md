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

### 6. Source recovery approach (v1-source-recovery): span-based extraction

When `config.source_text` contains V1 source (detectable because migration was
applied), the trace renderer extracts original source text at each rule's span
rather than pretty-printing from V2 AST `to_doc()`.

The approach:

1. For each rule, extract `source_text[rule.span.start..rule.span.end]` to get
   the original V1 s-expression.
2. Pretty-print this V1 text as the left column of the trace.
3. Overlay eval annotations (match results, decisions) from the TracingFold onto
   the rendered lines using the existing `find_line` needle-matching approach.

This decouples display structure from eval structure. Annotations are produced by
eval on the V2 AST; display comes from original source.

**Alternative considered**: Reverse-transforming V2 Doc trees to look like V1.
Rejected — fragile, requires an inverse for every migration rule.

**Alternative considered**: Carrying parallel V1 CST alongside V2 AST. Rejected
— doubles data, complicates the config struct.

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
