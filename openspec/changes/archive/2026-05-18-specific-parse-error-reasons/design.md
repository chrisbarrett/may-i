## Context

The engine emits the literal `"parse error: ambiguous command boundary"` at
two aggregate sites (`crates/engine/src/eval/command.rs:129,241`) whenever
`parse_result.has_errors()` is true. This single string is the only thing
the Claude Code hook surfaces as `permissionDecisionReason`
(`src/cmd_claude_code_hook.rs:116`), and the only headline reason
`may-i eval` shows.

The structured information needed to do better already exists. Each
`ParseDiagnostic` carries:

- a `Severity` (`Error` for boundary-ambiguous cases),
- a `ParseDiagnosticKind` (`UnterminatedSingleQuote`, `UnterminatedBacktick`, …),
- a byte-offset `Span { start, end }` into the original input,
- a stable English `message()` (e.g. `"unterminated single quote"`).

These flow as `EvalResult.parse_diagnostics` to the CLI, which already
renders them via miette in `src/shell_parse_error.rs`. The hook surface,
however, only consumes `reason` — so the structured diagnostics are
invisible to the primary agent consumer.

## Goals / Non-Goals

**Goals:**

- Replace the generic reason with a one-line message that names the
  diagnostic kind, line+column, and a short source excerpt around the
  offending span.
- Keep the `"parse error: "` prefix so the agent can distinguish a
  parse-level failure from a policy denial.
- Keep the formatter in `crates/shell-parser` so the diagnostic data
  and its canonical phrasing live together.
- Leave the CLI miette path untouched — it already renders the full
  diagnostic vector with carets.

**Non-Goals:**

- No fix suggestions (heredoc / `-F file` / escape advice). Pattern
  detection widens surface area for marginal benefit; trust the agent
  to know shell.
- No reporting of cascading diagnostics. Multi-diagnostic cases are
  almost always a single root cause echoing; surfacing them in the
  reason invites chasing the wrong fix.
- No schema or migration changes to hook output or `EvalResult` shape.

## Decisions

### Formatter lives on `ParseDiagnostic` in `shell-parser`

Add `impl ParseDiagnostic { pub fn format_with_source(&self, src: &str) -> String }`
returning `"<kind message> at line L, column C: <excerpt>"`.

- L, C are 1-based, derived from `span.start` by counting newlines in `src`.
- Excerpt: ~20 chars before `span.start` and ~30 chars from `span.start`,
  with control characters escaped (`\n`, `\t`, etc.), ellipsised on either
  side when truncated, and wrapped in single quotes.

**Alternatives considered:**

- Format in the engine. Rejected — the data lives in shell-parser; engine
  would duplicate the kind-to-message mapping that already exists in
  `ParseDiagnostic::message()`.
- Format in each surface (hook, eval pretty, eval JSON). Rejected — three
  call sites means three places to keep in sync, with high drift risk.
- Reuse `ShellParseError` (the miette renderer in `src/shell_parse_error.rs`).
  Rejected — miette output is multi-line, ANSI-styled, optimised for TTY;
  the hook reason is a single plain string in a JSON field.

### First error-severity diagnostic only

The engine selects the first `ParseDiagnostic` with `Severity::Error` and
passes it (and the input) to the formatter. Warnings are ignored. If the
parser reported error-severity but the diagnostics vector contains no
error-severity entries (defensive case), fall back to the current generic
string.

**Alternatives considered:**

- All diagnostics joined. Rejected — cascades read as noise (a stray `'`
  produces an unterminated single quote *and* an unterminated backtick
  *and* an unterminated command substitution; only the first is real).
- Highest-severity, then earliest. Rejected — `Severity` is a binary
  Warning/Error; earliest is already the right tiebreaker.

### Both aggregate sites use the same helper

`evaluate_top_level` (`command.rs:129`) and `evaluate_authorised_string`
(`command.rs:241`) both call the formatter with the same `input` string
they parsed. Outer-frame line/column are correct by construction — the
helper does not need to know about recursive offsets because each site
passes its own local source.

## Risks / Trade-offs

- **[Risk]** Excerpt may leak sensitive content from the rejected command
  into the hook reason. → **Mitigation:** hook callers already trust the
  command they're authorising — the input is what they're asking about.
  No new exposure surface vs. the current trace output.
- **[Risk]** Line/column counting on large inputs adds work to a hot
  rejection path. → **Mitigation:** single linear scan of bytes preceding
  `span.start`; bounded by input length, which is already O(n) parsed.
- **[Risk]** Snapshot tests pinned to the old reason string fail. →
  **Mitigation:** pre-1.0; update snapshots as part of this change.
- **[Trade-off]** Excerpt width is a heuristic (~20+30 chars). Too narrow
  hides context, too wide bloats reason. Chosen to fit comfortably in
  one terminal line including the prefix and "at line L, column C: " framing.
