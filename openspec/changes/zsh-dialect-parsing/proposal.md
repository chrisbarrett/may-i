## Why

The parser assumes bash syntax. zsh has no formal published grammar, but it
diverges from bash in ways that misparse legitimate, executable zsh. Measured
against `zsh -n`, the two highest-frequency divergences are:

- **Glob qualifiers** (`ls **/*(.)`) emit an `Error`-severity diagnostic,
  which floors the decision to `:ask` — a genuine false positive that
  degrades authorisation for correct input.
- **No-semicolon brace terminators** (`foo() { echo hi }`) emit a
  `Warning` and misparse: the `}` is swallowed as a command argument and the
  group's boundary is lost. This does not floor the decision (embedded
  commands still evaluate, so it is fail-safe), but the AST is wrong and the
  trace is noisy.

Agents running under a zsh login shell routinely emit both forms. `$SHELL`
already tells us which dialect the harness will actually execute; the parser
should honour it rather than judging zsh against the bash grammar.

## What Changes

- Introduce a **shell dialect** selected per invocation. Default is bash
  (today's behaviour, unchanged). When the invocation's shell resolves to
  zsh, the parser accepts a documented set of zsh-only constructs instead of
  flagging them.
- Dialect resolution: the hook and `eval` modes derive the dialect from the
  executing shell (`$SHELL` basename), defaulting to bash when absent or
  unrecognised. `check` stays hermetic (bash). An explicit override is
  available for reproducing a decision under a chosen dialect.
- First-pass zsh constructs (highest-frequency divergences, measured against
  `zsh -n` as oracle):
  - **No-semicolon brace terminator** — `}` closes a command list without a
    preceding `;` or newline (`{ echo a }`, `foo() { echo hi }`).
  - **Glob qualifiers** — a trailing `(…)` qualifier on a glob word
    (`*(.om[1])`, `**/*(.)`, `*(/)`).
- Bash dialect is unaffected: `{ echo a }` and glob qualifiers still produce
  the same diagnostics they do today. The zsh productions are gated on the
  active dialect, never universal.
- Constructs deferred to a follow-up (documented, not implemented):
  anonymous functions `() { … }`, `foreach … end`, `repeat` loops,
  `always { }` blocks. Runtime `setopt`-dependent behaviour (e.g.
  `SH_WORD_SPLIT`) is explicitly out of scope — it is not statically
  decidable.

## Capabilities

### New Capabilities

- `shell-dialect` (bucket: `parsing`, user-facing): the dialect concept, the
  set of dialects, how a dialect is resolved per invocation (`$SHELL` → dialect,
  bash default, explicit override), and which zsh-only constructs the zsh
  dialect accepts. Trust-relevant: no — dialect changes which inputs parse
  cleanly, not which rules participate or how they are hashed.

### Modified Capabilities

- `shell-command-security-model` (bucket: `parsing`): diagnostics become
  **dialect-relative**. A construct that is well-formed in the active dialect
  SHALL NOT produce a diagnostic; a construct malformed in every supported
  dialect keeps its current severity. The existing bash scenarios are
  restated as holding under the bash dialect.

## Impact

- **`crates/shell-parser`**: `parse()` gains a dialect parameter; a new
  `Dialect` type; parser/lexer productions for the two zsh constructs, gated
  on dialect. `parse_simple_command` and other public entry points thread the
  dialect through (bash default preserves existing call sites where feasible).
- **`src/main.rs` / invocation modes**: resolve the dialect from the executing
  shell for hook and `eval`; wire the explicit override flag.
- **Callers in `may-i-engine`**: recursive re-parsing of embedded command
  bodies inherits the outer invocation's dialect.
- No config-format change, so no migration. `$SHELL`-based resolution is
  observed ground truth, analogous to the entry environment — not a Fact.
