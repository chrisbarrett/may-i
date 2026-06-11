## Why

A command substitution inside an **unquoted** heredoc body is executed by real
bash, but `may-i` does not evaluate it. Confirmed against the built binary with
`echo`/`rm` rules where `rm --force` denies:

```
cat <<EOF
$(rm --force)
EOF
```

→ `:allow`. The `$(rm --force)` runs at heredoc expansion time in a real shell,
yet it never reaches evaluation. This is the exact dual of the already-fixed
process-substitution and `$(…)` extraction work: the parser correctly treats a
**quoted** heredoc (`<<'EOF'`, `<<"EOF"`, `<<\EOF`) as inert (real bash suppresses
expansion there — see the existing "Quoted heredoc bodies are inviolable"
requirement), but it must do the opposite for an **unquoted** heredoc, whose body
*is* expanded. An embedded command that escapes analysis defeats the tool.

## What Changes

- Extract and evaluate command and arithmetic substitutions
  found in the body of an **unquoted** heredoc (`<<EOF`, `<<"EOF"` is quoted and
  stays inert; the unquoted delimiter form `<<EOF` expands). Each embedded
  command becomes its own evaluation unit, aggregated strictest-wins, exactly as
  for `$(…)` in argument position. Process substitution is NOT extracted: bash
  does not perform it in heredoc bodies, so `<(…)` there is inert literal text
  (often documentation), and extracting it would deny commands that never run.
- Quoted heredocs (`<<'EOF'`, `<<\EOF`) remain inviolable — unchanged. The
  distinction is the delimiter quoting, which the lexer already records.
- Backstop: an unterminated substitution inside an unquoted heredoc body is not
  recursed into (it carries an Error-severity diagnostic and the floor owns the
  outcome), consistent with "Unterminated substitutions are not recursed into".

## Capabilities

### New Capabilities

<!-- none -->

### Modified Capabilities

- `shell-command-security-model` (bucket: parsing; trust-relevant): add a
  requirement that embedded substitutions in an unquoted heredoc body are
  extracted and evaluated, complementing the existing quoted-heredoc-inviolable
  requirement.

## Impact

- `crates/shell-parser` — when a heredoc opener is unquoted, parse the body for
  dynamic `WordPart`s (it is currently captured as an opaque literal body);
  attach their source + span with the same inner-span semantics as elsewhere.
  Quoted-opener bodies stay opaque.
- `crates/engine/src/eval/decompose.rs` — emit `EvalUnit::EmbeddedCommand` for
  substitutions found in an unquoted heredoc body, reusing the `$(…)` path.
- Tests: `crates/shell-parser` body-parsing cases + `crates/engine` eval
  scenarios; a proptest that no command escapes when reachable via an unquoted
  heredoc.
- No DSL, config, or trust-hash change; no migration. Out of scope: parameter
  expansions that merely interpolate text (only embedded *commands* are
  evaluation units).
