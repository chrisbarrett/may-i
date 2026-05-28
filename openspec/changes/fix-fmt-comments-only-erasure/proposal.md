## Why

`may-i fmt` erases the contents of any config file that contains only comments (and whitespace), replacing the file with a single newline. This is silent data loss — the user has no warning, the exit code is `0`, and the file shrinks from N bytes to 1 byte. Reproduces against a file containing only `;;` lines.

## What Changes

- `may-i fmt` SHALL be a no-op on input that parses cleanly but contains zero forms (e.g. comments-only files, whitespace-only files). Files of this shape SHALL be left byte-identical on disk; stdin filter mode SHALL pass them through to stdout unchanged.
- `--check` SHALL report such inputs as already canonical (exit `0`), never as "would change".
- Add a property test asserting that any input with no parse errors round-trips byte-identically when the input contains zero forms.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `fmt-command`: add a requirement that formless inputs (no top-level forms, no parse errors) are preserved verbatim across both file mode and stdin filter mode, in both normal and `--check` invocations.

## Impact

- `src/cmd_fmt.rs` — `canonical_text` / `process_file` / `run_stdin_text`: skip the rewrite when the parsed CST yields zero forms and the source has no parse errors.
- Optional follow-up (decided in design.md): teach `crates/sexpr/src/cst.rs::Parser::parse` not to drop trailing trivia when no form follows. The user-facing fix does not depend on this; treat as design choice.
- Tests: integration test for the comments-only file, property test for the formless round-trip invariant.
