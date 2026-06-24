## ADDED Requirements

### Requirement: may-i-output is the sole crate depending on colored

The `colored` crate SHALL be a dependency of `may-i-output` only. No other
workspace crate — including the root binary, `config`, and `pp` — SHALL declare
`colored` in its `Cargo.toml`, so inline styling (`"x".red()`, `.dimmed()`, …)
outside the renderer is a compile error rather than a reviewable convention. This
makes the role→SGR table in `may-i-output` the only code that can produce an ANSI
sequence.

#### Scenario: Only may-i-output depends on colored

- **WHEN** `cargo metadata --no-deps --format-version 1` is queried and each workspace member's dependency list is inspected
- **THEN** `colored` appears only for the `may-i-output` package

#### Scenario: No inline colored calls outside the renderer

- **WHEN** the workspace is scanned (excluding `crates/may-i-output/`) for `use colored` or `Colorize` method calls (`.red()`, `.green()`, `.blue()`, `.yellow()`, `.cyan()`, `.dimmed()`, `.bold()`, `bright_*`)
- **THEN** zero matches are found

### Requirement: Direct process-stream printing is denied outside the sink

The workspace SHALL deny `clippy::print_stdout`, `clippy::print_stderr`, and
`clippy::dbg_macro` so that `println!`/`print!`/`eprintln!`/`eprint!`/`dbg!` are
compile-blocked. Exactly one module (the output sink) SHALL carry the
`#[allow(...)]` for these lints. A pre-commit (prek) hook SHALL additionally ban
acquisition of a raw process stream handle — `io::stdout`, `io::stderr`,
`console::Term::stdout`/`stderr`, and raw terminal file descriptors — anywhere
outside the sink module, closing the gap clippy's macro lints leave (e.g.
`writeln!(stderr(), …)`).

#### Scenario: Workspace denies the print lints

- **WHEN** the workspace lint configuration is inspected
- **THEN** `print_stdout`, `print_stderr`, and `dbg_macro` are set to `deny`, and the only `#[allow(...)]` for them is in the sink module

#### Scenario: Clippy is clean under the new lints

- **WHEN** `cargo clippy --workspace` runs
- **THEN** no `print_stdout`, `print_stderr`, or `dbg_macro` lint fires

#### Scenario: prek hook bans stream-handle acquisition outside the sink

- **WHEN** the prek hook scans the workspace (excluding the sink module and tests) for `io::stdout`, `io::stderr`, `console::Term::std`, and raw-fd terminal access
- **THEN** zero matches are found, and the hook fails the commit if any are introduced
