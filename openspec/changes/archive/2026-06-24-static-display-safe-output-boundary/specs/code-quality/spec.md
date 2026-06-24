## ADDED Requirements

### Requirement: No workspace crate depends on colored

The `colored` crate SHALL NOT be a dependency of any workspace crate — including
the root binary, `config`, `pp`, and `may-i-output`. The renderer in
`may-i-output` emits SGR sequences directly from its role→SGR table (raw
`\x1b[…m` writes), so `colored` is unnecessary even there, and any inline styling
(`"x".red()`, `.dimmed()`, …) anywhere in the workspace is a compile error rather
than a reviewable convention. This is strictly stronger than confining `colored`
to the renderer crate: the role→SGR table in `may-i-output` is the only code that
produces an ANSI sequence, and it does so without the dependency.

#### Scenario: colored is absent from the dependency graph

- **WHEN** `cargo metadata --format-version 1` (or `Cargo.lock`) is inspected
- **THEN** no package named `colored` appears

#### Scenario: No inline colored calls anywhere

- **WHEN** the workspace is scanned for `use colored` or `Colorize` method calls (`.red()`, `.green()`, `.blue()`, `.yellow()`, `.cyan()`, `.dimmed()`, `.bold()`, `bright_*`)
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
