# fmt-command Specification

## Purpose

The `may-i fmt` CLI subcommand: in-place file formatting, load-graph walk when no positional arguments, stdin → stdout filter mode, `--check` exit-code-only mode for CI, and the legacy-syntax warning that defers semantic rewrites to `may-i migrate`.

## Requirements

### Requirement: Format files in place by default

`may-i fmt FILE [FILE…]` SHALL format each given file in place. The command SHALL parse each file as a CST, apply the canonical body-form ordering pass, render with the pretty-printer using the column width detected from source, and overwrite the file with the result.

When multiple files are passed, each is processed independently. A parse error in one file SHALL NOT block processing of others; errors SHALL be collected and reported per file.

Read-only files SHALL be skipped with a stderr warning naming the path; processing of remaining files continues.

#### Scenario: Single file formatted in place

- **WHEN** `may-i fmt foo.lisp` runs against a file with non-canonical whitespace or declaration order
- **THEN** `foo.lisp` is overwritten with the canonical form
- **AND** the command exits `0`

#### Scenario: Multiple files formatted independently

- **WHEN** `may-i fmt a.lisp b.lisp c.lisp` runs and `b.lisp` has a parse error
- **THEN** `a.lisp` and `c.lisp` are formatted in place
- **AND** stderr names `b.lisp` with the parse error location
- **AND** the command exits `2` (the highest severity across files)

#### Scenario: Read-only file skipped with warning

- **WHEN** one of the files in the argument list is read-only
- **THEN** stderr emits `warning: skipped, not writable: PATH`
- **AND** processing of remaining files continues

### Requirement: Walk load graph when no positional arguments

`may-i fmt` invoked with no positional arguments AND with stdin connected to a terminal SHALL walk the `(load …)` graph starting from the primary config (or the path given by `--config` / `MAYI_CONFIG`) and format every transitively-loaded file in place. The walk SHALL use the same `walk_load_graph` traversal as `may-i migrate`.

#### Scenario: Bare invocation walks load graph

- **WHEN** `may-i fmt` runs in a TTY with no positional arguments
- **THEN** the primary config and every file reachable via transitive `(load …)` is formatted in place
- **AND** read-only files in the graph are skipped with stderr warnings

### Requirement: Stdin filter mode

`may-i fmt` SHALL operate as a stdin → stdout filter when invoked with no positional arguments and stdin connected to a non-terminal source, OR when invoked with `-` as the sole positional argument.

In stdin filter mode:

- The command SHALL read stdin to completion, parse, canonicalise, render, and write the result to stdout.
- The command SHALL NOT write to any file.
- A trailing newline SHALL be present in the output if and only if the input ended with a newline.

Mixing `-` with file paths (e.g., `may-i fmt - other.lisp`) SHALL be rejected at argument parsing with an error.

#### Scenario: Piped stdin produces stdout output

- **WHEN** `cat foo.lisp | may-i fmt`
- **THEN** stdin is read, formatted, written to stdout
- **AND** no file on disk is modified
- **AND** the command exits `0` on successful format

#### Scenario: Explicit dash reads stdin

- **WHEN** `may-i fmt -` runs with stdin piped
- **THEN** behaviour matches the implicit-pipe case

#### Scenario: Mixed dash and file paths rejected

- **WHEN** `may-i fmt - other.lisp` is invoked
- **THEN** the command exits `2` with a stderr message rejecting the mixed mode

### Requirement: Check mode signals via exit code only

When `--check` is passed, `may-i fmt` SHALL determine whether each input is already canonically formatted without writing to any file or to stdout. The command SHALL exit:

- `0` if every input matches its canonical form
- `1` if at least one input would change
- `2` if any input fails to parse, or another I/O / config error occurs

Stdout SHALL remain empty in `--check` mode. Stderr MAY carry warnings (legacy syntax, read-only file) and error pointers.

#### Scenario: Already-canonical input exits zero

- **WHEN** `may-i fmt --check foo.lisp` runs against a file already in canonical form
- **THEN** exit code is `0`
- **AND** stdout is empty

#### Scenario: Would-change input exits one

- **WHEN** `may-i fmt --check foo.lisp` runs against a file that would be reformatted
- **THEN** exit code is `1`
- **AND** stdout is empty

#### Scenario: Parse error in check mode exits two

- **WHEN** `may-i fmt --check foo.lisp` runs against a file with a syntax error
- **THEN** exit code is `2`
- **AND** stderr names the file with the error location

#### Scenario: Stdin in check mode

- **WHEN** `cat foo.lisp | may-i fmt --check`
- **THEN** stdin is read and formatted in memory
- **AND** exit code is `0` if input matches canonical form, `1` otherwise
- **AND** stdout is empty

#### Scenario: Multi-file check exit code is highest severity

- **WHEN** `may-i fmt --check a.lisp b.lisp c.lisp` runs and `a.lisp` is canonical, `b.lisp` would change, `c.lisp` has a parse error
- **THEN** exit code is `2`

### Requirement: Legacy syntax warning, no automatic rewrite

When the input contains forms the strict canonical loader rejects (e.g., `(effect :allow)`, `(may-i *)`, plist-form `define-arg-style` or `check` body), `may-i fmt` SHALL:

- Pretty-print the CST as-is. Whitespace is canonicalised; legacy forms are preserved verbatim. No semantic rewrites are applied.
- Emit a stderr warning naming the source (file path or `<stdin>`) and suggesting `may-i migrate`.
- Continue with the normal exit code logic.

`may-i fmt` SHALL NOT silently apply migration rewrites. Migration is the explicit, user-invoked path.

#### Scenario: File with legacy syntax formatted with warning

- **WHEN** `may-i fmt foo.lisp` runs against a file containing `(effect :allow)`
- **THEN** the file is overwritten with whitespace-canonical output preserving the legacy form
- **AND** stderr emits a warning naming `foo.lisp` and suggesting `may-i migrate`
- **AND** the command exits `0`

#### Scenario: Stdin with legacy syntax formatted with warning

- **WHEN** stdin contains legacy syntax piped to `may-i fmt`
- **THEN** stdout receives the formatted output preserving the legacy form
- **AND** stderr emits a warning citing `<stdin>`

#### Scenario: Legacy syntax in check mode flags would-change

- **WHEN** `may-i fmt --check foo.lisp` runs against a legacy file whose whitespace is non-canonical
- **THEN** exit code is `1`
- **AND** stderr emits the legacy-syntax warning
- **AND** stdout is empty
