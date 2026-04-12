## ADDED Requirements

### Requirement: Load directive parses as a top-level form

The system SHALL recognise `(load "<path-or-glob>")` as a valid top-level form.
The form MUST contain exactly one string argument. The argument is a file path or
glob pattern.

#### Scenario: Simple file path

- **WHEN** config contains `(load "git.lisp")`
- **THEN** the system reads and parses `git.lisp` relative to the containing
  file's directory, and splices its top-level forms in place of the `load` form

#### Scenario: Missing argument

- **WHEN** config contains `(load)`
- **THEN** the system reports an error indicating `load` requires a path argument

#### Scenario: Too many arguments

- **WHEN** config contains `(load "a.lisp" "b.lisp")`
- **THEN** the system reports an error indicating `load` takes exactly one
  argument

#### Scenario: Non-string argument

- **WHEN** config contains `(load foo)`
- **THEN** the system reports an error indicating the argument must be a string

### Requirement: Glob expansion with lexical ordering

The system SHALL expand glob patterns in `load` arguments using standard glob
syntax. Matching files SHALL be loaded in lexical (byte) sort order.

#### Scenario: Glob matches multiple files

- **WHEN** config contains `(load "rules/*.lisp")` and the directory contains
  `rules/docker.lisp`, `rules/git.lisp`, `rules/ssh.lisp`
- **THEN** the system loads them in order: `docker.lisp`, `git.lisp`,
  `ssh.lisp`, splicing all their forms in place of the single `load` form

#### Scenario: Glob matches no files

- **WHEN** config contains `(load "rules/*.lisp")` and no files match
- **THEN** the system emits a warning to stderr and continues with zero forms
  spliced (no error)

### Requirement: Path resolution relative to containing file

Paths in `load` forms SHALL resolve relative to the directory of the file
containing the `load` form. Absolute paths SHALL be used as-is.

#### Scenario: Relative path

- **WHEN** `~/.config/may-i/config.lisp` contains `(load "rules/git.lisp")`
- **THEN** the system reads `~/.config/may-i/rules/git.lisp`

#### Scenario: Absolute path

- **WHEN** config contains `(load "/etc/may-i/shared.lisp")`
- **THEN** the system reads `/etc/may-i/shared.lisp`

#### Scenario: Nested relative path

- **WHEN** `~/.config/may-i/rules/git.lisp` (itself loaded) contains
  `(load "git-extras.lisp")`
- **THEN** the system reads `~/.config/may-i/rules/git-extras.lisp`

### Requirement: Recursive load support

Loaded files SHALL themselves be eligible to contain `(load ...)` forms, which
are expanded recursively.

#### Scenario: Two-level recursion

- **WHEN** `config.lisp` loads `rules/main.lisp`, which loads
  `rules/sub/extra.lisp`
- **THEN** all three files' forms are merged into the final Config

### Requirement: Circular load detection

The system SHALL detect circular loads and report an error. Detection is based on
canonical (resolved) file paths.

#### Scenario: Direct cycle

- **WHEN** `a.lisp` contains `(load "b.lisp")` and `b.lisp` contains
  `(load "a.lisp")`
- **THEN** the system reports a circular load error naming the cycle

#### Scenario: Self-referential load

- **WHEN** `config.lisp` contains `(load "config.lisp")`
- **THEN** the system reports a circular load error

### Requirement: Per-file legacy migration

Each loaded file SHALL independently attempt legacy migration if canonical
parsing fails, exactly as the root config file does today.

#### Scenario: Mixed legacy and v2 files

- **WHEN** `config.lisp` (v2 syntax) loads `legacy.lisp` (v1 syntax)
- **THEN** both files parse successfully; legacy.lisp is transparently migrated

### Requirement: Error reporting identifies source file

Parse errors in loaded files SHALL include the filename of the file containing
the error.

#### Scenario: Error in loaded file

- **WHEN** `config.lisp` loads `rules/bad.lisp` and `bad.lisp` contains invalid
  syntax
- **THEN** the error message includes `rules/bad.lisp` (or its full path) so
  the user knows which file to fix

### Requirement: File not found is an error

If a `load` argument is a literal path (not a glob) and the file does not exist,
the system SHALL report an error.

#### Scenario: Missing file

- **WHEN** config contains `(load "nonexistent.lisp")`
- **THEN** the system reports a file-not-found error naming the path

### Requirement: Load is transparent to downstream

The `Config` AST type SHALL not change. Code consuming `Config` (evaluator,
checker, etc.) SHALL be unaware whether the config was loaded from one file or
many.

#### Scenario: Equivalent single-file and multi-file configs

- **WHEN** a single-file config and a multi-file config (using `load`) contain
  the same rules in the same order
- **THEN** both produce identical `Config` values
