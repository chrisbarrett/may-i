## Context

Config is currently a single file (`~/.config/may-i/config.lisp`). The loading
pipeline in `io.rs` reads one file, optionally migrates it, then hands the sexpr
forms to `parse_config_from_sexprs` in `config.rs`. The `Config` AST is flat:
vectors of rules, defines, checks, and security settings.

## Goals / Non-Goals

**Goals:**

- Users can split config into multiple files using `(load "<file-or-glob>")`
- Deterministic, predictable load order (lexical sort for globs)
- Good error messages that identify which file contains the error
- Recursive loads with cycle detection
- Each file migrates independently (legacy + v2 coexistence)

**Non-Goals:**

- Namespacing or scoping (loaded rules merge into one flat Config)
- Conditional loading (e.g. platform-specific includes)
- Directory-as-config (implicitly loading a directory without explicit `load`)

## Decisions

### 1. Expansion at the IO layer, not the config parser

`(load ...)` is resolved in `io.rs` after sexpr parsing but before
`parse_config_from_sexprs`. The config parser never sees `load` forms.

**Why:** The parser operates on `&[Sexpr]` with no I/O. Keeping it pure
preserves testability and separation of concerns. Migration already lives in IO.

**Alternative:** Handle `load` in `parse_config_from_sexprs`. Rejected because
it would require threading file I/O through a parser that is currently pure.

### 2. Glob via the `glob` crate

Add the `glob` crate as a dependency of `may-i-config`. Rust's `std` has no
glob support.

**Why:** `glob` is small, well-established, and has no transitive dependencies.
Patterns like `rules/*.lisp` are the primary use case.

**Alternative:** Manual directory listing + regex. More code, less standard, no
benefit.

### 3. Lexical sort order for glob results

Glob matches are sorted lexically (like `/etc/conf.d/`). Users control ordering
via filenames (e.g. `00-base.lisp`, `10-git.lisp`).

**Why:** Deterministic and familiar. Rule evaluation order matters (first match
wins), so predictable ordering is important.

### 4. Paths relative to the containing file

`(load "rules/*.lisp")` in `~/.config/may-i/config.lisp` resolves to
`~/.config/may-i/rules/*.lisp`.

**Why:** This is the universal convention (C `#include`, CSS `@import`, etc.).
Absolute paths also work as-is.

### 5. Cycle detection via canonical path set

Maintain a `HashSet<PathBuf>` of canonicalised paths on the load stack. Error
immediately on revisit with a message showing the cycle chain.

**Why:** Simple, correct, zero overhead for the common case (no cycles).

### 6. Per-file migration

Each loaded file independently attempts migration if canonical parsing fails,
exactly as `load()` does today. This allows a user to have some files in legacy
syntax and others in v2.

**Why:** Matches existing behaviour. No reason to restrict migration to the root
file only.

### 7. Error reporting with filename context

Errors from loaded files must include the originating filename. The existing
`ConfigError::from_raw` already accepts a filename string — this propagates
naturally as each file is loaded independently.

**Why:** Without this, a parse error in `rules/git.lisp` would be reported
without context about which file it came from.

## Risks / Trade-offs

- **[Risk] Non-existent glob matches silently produce zero forms** → Mitigate by
  emitting a warning to stderr when a glob pattern matches no files. Do not
  error, since an empty directory is a valid state.
- **[Risk] Deeply recursive loads** → The cycle detection set naturally bounds
  this. No artificial depth limit needed unless pathological configs emerge.
- **[Trade-off] No scoping** → All loaded rules merge into one flat list. This
  is simpler but means name collisions in `define` are possible across files.
  Accept this for now; scoping can be added later if needed.
