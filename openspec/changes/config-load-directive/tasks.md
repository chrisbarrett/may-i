## 1. Dependencies

- [x] 1.1 Add `glob` crate to `crates/config/Cargo.toml` dependencies

## 2. Load form validation

- [x] 2.1 Add `load` to the known top-level form tags in `config.rs` — emit an
  error if it reaches the parser ("load forms should be resolved before
  parsing"), as a safety net
- [x] 2.2 Write a helper `parse_load_arg` in `io.rs` that extracts and
  validates the string argument from a `(load ...)` sexpr (exactly one arg,
  must be a string)

## 3. Core expansion logic

- [x] 3.1 Implement `expand_loads` in `io.rs`: given a list of sexprs and the
  containing file's directory, walk the list and replace each `(load ...)`
  form with the sexprs from the referenced file(s)
- [x] 3.2 Implement glob expansion within `expand_loads`: resolve the pattern
  relative to the containing directory, sort matches lexically, warn to
  stderr on zero matches
- [x] 3.3 Implement cycle detection: thread a `HashSet<PathBuf>` of canonical
  paths through expansion; error with a descriptive cycle message on revisit
- [x] 3.4 Make expansion recursive: loaded files' sexprs are themselves passed
  through `expand_loads` before splicing

## 4. Per-file loading and migration

- [x] 4.1 Extract a `load_file_sexprs` helper that reads a file, parses to
  sexprs, and attempts migration if canonical parsing fails — returning
  `Vec<Sexpr>` (reusing the existing migration logic from `load`/
  `try_migrate_and_parse`)
- [x] 4.2 Wire `expand_loads` into the `load()` function: after parsing the
  root file to sexprs, call `expand_loads` before handing to
  `parse_config_from_sexprs`

## 5. Error reporting

- [x] 5.1 Ensure errors from loaded files include the source filename in the
  error message (verify `ConfigError::from_raw` filename propagation works
  through the expansion path)
- [x] 5.2 Report file-not-found as a clear error for literal (non-glob) paths

## 6. Tests

- [x] 6.1 Unit test: `(load "file.lisp")` with a single file splices forms
  correctly
- [x] 6.2 Unit test: glob pattern loads multiple files in lexical order
- [x] 6.3 Unit test: glob matching zero files produces a warning, not an error
- [x] 6.4 Unit test: paths resolve relative to containing file, including nested
  loads
- [x] 6.5 Unit test: circular load is detected and produces a clear error
- [x] 6.6 Unit test: self-referential load is detected
- [x] 6.7 Unit test: loaded file in legacy syntax is transparently migrated
- [x] 6.8 Unit test: missing file (non-glob) produces a file-not-found error
- [x] 6.9 Unit test: `(load)`, `(load "a" "b")`, `(load foo)` all produce
  validation errors
- [x] 6.10 Integration test: multi-file config produces identical `Config` to
  equivalent single-file config
