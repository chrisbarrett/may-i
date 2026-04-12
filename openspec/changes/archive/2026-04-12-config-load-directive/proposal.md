## Why

Config files grow unwieldy as users add more rules. The user's config is already
1100+ lines. There is no way to split it into logical groups (e.g. git rules,
docker rules, SSH rules) without external tooling.

## What Changes

- Add a `(load "<file-or-glob>")` top-level special form that splices the
  contents of other config files into the current file.
- Glob patterns expand with lexical (conf.d) ordering for deterministic
  evaluation.
- Paths resolve relative to the file containing the `(load ...)` form.
- Loads are recursive: a loaded file may itself contain `(load ...)` forms.
- Circular loads are detected and reported as errors.
- Each loaded file is independently eligible for legacy migration.
- The `Config` AST type is unchanged; downstream code is unaware of the split.

## Capabilities

### New Capabilities

- `load-directive`: Parsing, path resolution, glob expansion, cycle detection,
  and recursive splicing of `(load ...)` forms at the IO layer.

### Modified Capabilities

(none)

## Impact

- `crates/config/src/io.rs`: Primary change site. Load expansion happens after
  sexpr parsing and before `parse_config_from_sexprs`.
- `crates/config/src/config.rs`: The `parse_config_from_sexprs` match on
  top-level form tags needs a branch (or pre-filter) so `load` is never seen by
  the config parser — it is fully resolved upstream.
- Error reporting: `ConfigError` must carry the originating filename so that
  parse errors in loaded files point to the correct file.
- No new dependencies expected (`glob` is already available via `std`; if not,
  the `glob` crate is tiny).
