## Why

The migration system transparently rewrites v1 configs to v2. Getting this wrong silently breaks users' security policies. While individual rewrite rules have good unit tests, **no test verifies evaluation equivalence for compound v1 forms** — a rule with `(command ...)` + `(context ...)` + `(args ...)` passes through 4-5 rewrite rules with no test checking the composed result produces the same security decisions.

Additionally, several real-world v1 patterns from the user's config (wrapper forms, `has` with complex value patterns, command-level `or`/`regex`) lack migration test coverage.

## What Changes

### End-to-end evaluation equivalence tests
- Compound rules (command + context + args combined)
- Compound context with nested `has` key-value patterns
- Multi-clause `cond` inside `args`
- Named predicate references via `defcontext`

### Wrapper migration tests (from real config patterns)
- `timeout` with positional regex + bare capture
- `mise` with positional + flag + `--` separator + capture
- `nix` with positional `or` + flag with named option + capture
- `nix-shell` with flag-only (no positional) + capture
- `bash` with single-char flag + capture

### `has` → `fact?` with complex values
- Key with regex value pattern
- Key with wildcard value
- Key with `or` value pattern
- Key with compound value pattern

### Command patterns inside `(command ...)`
- `(command (or "rm" "rmdir"))` — or pattern
- `(command (regex "^git-"))` — regex with exact output verification
- `(command (or "cat" "head" "tail"))` — multi-element or

### Comment/trivia preservation
- Comments between top-level forms
- Inline comments inside wrapper forms
- Multi-line comment blocks above rules
- Trailing comments on closing parens

### Mixed v1/v2 configs
- File with some rules already migrated, some not — only v1 forms should change
- Idempotency on already-migrated real config

### New proptest generators
- `any_v1_rule_with_context` — `(rule (command CMD) (context PRED) (effect E))`
- `any_v1_rule_with_args` — `(rule (command CMD) (args MATCHER) (effect E))`
- `any_v1_compound_rule` — all three combined
- `any_v1_wrapper` — generates wrapper forms with random patterns
- `any_v1_config` — full v1 configs mixing all form types
- Eval-equivalence property for each generator

## Capabilities

### New Capabilities

- `migration-eval-equivalence`: Property and regression tests ensuring v1→v2 migration preserves evaluation semantics

### Modified Capabilities

- `transparent-config-migration`: Extended test coverage for compound forms and real-world patterns
- `migration-property-tests`: New generators for compound v1 forms

## Impact

- `crates/config/src/migrate/` — new test modules and proptest generators
- `crates/config/src/migrate/property_tests.rs` — new generators and properties
- Critical for user-facing compatibility guarantee
