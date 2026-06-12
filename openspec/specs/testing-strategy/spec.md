---
audience: contributor
bucket: testing
---
# testing-strategy Specification

## Purpose

Contributor-only. Project-wide testing strategy: property-tests-first, the classes of invariant those properties must cover, and when targeted unit tests are an acceptable fallback for hard-to-hit branches. Also covers shared integration-test infrastructure (`tests/common/mod.rs`, thread-safe env-mutation contract, deterministic error messages, cwd-isolation for spawned `may-i` processes, env-lock contract for parallel tests) and the **oracle-trace snapshot harness** (V1 fixture loaded via transparent migration, byte-for-byte comparison of stripped and raw-coloured trace output against checked-in snapshots, pinned 80-column geometry, config-path normalisation).

## Requirements

### Requirement: Prefer property tests

New tests SHALL prefer property-based testing with proptest and Arbitrary implementations on core AST types. Targeted unit tests SHALL be used as a fallback for hard-to-hit branches or specific regression cases.

#### Scenario: Property test chosen by default

- **WHEN** a new test is being authored for a function over an AST type
- **THEN** the author SHALL write a proptest first, falling back to a unit test only for branches the proptest cannot reach

### Requirement: Verification tiers are explicit

The repository SHALL define four verification tiers, each with a
specific cadence and scope:

- **pre-commit**: fast, scoped to affected crates. Includes `cargo
  fmt --check`, affected `cargo clippy`, affected `cargo test`, and
  OpenSpec validation. No separate `cargo build` step: clippy runs
  the same compiler checks, and test forces full codegen.
- **pre-push**: full-workspace, no instrumentation. Includes
  `cargo clippy --workspace --all-targets -- -D warnings` and
  `cargo test --workspace`.
- **release**: instrumentation and fuzz on top of CI. Runs only via
  `scripts/release.sh`. Includes a CI-green gate on HEAD (which
  proves fmt, clippy, and tests passed in CI for the same commit),
  `cargo tarpaulin` (with `run-types = ["Lib", "Tests", "Doctests"]`),
  `cargo +nightly fuzz run fuzz_evaluator -- -max_total_time=60`, and
  `nix build`.
- **nightly**: slow, non-blocking. Runs `cargo tarpaulin`, a longer
  fuzz pass (`-max_total_time=600`), and `nix flake check` (package
  build, clippy, fmt, nextest, cargo-audit against a freshly updated
  advisory database) against `main` on a scheduled GitHub Actions
  workflow.

#### Scenario: Coverage gate runs at release tier only

- **WHEN** `cargo tarpaulin` is configured as a verification step
- **THEN** it SHALL appear in the release tier (`scripts/release.sh`)
  and the nightly tier, but NOT in the pre-push tier

#### Scenario: Fuzz pass runs at release and nightly tiers

- **WHEN** the fuzz target is invoked in CI or hooks
- **THEN** it SHALL only appear in the release tier (60s budget) and
  the nightly tier (600s budget)

#### Scenario: Tarpaulin run-types cover all test kinds at release tier

- **WHEN** `cargo tarpaulin` runs as part of release verification
- **THEN** its `run-types` configuration SHALL include `Lib`,
  `Tests`, and `Doctests`

### Requirement: All CLI subcommands have integration tests
Every user-facing CLI subcommand SHALL have at least one happy-path and one error-path integration test that invokes the may-i binary as a subprocess.

#### Scenario: check subcommand happy path
- **WHEN** `may-i check` is run with a valid config
- **THEN** the exit code SHALL be 0 and output SHALL list check results

#### Scenario: check subcommand with failures
- **WHEN** `may-i check` is run with a config containing failing checks
- **THEN** the exit code SHALL be non-zero

#### Scenario: parse subcommand
- **WHEN** `may-i parse` is run with a valid shell command
- **THEN** the exit code SHALL be 0 and output SHALL show parsed structure

#### Scenario: migrate subcommand as subprocess
- **WHEN** `may-i migrate` is run with a v1 config file
- **THEN** the output SHALL contain valid v2 syntax

#### Scenario: eval with --fact flags
- **WHEN** `may-i eval` is run with --fact flags
- **THEN** the evaluation SHALL use the provided facts in decision-making

#### Scenario: missing config file
- **WHEN** MAYI_CONFIG points to a nonexistent file
- **THEN** the exit code SHALL be non-zero with a descriptive error

#### Scenario: hook with --json output
- **WHEN** the hook is invoked with --json flag
- **THEN** the output SHALL be valid JSON

### Requirement: Key invariants are verified

Property tests SHALL cover these invariant classes:

- **No panics**: Evaluation functions never panic on valid inputs
- **Boolean algebra**: And/Or/Not obey standard laws including De Morgan's
- **Determinism**: Same input always produces same output
- **Recursion limits**: Depth limits are respected and produce Ask
- **Type safety**: Predicates return Match/NoMatch, effects return Decision/Nil

#### Scenario: All invariant classes have a proptest

- **WHEN** the test suite runs
- **THEN** at least one proptest SHALL exist for each invariant class listed above

### Requirement: Arbitrary implementations cover AST types

Core AST types (Effect, Predicate, ArgPattern, CommandPattern, Expr, FactQuery, FactPattern, ContextFacts) SHALL implement proptest's Arbitrary trait for use in property tests.

#### Scenario: Arbitrary derives are available

- **WHEN** a proptest names one of the listed AST types as a generator input
- **THEN** the type SHALL provide an `Arbitrary` impl producing well-formed values

### Requirement: Shell parser does not panic on arbitrary input

`parser::parse()` SHALL NOT panic when given any arbitrary string input.

#### Scenario: Arbitrary string fed to the parser

- **WHEN** a proptest passes a generated string to `parser::parse()`
- **THEN** the call SHALL return either Ok or a structured Err, never panic

### Requirement: Config parsers do not panic on generated CST

The config parsers (effect, predicate, command, rule) SHALL NOT panic when given CST nodes generated by existing test generators.

#### Scenario: Generated CST node parses or errors

- **WHEN** a proptest passes a generated CST node to any config parser
- **THEN** the parser SHALL return a value or a structured error without panicking

### Requirement: validate_and_resolve does not panic

`validate_and_resolve()` SHALL NOT panic on arbitrary (rules, defines) input.

#### Scenario: Arbitrary rules and defines

- **WHEN** a proptest passes generated rules and defines to `validate_and_resolve()`
- **THEN** the call SHALL return Ok or a structured Err, never panic

### Requirement: Doc functor laws hold

`Doc::map` SHALL satisfy the functor identity and composition laws.

#### Scenario: Identity law

- **WHEN** a proptest applies `Doc::map(id)` to an arbitrary doc
- **THEN** the result SHALL equal the original doc

#### Scenario: Composition law

- **WHEN** a proptest applies `Doc::map(f).map(g)` and `Doc::map(g . f)` to the same arbitrary doc
- **THEN** both results SHALL be equal

### Requirement: Pretty-printer idempotency

Pretty-printing a doc, parsing it back, and pretty-printing again SHALL produce the same output.

#### Scenario: Roundtrip stabilises after one pass

- **WHEN** a proptest pretty-prints a doc, parses, and pretty-prints again
- **THEN** the second print SHALL equal the first

### Requirement: Pretty-printer width monotonicity

Narrower widths SHALL produce at least as many lines as wider widths.

#### Scenario: Reducing width does not reduce line count

- **WHEN** a proptest renders the same doc at width `w1 < w2`
- **THEN** the line count at `w1` SHALL be greater than or equal to the line count at `w2`

### Requirement: Shell segment inverse

Concatenating all segments of a parsed shell string SHALL reproduce the original input.

#### Scenario: Segment join equals input

- **WHEN** a proptest splits a shell string into segments and concatenates them
- **THEN** the result SHALL equal the original string

### Requirement: Layout write_layout does not panic

`write_layout()` SHALL NOT panic on arbitrary Layout trees and terminal widths.

#### Scenario: Arbitrary layout and width

- **WHEN** a proptest passes a generated layout tree and width to `write_layout()`
- **THEN** the call SHALL complete without panicking

### Requirement: Transform functions are idempotent

`truncate_matched_anywhere` and `dim_unevaluated` SHALL be idempotent.

#### Scenario: Second application is a no-op

- **WHEN** a proptest applies either transform twice to an arbitrary input
- **THEN** the result after one application SHALL equal the result after two

### Requirement: ContextFacts merge is commutative

`ContextFacts::merge` SHALL be commutative: `a.merge(b) == b.merge(a)`.

#### Scenario: Merge order does not matter

- **WHEN** a proptest computes `a.merge(b)` and `b.merge(a)` for arbitrary `ContextFacts` `a` and `b`
- **THEN** the two results SHALL be equal

### Requirement: Resolution completeness

After successful `validate_and_resolve`, no `Predicate::Named` variants SHALL remain in the resolved config.

#### Scenario: No Named variants survive resolution

- **WHEN** a proptest resolves an arbitrary valid config
- **THEN** no `Predicate::Named` SHALL appear anywhere in the resolved output

### Requirement: Config parse roundtrip property

Parsing a valid config, serializing it, and parsing again SHALL produce an equivalent result.

#### Scenario: Roundtrip preserves config

- **WHEN** a proptest parses an arbitrary valid config, serialises it, and parses again
- **THEN** the second parse result SHALL equal the first

### Requirement: CST pretty_serialize roundtrip property

Pretty-printing a CST and re-parsing it SHALL preserve structure.

#### Scenario: CST roundtrip preserves structure

- **WHEN** a proptest pretty-prints a CST and re-parses the output
- **THEN** the re-parsed CST SHALL have the same structure as the original

### Requirement: Positional backtracking correctness property

Matched args concatenated with unconsumed args SHALL equal the original args.

#### Scenario: Match plus remainder equals input

- **WHEN** a proptest evaluates a positional matcher against arbitrary args
- **THEN** the matched prefix concatenated with the unconsumed suffix SHALL equal the original args

### Requirement: Cycle detection soundness property

Randomly generated acyclic define graphs SHALL pass validation; graphs with cycles SHALL be rejected.

#### Scenario: Acyclic graph passes

- **WHEN** a proptest generates an acyclic define graph and runs validation
- **THEN** validation SHALL succeed

#### Scenario: Cyclic graph fails

- **WHEN** a proptest generates a define graph containing a cycle and runs validation
- **THEN** validation SHALL fail with a cycle-detection error

### Requirement: Expression parser roundtrip property

Expressions SHALL roundtrip through serialization and parsing.

#### Scenario: Serialise then parse equals input

- **WHEN** a proptest serialises an arbitrary expression and parses the result
- **THEN** the parsed expression SHALL equal the original

### Requirement: render_annotated_rule never panics

The rendering pipeline SHALL NOT panic on arbitrary inputs.

#### Scenario: Arbitrary inputs render or error

- **WHEN** a proptest passes arbitrary inputs to `render_annotated_rule`
- **THEN** the call SHALL complete without panicking

### Requirement: Migration preserves semantics with defines

Migration SHALL preserve evaluation semantics for configs that include `define` predicates.

#### Scenario: Defines roundtrip through migration

- **WHEN** a proptest migrates a v1 config containing `define` predicates
- **THEN** the migrated v2 config SHALL produce the same decision as the v1 original for every sampled input

### Requirement: Integration test loads V1 fixture and evaluates commands

The test harness SHALL load `tests/fixtures/v1/config.lisp` (V1 syntax) via
`may_i_config::load`, which transparently migrates it. For each case in
`tests/fixtures/v1/cases.toml`, it SHALL evaluate the command with the specified
facts using the full eval pipeline (TracingFold + trace rendering).

#### Scenario: Config loads via transparent migration
- **WHEN** the test calls `may_i_config::load` with the V1 fixture path
- **THEN** the config loads successfully with transparent V1-to-V2 migration

#### Scenario: Each test case evaluates without error
- **WHEN** a test case specifies command `"git status"` with no facts
- **THEN** evaluation completes and produces a trace and result

#### Scenario: Test case with runtime facts
- **WHEN** a test case specifies facts `[":opencode/agent=build"]`
- **THEN** those facts are parsed and passed to the eval context

### Requirement: Stripped output matches oracle snapshots

For each test case, the trace output with ANSI codes stripped SHALL match the
corresponding `tests/snapshots/oracle_v1/{name}.txt` file byte-for-byte, after
config path normalisation.

#### Scenario: Structural match for simple allow
- **WHEN** evaluating `"cat foo"` against the V1 fixture
- **THEN** the stripped output matches `cat_file.txt`

#### Scenario: Structural match for multi-rule trace
- **WHEN** evaluating `"git status"` against the V1 fixture (no facts)
- **THEN** the stripped output matches `git_status.txt`, which includes 4 rule
  traces (lines 43, 47, 52, 60) with non-matching positional annotations

#### Scenario: Structural match for context-dependent rule
- **WHEN** evaluating `"git checkout -- main.ts"` with fact `:opencode/agent=plan`
- **THEN** the stripped output matches `git_checkout_file_plan.txt`, showing the
  plan-mode rule matching with positional annotations

#### Scenario: Structural match for default ask
- **WHEN** evaluating `"unknown-cmd arg"` against the V1 fixture
- **THEN** the stripped output matches `unknown_cmd.txt`, showing "No matching rule"

### Requirement: Raw ANSI output matches oracle snapshots

For each test case, the trace output with ANSI colour codes SHALL match the
corresponding `tests/snapshots/oracle_v1/{name}.raw` file byte-for-byte, after
config path normalisation.

#### Scenario: Colour codes for deny decision
- **WHEN** evaluating `"rm -rf /"` against the V1 fixture
- **THEN** the raw output matches `rm_rf_root.raw`, including red colouring on
  `:deny` and the result command text

#### Scenario: Colour codes for allow decision
- **WHEN** evaluating `"git status"` against the V1 fixture
- **THEN** the raw output matches `git_status.raw`, including green colouring on
  `:allow` and green bold on "yes" annotations

### Requirement: Config path is normalised before comparison

The output line `config: <path>` SHALL be replaced with a stable placeholder
before comparing against snapshots. The same normalisation SHALL be applied to
the oracle snapshot content.

#### Scenario: Path differs between machines
- **WHEN** the dev build produces `config: /tmp/test123/config.lisp`
- **AND** the oracle snapshot contains `config: ~/src/.../config.lisp`
- **THEN** both are normalised to `config: <config-path>` before comparison

### Requirement: Terminal width pinned at 80 columns

The test SHALL set `COLUMNS=80` before rendering so the two-column layout is
deterministic and matches the oracle capture environment.

#### Scenario: Deterministic layout
- **WHEN** the test renders trace output
- **THEN** `COLUMNS` is set to `"80"` and layout uses 80-column geometry

### Requirement: Colour output forced in test environment

The test SHALL force colour output (via `colored::control::set_override(true)`)
to match the oracle capture which used `CLICOLOR_FORCE=1`.

#### Scenario: Colour enabled despite non-TTY
- **WHEN** the test captures output to a string buffer
- **THEN** ANSI escape sequences are present in the raw output

### Requirement: Shared integration test helpers
Integration test files SHALL share common helper functions via a `tests/common/mod.rs` module rather than duplicating them.

#### Scenario: Helper functions used across test files
- **WHEN** multiple integration test files need write_config or bash_payload helpers
- **THEN** they SHALL import from tests/common/mod.rs

### Requirement: Thread-safe environment variable tests
Tests that manipulate environment variables SHALL use thread-safe mechanisms (e.g., temp_env crate) rather than unsafe direct env::set_var calls.

#### Scenario: Config path tests run in parallel
- **WHEN** config path resolution tests run concurrently
- **THEN** they SHALL not interfere with each other's environment state

### Requirement: Valid git-repo fixtures for discovery tests
Test helpers that create a `.git` marker to exercise repository-root discovery SHALL write enough of a git repository (at minimum `.git/HEAD` and `.git/config`) for `git rev-parse --show-toplevel` to recognise the directory as a valid repo, rather than relying on `git`'s tolerance of an empty `.git/` directory.

#### Scenario: `init_git` produces a repo git accepts
- **WHEN** a test calls the local `init_git(path)` helper to set up a discovery fixture
- **THEN** running `git rev-parse --show-toplevel` from `path` SHALL return `path`, regardless of git version or filesystem timing

#### Scenario: Discovery does not fall through to an ancestor repo
- **WHEN** a tempdir created under `$TMPDIR` is initialised with `init_git` and `$TMPDIR` itself lives below another git repo
- **THEN** `discover_repo_root(tempdir)` SHALL return the tempdir, not the ancestor repo

### Requirement: Integration-test cwd isolation
Integration tests that spawn the `may-i` binary via `assert_cmd` SHALL set the child process's working directory to a location outside any git repository, so that repo-local config discovery does not run against the workspace.

#### Scenario: Spawned `may-i` does not discover workspace as repo root
- **WHEN** an integration test invokes the `may-i` binary without explicitly overriding `current_dir`
- **THEN** the child's cwd SHALL be a directory with no ancestor `.git`, `.hg`, or `.jj` marker, so `discover_repo_root` returns `None`

#### Scenario: Tests that need a specific cwd opt in
- **WHEN** an integration test asserts behaviour that depends on a specific repo-local discovery cwd
- **THEN** it SHALL explicitly call `.current_dir(...)` on the command, overriding the default isolation, AND the test SHALL document why

### Requirement: Deterministic validation error messages
Validation routines whose error messages name specific entities (e.g., the `a -> b` pair in a cyclic-define error) SHALL produce the same message bytes across runs given the same input, so that tests and snapshots remain stable.

#### Scenario: Cycle detection picks a stable starting node
- **WHEN** define-cycle detection runs over the same set of defines twice
- **THEN** the error message SHALL be byte-identical between runs, including the name pair shown in the message

#### Scenario: Multiple cycles report the same one each run
- **WHEN** the input contains more than one cyclic define group
- **THEN** the cycle reported in the error SHALL be selected deterministically (e.g., by sorted name), not by `HashMap` iteration order

### Requirement: Environment-mutation locking contract is documented
Process-global locks used to serialise environment-variable mutation across parallel tests SHALL carry a doc comment at the definition site stating that any test in the binary which mutates a process-global env var must acquire the same lock.

#### Scenario: ENV_LOCK has a contract comment
- **WHEN** a reader views the definition of a static `Mutex` used to guard env-var mutation in test code
- **THEN** a doc comment SHALL describe the requirement to share the lock and the consequences of unguarded mutation

#### Scenario: New env-mutating test takes the existing lock
- **WHEN** a future test in the same binary needs to call `unsafe { env::set_var(...) }`
- **THEN** it SHALL acquire the documented shared lock rather than introduce a parallel one

### Requirement: Interactive prompting flows are unit-tested through a fake prompt

Interactive prompting flows (the per-rule trust review loop, the integrity-repair loop, and any future loop following the same shape) SHALL be exercised by unit tests that drive the loop through a fake prompting impl, not solely by end-to-end TTY-driven integration tests. The fake SHALL record output and replay a scripted sequence of user answers, so loop branches (per-entry decisions, quit short-circuit, non-interactive skip) can be asserted on without a real terminal or subprocess.

#### Scenario: Per-rule review loop has a unit test over a fake prompt

- **WHEN** the test suite runs
- **THEN** at least one unit test SHALL exist that exercises the per-rule review loop against a fake prompt impl, scripting a multi-rule scenario and asserting on the resulting trust-store mutations and review summary

#### Scenario: Integrity-repair loop has a unit test over a fake prompt

- **WHEN** the test suite runs
- **THEN** at least one unit test SHALL exist that exercises the integrity-repair loop against a fake prompt impl, covering both the interactive (re-approve / drop) branches and the non-interactive (advisory-only) branch

#### Scenario: Loop logic does not depend on TTY crates

- **WHEN** the module hosting the pure review or repair loop is scanned for direct imports
- **THEN** no direct dependency on `console`, `dialoguer`, or other TTY-driver crates SHALL appear in the loop module; those crates SHALL be confined to the terminal prompting impl
