## ADDED Requirements

### Requirement: pp crate submodule structure

When `crates/pp/src/lib.rs` exceeds the file size limit, it SHALL be decomposed
into a submodule directory. `lib.rs` SHALL re-export all previously-public
symbols.

#### Scenario: pp lib.rs split into submodules

- **WHEN** `crates/pp/src/` is examined after restructuring
- **THEN** the directory contains `lib.rs`, `output.rs`, `render.rs`,
  `buffer.rs`, and `color.rs`
- **THEN** no production file exceeds 600 lines

#### Scenario: pp public API preserved

- **WHEN** `cargo check` is run on the full workspace after pp restructuring
- **THEN** compilation succeeds with no import-path errors
- **THEN** `may_i_pp::pretty`, `may_i_pp::pretty_into`, `may_i_pp::Format`,
  `may_i_pp::PrettyOutput`, and `may_i_pp::visible_len` resolve to the same
  types as before

#### Scenario: pp test modules extracted

- **WHEN** `crates/pp/src/` is examined
- **THEN** `#[cfg(test)]` blocks from the original `lib.rs` live in dedicated
  test files, not inline in production modules

### Requirement: eval submodule directory

When `crates/engine/src/eval.rs` exceeds the file size limit, it SHALL be
decomposed into an `eval/` directory. `eval/mod.rs` SHALL re-export all
previously-public symbols.

#### Scenario: eval.rs split into submodules

- **WHEN** `crates/engine/src/eval/` is examined after restructuring
- **THEN** the directory contains `mod.rs`, `context.rs`, `entry.rs`,
  `predicates.rs`, `positional.rs`, and `effects.rs`
- **THEN** no production file exceeds 600 lines

#### Scenario: eval public API preserved

- **WHEN** `cargo check` is run on the full workspace after eval restructuring
- **THEN** compilation succeeds with no import-path errors
- **THEN** `may_i_engine::evaluate`, `may_i_engine::evaluate_with_fold`,
  `may_i_engine::EvalContext`, and `may_i_engine::EvalError` resolve to the same
  types as before

#### Scenario: eval test modules extracted

- **WHEN** `crates/engine/src/eval/` is examined
- **THEN** `#[cfg(test)]` blocks from the original `eval.rs` live in dedicated
  test files under `eval/tests/`, not inline in production modules

### Requirement: test_generators test extraction

The test modules in `crates/engine/src/test_generators.rs` SHALL be extracted
into separate files, leaving only the proptest generator functions in
`test_generators.rs`.

#### Scenario: generators file reduced to generators only

- **WHEN** `crates/engine/src/test_generators.rs` is examined after restructuring
- **THEN** it contains only proptest strategy functions and `pub use` re-exports
- **THEN** it does not exceed 600 lines

#### Scenario: extracted test modules compile and pass

- **WHEN** `cargo test -p may-i-engine` is run after extraction
- **THEN** all property tests that previously lived in `test_generators.rs` pass
