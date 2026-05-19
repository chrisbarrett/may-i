## MODIFIED Requirements

### Requirement: Pipeline owns per-invocation state

The system SHALL provide a `CommandPipeline` (working name) contributor-facing type in the binary crate that owns the per-invocation state shared by every evaluation subcommand: the `may_i_config::LoadResult` (loaded config + pre-migration forms + config path), the detected `output::Terminal`, the json-output flag, and an `InvocationTrust` collaborator (see `trust-gate`) that owns the per-invocation Trust concern. The pipeline SHALL NOT hold trust-store loaders, trust catalog state, trust-load-attempted flags, prelude-rendered flags, or trust-warning-rendered flags directly — those move into `InvocationTrust`. CLI subcommands SHALL NOT individually call `may_i_config::load_and_resolve` or `output::Terminal::detect`; both happen during pipeline construction.

#### Scenario: Pipeline constructed once per invocation

- **WHEN** the binary's `main` enters any evaluation subcommand (`eval`, `check`, the default hook entry)
- **THEN** exactly one `CommandPipeline` is constructed for that invocation and passed to the subcommand
- **AND** `may_i_config::load_and_resolve` and `output::Terminal::detect` are each called exactly once

#### Scenario: Subcommands borrow from the pipeline

- **WHEN** a subcommand needs the loaded config, the terminal, the config path, or the json flag
- **THEN** it accesses them through `&CommandPipeline` accessors, not by re-loading

#### Scenario: Pipeline holds exactly one InvocationTrust

- **WHEN** scanning the `CommandPipeline` struct definition in `src/pipeline.rs`
- **THEN** it contains exactly one field of type `InvocationTrust`
- **AND** it contains no field of type `Option<TrustCatalogState>`, `Box<dyn Fn() -> Option<TrustStoreState>>`, or named `catalog_attempted` / `prelude_rendered` / `trust_warning_rendered`

### Requirement: Pipeline runs the prelude exactly once

The pipeline SHALL expose a single `render_prelude_advisories` operation that delegates to `InvocationTrust::render_prelude`. The delegation SHALL render the migration note (when the loaded config was transparently migrated) followed by trust-store integrity advisories, to the pipeline's stderr. The operation SHALL be idempotent — calling it more than once in an invocation has no additional effect. The idempotency state lives on `InvocationTrust`, not on `CommandPipeline`.

#### Scenario: Prelude renders migration note then integrity advisory

- **WHEN** a subcommand calls `render_prelude_advisories` in text mode and both the migration note and an integrity advisory apply
- **THEN** the migration note is rendered first, then the integrity advisory, to stderr — matching today's ordering in `cmd_eval` and `cmd_check`

#### Scenario: JSON mode skips prelude advisories

- **WHEN** the pipeline's `json` flag is set
- **THEN** `render_prelude_advisories` is a no-op (matching today's JSON-mode behaviour)

#### Scenario: Idempotent on repeated calls

- **WHEN** `render_prelude_advisories` is called twice in one invocation
- **THEN** the second call writes nothing to stderr
- **AND** the idempotency is enforced by state inside `InvocationTrust`

### Requirement: Single trust-store load is observable

The pipeline SHALL ensure the trust store is loaded at most once per invocation, regardless of how many times `consult_trust` is called or how many advisories are rendered. The single-load invariant is enforced inside `InvocationTrust`. A test fake injected via `InvocationTrust::with_loader` SHALL be able to count loader calls and assert the invariant; the pipeline SHALL expose a `CommandPipeline::with_trust(loaded, json, InvocationTrust)` constructor variant that accepts a pre-built `InvocationTrust` for tests.

#### Scenario: One invocation, one store load

- **WHEN** a test wraps the store loader behind a counter, builds an `InvocationTrust::with_loader(json, counting_loader)`, passes it into `CommandPipeline::with_trust`, and runs an evaluation flow that triggers both prelude advisories and gate consultation
- **THEN** the loader counter reads exactly 1 at the end of the invocation

#### Scenario: Test seam lives on InvocationTrust

- **WHEN** scanning `src/pipeline.rs` for a `with_store_loader` constructor
- **THEN** no such constructor exists; the only test seam for injecting a custom loader is `InvocationTrust::with_loader`, with the pipeline accepting the resulting `InvocationTrust` via `CommandPipeline::with_trust`
