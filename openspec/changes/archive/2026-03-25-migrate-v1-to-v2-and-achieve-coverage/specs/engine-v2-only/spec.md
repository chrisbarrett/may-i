## ADDED Requirements

### Requirement: Single v2 evaluator implementation
The engine crate SHALL have only v2 evaluation logic, with all v1 code removed.

#### Scenario: No v1 code in engine
- **WHEN** the `crates/engine/src/` directory is examined
- **THEN** no v1-specific modules or files exist
- **AND** `lib_v1.rs` does not exist

#### Scenario: No v1 imports
- **WHEN** `crates/engine/src/lib.rs` is examined
- **THEN** no imports reference v1 modules
- **AND** all exports are v2-compatible

### Requirement: v2 module structure
The v2 evaluator SHALL be organized in a clear module structure.

#### Scenario: v2 module exports
- **WHEN** `pub use v2::*` is used
- **THEN** all public v2 types are accessible
- **AND** no v1 types are exposed

#### Scenario: v2 evaluation entry point
- **WHEN** `evaluate()` or `evaluate_with_context()` is called
- **THEN** v2 evaluation logic is executed
- **AND** no v1 fallback paths exist

### Requirement: Backward compatible public API
The public API SHALL remain compatible with v2 consumers.

#### Scenario: Existing v2 API unchanged
- **WHEN** existing v2 code uses the public API
- **THEN** it compiles without changes
- **AND** behavior remains identical

#### Scenario: Config compatibility
- **WHEN** v2 configs are loaded
- **THEN** they work without modification
