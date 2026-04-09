## 1. Add #[non_exhaustive] to extensible enums

- [x] 1.1 Add #[non_exhaustive] to Effect enum in crates/core/src/ast.rs
- [x] 1.2 Add #[non_exhaustive] to Predicate enum in crates/core/src/ast.rs
- [x] 1.3 Add #[non_exhaustive] to EvalError in crates/engine/src/lib.rs
- [x] 1.4 Add #[non_exhaustive] to FactPattern in crates/core/src/predicates.rs
- [x] 1.5 Add #[non_exhaustive] to Expr, CommandPattern, ArgPattern in crates/core/src/pattern.rs
- [x] 1.6 Add #[non_exhaustive] to ResolutionError in crates/config/src/resolve.rs
- [x] 1.7 Add wildcard arms to all internal exhaustive matches that now need them
- [x] 1.8 Run cargo build --workspace and fix any compilation errors

## 2. Restrict visibility of internal types

- [x] 2.1 Change ParsedCheck and parse_check_command to pub(crate) in crates/engine/src/check.rs
- [ ] 2.2 Change Ann enum to pub(crate) in src/annotation.rs
- [x] 2.3 Change TracingFold struct to pub(crate) in src/annotation.rs
- [x] 2.4 Change print_separator and render_elements to pub(crate) in src/output/mod.rs
- [x] 2.5 Run cargo build --workspace and fix any compilation errors
