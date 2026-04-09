## Context

Code review identified duplicated logic, bare unwraps, an unreachable branch, and several minor quality issues. None are bugs, but they increase maintenance cost and risk.

## Goals / Non-Goals

**Goals:**
- Eliminate duplicated helper functions and logic
- Replace bare unwraps with documented expects or proper error handling
- Fix unreachable code paths
- Add safety bounds to unbounded loops

**Non-Goals:**
- Large-scale refactoring (e.g., splitting cst.rs or annotation.rs into submodules — noted as optional in proposal)
- Changing public APIs
- Adding new features

## Decisions

### Config loading: extract fn load_config(path) -> Result<Config>
Place in a shared module (e.g., `src/config_loader.rs` or a function in `src/lib.rs`). Three callers (cmd_eval, cmd_check, cmd_claude_code_hook) all do resolve_path → load → validate_and_resolve.

### quote_string: move to crates/sexpr/src/lib.rs
Both `cst.rs::quote_string` and `sexpr.rs::quote_atom` do identical escaping. Expose one `pub fn quote_string(s: &str) -> String` from the sexpr crate root and delete the duplicates.

### rewrite_until_convergence: add MAX_ITERS = 100
If rules oscillate (A→B→A), the current code loops forever. A 100-iteration cap is generous (real configs converge in 2-3 passes) and provides a safety net.

### colorize_right: reorder branches
The ~/∈ check at line 56 should come before the general → check at line 20, since strings with both characters currently fall into the wrong branch.

### Keyword::new unwraps: use expect with reason
`Keyword::new(":via").expect("hardcoded keyword")` is clearer than bare unwrap. A const approach would be better but requires Keyword to support const construction, which is more invasive.

## Risks / Trade-offs

- [Config loading helper couples cmd modules] → Minimal coupling — it's a pure function that takes a path and returns a Config.
- [Rewrite iteration cap could theoretically reject valid configs] → 100 iterations is far beyond any real convergence path. Log a warning if the cap is hit.
