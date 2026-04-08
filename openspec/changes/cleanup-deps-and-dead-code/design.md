## Context

Cargo.toml carries three unused dependencies. The tests/archive/ directory is dead code. Clippy has ~15 auto-fixable warnings.

## Goals / Non-Goals

**Goals:**
- Remove all unused dependencies from root Cargo.toml
- Delete dead test code
- Clear trivial clippy warnings

**Non-Goals:**
- Restructuring dependency trees between crates
- Manual clippy fixes that require design decisions

## Decisions

### Delete tests/archive/ entirely
These files are not compiled (Cargo doesn't auto-discover subdirectory test files). They reference deprecated flags and stale APIs. Git history preserves them if needed.

### Run clippy --fix for auto-fixable only
Only apply clippy's automatic fixes (redundant closures, `.len() == 0` → `.is_empty()`, useless vec). Skip warnings that require judgment calls.

### Verify colored before removing
Check whether the root binary uses `colored` directly (e.g., `use colored::Colorize`) or only gets it transitively. Remove from root Cargo.toml only if confirmed unused.

## Risks / Trade-offs

- [Removing serde might break if some derive macro references it] → Check with `cargo build` after removal.
- [Clippy auto-fix could theoretically change behavior] → Run full test suite after.
