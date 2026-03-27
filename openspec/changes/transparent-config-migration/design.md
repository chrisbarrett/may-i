## Context

The migration system already exists (`crates/config/src/migrate.rs`) with rewrite rules for converting v1 syntax to canonical. The `migrate` command uses CST parsing → rewrite rules → serialization. However, config-dependent commands (eval, check) currently only use the canonical parser (`parse_config`), which fails on legacy syntax.

CST nodes carry span information through `TriviaAnn`. The `CstNode::to_sexpr()` method converts CST to Sexpr while preserving spans, enabling accurate error reporting through the migration chain.

## Goals / Non-Goals

**Goals:**
- All config-dependent commands work transparently with legacy configs
- Error messages report correct source locations (original file positions)
- Warn users when auto-migration is applied
- Preserve existing fast path for already-migrated configs

**Non-Goals:**
- Modifying the rewrite rules (they already work)
- Changing the migrate command behavior
- Supporting invalid configs (migration must succeed for transparent fallback)
- Performance optimization for legacy configs (acceptable to be slower)

## Decisions

### Decision: Try-parse-first, migrate-on-failure strategy
**Rationale:** Modern configs (already migrated) are the fast path. Legacy configs are rare and only pay the migration cost once per session.

**Alternative considered:** Proactive detection via string scan for keywords (`wrapper`, `defcontext`, etc.). Rejected as unnecessary complexity—parse failure is a reliable signal.

### Decision: Extract `parse_config_from_sexprs(forms: &[Sexpr])` 
**Rationale:** Enables the migration flow: CST → migrate → Sexpr forms → parse without re-serializing to text. The current `parse_config(input: &str)` does both parsing and AST construction.

**Signature:**
```rust
pub fn parse_config_from_sexprs(forms: &[Sexpr]) -> Result<Config, RawError>
```

### Decision: Preserve source spans through CST→Sexpr conversion
**Rationale:** `CstNode::to_sexpr()` copies the span from `TriviaAnn` to the Sexpr. When we later convert Sexpr to AST, those spans flow into the AST nodes. Error reporting uses these spans against the original source text.

### Decision: Return original error if migration also fails
**Rationale:** The original error ("unknown top-level form: wrapper") is more informative than a migration error. Migration failure usually means the config is fundamentally broken, not just legacy syntax.

### Decision: Warning message format
```
Config auto-migrated from legacy format. Run `may-i migrate` to update permanently.
```
Printed to stderr so it doesn't interfere with stdout (important for JSON mode).

## Risks / Trade-offs

**[Risk]** Migration produces semantically different config (rare edge cases in rewrite rules)
→ **Mitigation:** Migration rules are well-tested. The `validate_migration()` function already checks that migrated output parses correctly.

**[Risk]** Span drift during complex migrations (nested forms moving between lines)
→ **Mitigation:** CST spans are byte offsets into the original source. Even if forms move between lines during conceptual migration, the byte offsets remain valid for error reporting.

**[Risk]** Double-parsing overhead for invalid configs (try parse → fail → migrate → fail → return original error)
→ **Mitigation:** Invalid configs are rare. Valid modern configs pay zero overhead. Valid legacy configs pay one extra CST parse + migration.

## Migration Plan

Not applicable—this is a runtime behavior change, not a data migration.

## Open Questions

None—design is complete.
