## Context

The may-i configuration system uses an s-expression based DSL for defining authorization rules. Rules can contain embedded `(check ...)` forms for testing that verify the rule produces expected decisions for given commands and context.

Currently, checks are only allowed inside rule definitions:
```lisp
(rule (command "git")
      (effect :allow)
      (check :allow "git status"))  ; embedded check
```

Users want to write standalone tests that evaluate against the complete rule set, not tied to any specific rule. This enables:
- Integration tests that verify cross-cutting behavior
- Security invariants (e.g., "nobody can rm -rf /")
- Better test organization (tests in one section, rules in another)

## Goals / Non-Goals

**Goals:**
- Allow `(check ...)` forms at the top level of config files
- Top-level checks test against the complete rule set using the standard evaluation engine
- Support `with-facts` scoping exactly like embedded checks
- Mix top-level and embedded checks freely in the same config
- Clear error reporting that distinguishes top-level check failures

**Non-Goals:**
- Changes to check semantics (same `Check` type, same execution)
- New check syntax beyond what's already supported in embedded checks
- Changes to how embedded checks work
- Test ordering guarantees (top-level vs embedded)
- Named checks or test suites

## Decisions

### Decision: Reuse existing `Check` type
**Rationale**: The `Check` struct already has exactly the fields we need: `command`, `expected`, `context`, `source_span`. No new fields required.

**Alternative considered**: Create a `TopLevelCheck` type with additional metadata like name/description. Rejected to keep the change minimal.

### Decision: Parse with same `parse_check_items()` function
**Rationale**: Embedded checks and top-level checks have identical syntax. The existing parser already handles `with-facts`, decision keywords, and commands.

**Implementation**: Call `parse_check_items(&list[1..], &ContextFacts::default(), warnings, form.span())` for top-level forms, same as inside rules.

### Decision: Store in `Config.checks` alongside `rules`
**Rationale**: Clean separation - rules have their embedded checks, config has top-level checks.

**Alternative considered**: Flatten all checks into one list. Rejected because embedded checks are conceptually tied to their rules (for documentation/context), while top-level checks are standalone.

### Decision: Run all checks together in `run_checks()`
**Rationale**: Simplest implementation - iterate rules for embedded checks, then iterate `config.checks` for top-level checks.

**Trade-off**: Users cannot easily run only embedded or only top-level checks. If needed, this could be added later via CLI flags.

## Risks / Trade-offs

**[Risk]** Config files could become disorganized with checks scattered everywhere
→ **Mitigation**: Document best practices; checks logically belong near what they test

**[Risk]** Check output may be confusing without knowing which are top-level vs embedded
→ **Mitigation**: Include location info in `CheckResult` (already has `location` field with file:line:col)

**[Risk]** Performance: large configs with many top-level checks
→ **Mitigation**: Each check is one engine evaluation; unlikely to be bottleneck. Can optimize later if needed.

**[Risk]** Breaking change if someone has a `check` top-level form that was previously rejected
→ **Mitigation**: This was previously an error ("unknown top-level form"), so this is not breaking

## Migration Plan

No migration needed - this is a pure addition. Existing configs work unchanged.

## Open Questions

None. Design is straightforward extension of existing functionality.
