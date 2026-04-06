# Canonical Expression Format

## Problem

The pretty-printer has sophisticated formatting rules that are implemented but
not fully documented:

1. **Indent specification system** - N-value mechanism for special forms
2. **If-form asymmetric indentation** - Visual distinction between then/else
3. **Fill layout for and/or** - Atom-packing instead of one-per-line
4. **Dead code** - References to `case` form that was renamed to `cond`

These rules affect automatic config migrations and trace output, so they need
to be specified and maintained.

## Solution

Create a canonical expression format specification and implement cleanup:

1. Document the indent spec system (N=0/1/2)
2. Document if-form asymmetric layout
3. Document fill layout for and/or
4. Remove dead `case` references
5. Rename `args_cond_to_case` → `hoist_cond`

## Success Criteria

- All formatting rules are documented in `/openspec/specs/canonical-expression-format/spec.md`
- `case` removed from INDENT_SPECS, colored keywords, and rendering
- `args_cond_to_case` renamed to `hoist_cond`
- All existing tests pass
- Migration output remains unchanged

## Scope

### In Scope
- Spec documentation
- Dead code removal
- Function renaming

### Out of Scope
- Changing any formatting behavior
- New formatting features

## Risks

| Risk | Mitigation |
|------|------------|
| Accidentally break cond rendering | Verify cond uses render_cond, not indent specs |
| Migration output changes | Test with sample configs before/after |
