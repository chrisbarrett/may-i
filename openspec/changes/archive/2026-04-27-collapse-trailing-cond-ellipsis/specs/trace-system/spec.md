## MODIFIED Requirements

### Requirement: Unevaluated branches are dimmed
When short-circuiting skips child nodes, those nodes SHALL be rendered in dimmed
style in the left column with no right-column annotation. When a `cond` branch
matches and produces an effect (short-circuiting evaluation), all subsequent
skipped branches and any skipped fallback SHALL be collapsed into a single
dimmed `…` atom rather than rendering each skipped branch individually.

#### Scenario: Cond short-circuit collapses trailing branches
- **WHEN** a `cond` has 5 branches and the 2nd branch matches
- **THEN** branches 1-2 render normally (branch 1 shows predicate evaluation,
  branch 2 shows match and effect)
- **AND** branches 3-5 are replaced by a single `…`

#### Scenario: Skipped fallback merges into trailing ellipsis
- **WHEN** a `cond` has branches and a fallback, and a branch matches
- **THEN** the skipped fallback is NOT rendered separately
- **AND** the single trailing `…` covers both remaining branches and fallback

#### Scenario: No match evaluates all branches normally
- **WHEN** no `cond` branch matches and there is a fallback
- **THEN** all branch predicates render with their evaluation traces
- **AND** the fallback renders normally (no collapsing)

#### Scenario: All branches skipped except first match
- **WHEN** the first `cond` branch matches
- **THEN** only the matching branch and a single trailing `…` appear
- **AND** no individual `(… …)` pairs are rendered
