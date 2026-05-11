## REMOVED Requirements

### Requirement: Expr::Or matches if any sub-expression matches

**Reason**: Capability `expr-combinator-matching` folded into `pattern-expressions`. `Expr::Or` semantics belong with the rest of the pattern-expression rules.
**Migration**: Reference `pattern-expressions`. Body and scenarios unchanged.
