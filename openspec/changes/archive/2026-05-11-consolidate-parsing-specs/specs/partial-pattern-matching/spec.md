## REMOVED Requirements

### Requirement: Fewer args than required patterns returns no match

**Reason**: Capability `partial-pattern-matching` folded into `pattern-expressions`. Quantifier semantics belong with the rest of the pattern-expression rules.
**Migration**: Reference `pattern-expressions`. Body and scenarios unchanged.

### Requirement: Optional quantifier matches with or without arg

**Reason**: Capability `partial-pattern-matching` folded into `pattern-expressions`.
**Migration**: Reference `pattern-expressions`.

### Requirement: OneOrMore quantifier requires at least one match

**Reason**: Capability `partial-pattern-matching` folded into `pattern-expressions`.
**Migration**: Reference `pattern-expressions`.

### Requirement: ZeroOrMore quantifier matches any count

**Reason**: Capability `partial-pattern-matching` folded into `pattern-expressions`.
**Migration**: Reference `pattern-expressions`.
