## REMOVED Requirements

### Requirement: `(authorise …)` pushes wrapper command name onto :via set

**Reason**: Capability `via-fact-builtin` folded into `facts`. The `:via` automatic-fact behaviour is a sub-section of the facts surface, not a separate capability.
**Migration**: Reference `facts` for the `:via` automatic-fact rules. Requirement body and scenarios are unchanged.

### Requirement: :via is the only automatically pushed fact

**Reason**: Capability `via-fact-builtin` folded into `facts`.
**Migration**: Reference `facts`.
