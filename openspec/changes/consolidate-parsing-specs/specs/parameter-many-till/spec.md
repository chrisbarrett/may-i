## REMOVED Requirements

### Requirement: `(many-till PAT)` declares multi-token parameter capture

**Reason**: Capability `parameter-many-till` folded into `parser-bindings`. Multi-token capture is part of the parser-declaration surface.
**Migration**: Reference `parser-bindings`. Body and scenarios unchanged.

### Requirement: Rules access `(many-till …)`-captured value via the bound `#var`

**Reason**: Capability `parameter-many-till` folded into `parser-bindings`.
**Migration**: Reference `parser-bindings`.

### Requirement: Multi-occurrence parameters fire rule body per occurrence

**Reason**: Capability `parameter-many-till` folded into `parser-bindings`.
**Migration**: Reference `parser-bindings`.
