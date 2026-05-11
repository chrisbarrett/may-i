## REMOVED Requirements

### Requirement: Prelude ships parsers for common wrapper tools

**Reason**: Capability `prelude-wrapper-parsers` folded into `parser-bindings`. Prelude declarations are part of the parser-declaration surface.
**Migration**: Reference `parser-bindings`. Body and scenarios unchanged.

### Requirement: Prelude ships `find` parser with `(many-till …)` and named bindings

**Reason**: Capability `prelude-wrapper-parsers` folded into `parser-bindings`.
**Migration**: Reference `parser-bindings`.
