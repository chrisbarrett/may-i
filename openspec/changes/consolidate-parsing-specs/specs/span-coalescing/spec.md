## REMOVED Requirements

### Requirement: Adjacent ignore spans SHALL be coalesced

**Reason**: Capability `span-coalescing` (contributor-only) folded into `wordpart-source-spans`. Span-coalescing is a downstream concern of the wordpart/source-span machinery.
**Migration**: Reference `wordpart-source-spans`. Body and scenarios unchanged.
