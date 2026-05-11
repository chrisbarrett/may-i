## REMOVED Requirements

### Requirement: Eval ingests explicit OpenCode agent context

**Reason**: Capability `opencode-context` folded into `claude-code-hook`. Both describe how an external harness supplies context to `may-i`.
**Migration**: Reference `claude-code-hook`. Body and scenarios unchanged.

### Requirement: OpenCode context can gate rule evaluation

**Reason**: Capability `opencode-context` folded into `claude-code-hook`.
**Migration**: Reference `claude-code-hook`.

### Requirement: OpenCode context remains inspectable in eval output

**Reason**: Capability `opencode-context` folded into `claude-code-hook`.
**Migration**: Reference `claude-code-hook`.
