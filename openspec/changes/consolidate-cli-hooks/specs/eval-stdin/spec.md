## REMOVED Requirements

### Requirement: Eval reads command from stdin when piped

**Reason**: Capability `eval-stdin` folded into `claude-code-hook`. Stdin handling is part of the harness-input contract.
**Migration**: Reference `claude-code-hook`. Body and scenarios unchanged.

### Requirement: Ambiguous input detection

**Reason**: Capability `eval-stdin` folded into `claude-code-hook`.
**Migration**: Reference `claude-code-hook`.

### Requirement: Missing input detection

**Reason**: Capability `eval-stdin` folded into `claude-code-hook`.
**Migration**: Reference `claude-code-hook`.
