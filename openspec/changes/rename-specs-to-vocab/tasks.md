## 1. Add the apply-procedure clarification to `spec-conventions`

- [ ] 1.1 Append the new requirement *Capability renames are filesystem
  moves driven by tasks.md* to `openspec/specs/spec-conventions/spec.md`.

## 2. Rename `pattern-expressions` → `patterns`

- [ ] 2.1 `mkdir openspec/specs/patterns/`.
- [ ] 2.2 `git mv openspec/specs/pattern-expressions/spec.md openspec/specs/patterns/spec.md`
  (or `mv` if not under git tracking yet).
- [ ] 2.3 Edit the title line: `# pattern-expressions Specification` →
  `# Patterns Specification`.
- [ ] 2.4 Edit the Purpose to use *Patterns* (not *Pattern Expressions*)
  in any prose; reference `CONTEXT.md`'s Pattern entry.
- [ ] 2.5 `rm -rf openspec/specs/pattern-expressions/`.
- [ ] 2.6 `grep -rln 'pattern-expressions' openspec/ .claude/ CONTEXT.md CLAUDE.md README.md`
  — repoint each hit to `patterns`.

## 3. Rename `trace-system` → `traces`

- [ ] 3.1 `mkdir openspec/specs/traces/`.
- [ ] 3.2 Move `spec.md` from `trace-system/` to `traces/`.
- [ ] 3.3 Edit the title line: `# trace-system Specification` →
  `# Traces Specification`.
- [ ] 3.4 Edit the Purpose to drop the `-system` suffix and refer to
  *traces* throughout.
- [ ] 3.5 `rm -rf openspec/specs/trace-system/`.
- [ ] 3.6 Repoint all cross-references.

## 4. Rename `human-evaluation-trace` → `decision-trace`

- [ ] 4.1 `mkdir openspec/specs/decision-trace/`.
- [ ] 4.2 Move `spec.md`.
- [ ] 4.3 Edit the title line: `# human-evaluation-trace Specification` →
  `# Decision-Trace Specification`.
- [ ] 4.4 Edit the Purpose to use *decisions* (not *evaluations*).
- [ ] 4.5 `rm -rf openspec/specs/human-evaluation-trace/`.
- [ ] 4.6 Repoint all cross-references.

## 5. Rename `rule-evaluation` → `rule-decisions`

- [ ] 5.1 `mkdir openspec/specs/rule-decisions/`.
- [ ] 5.2 Move `spec.md`.
- [ ] 5.3 Edit the title line: `# rule-evaluation Specification` →
  `# Rule-Decisions Specification`.
- [ ] 5.4 Edit the Purpose to use *decisions* throughout. Retain
  `Trust-relevant: no.`
- [ ] 5.5 `rm -rf openspec/specs/rule-evaluation/`.
- [ ] 5.6 Repoint all cross-references.

## 6. Rename `claude-code-hook` → `harness-integration`

- [ ] 6.1 `mkdir openspec/specs/harness-integration/`.
- [ ] 6.2 Move `spec.md`.
- [ ] 6.3 Edit the title line: `# claude-code-hook Specification` →
  `# Harness-Integration Specification`.
- [ ] 6.4 Rewrite the Purpose to position the spec as the umbrella
  harness-input contract (Claude Code is one adapter; OpenCode and
  generic stdin are others). The post-consolidation Purpose already
  covers OpenCode + stdin, so this is mostly a name-update pass.
- [ ] 6.5 `rm -rf openspec/specs/claude-code-hook/`.
- [ ] 6.6 Repoint all cross-references.

## 7. Verify

- [ ] 7.1 `ls openspec/specs/ | grep -E 'pattern-expressions|trace-system|human-evaluation-trace|rule-evaluation|claude-code-hook'`
  returns empty (old directories all removed).
- [ ] 7.2 Each renamed spec passes `spec-conventions` Requirement 1
  (canonical scaffold).
- [ ] 7.3 Each renamed spec passes the *Spec names use user vocabulary*
  requirement.
- [ ] 7.4 No dangling cross-references to old names anywhere in
  `openspec/`, `.claude/`, root markdown files, or source code comments
  that reference spec docs.
- [ ] 7.5 `openspec validate rename-specs-to-vocab --strict` passes.
