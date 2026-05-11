## 1. Add the apply-procedure clarification to `spec-conventions`

- [x] 1.1 Append the new requirement *Capability renames are filesystem
  moves driven by tasks.md* to `openspec/specs/spec-conventions/spec.md`.

## 2. Rename `pattern-expressions` → `patterns`

- [x] 2.1 `mkdir openspec/specs/patterns/`.
- [x] 2.2 `git mv openspec/specs/pattern-expressions/spec.md openspec/specs/patterns/spec.md`
  (or `mv` if not under git tracking yet).
- [x] 2.3 Edit the title line: `# pattern-expressions Specification` →
  `# Patterns Specification`.
- [x] 2.4 Edit the Purpose to use *Patterns* (not *Pattern Expressions*)
  in any prose; reference `CONTEXT.md`'s Pattern entry.
- [x] 2.5 `rm -rf openspec/specs/pattern-expressions/`.
- [x] 2.6 `grep -rln 'pattern-expressions' openspec/ .claude/ CONTEXT.md CLAUDE.md README.md`
  — repoint each hit to `patterns`.

## 3. Rename `trace-system` → `traces`

- [x] 3.1 `mkdir openspec/specs/traces/`.
- [x] 3.2 Move `spec.md` from `trace-system/` to `traces/`.
- [x] 3.3 Edit the title line: `# trace-system Specification` →
  `# Traces Specification`.
- [x] 3.4 Edit the Purpose to drop the `-system` suffix and refer to
  *traces* throughout.
- [x] 3.5 `rm -rf openspec/specs/trace-system/`.
- [x] 3.6 Repoint all cross-references.

## 4. Rename `human-evaluation-trace` → `decision-trace`

- [x] 4.1 `mkdir openspec/specs/decision-trace/`.
- [x] 4.2 Move `spec.md`.
- [x] 4.3 Edit the title line: `# human-evaluation-trace Specification` →
  `# Decision-Trace Specification`.
- [x] 4.4 Edit the Purpose to use *decisions* (not *evaluations*).
- [x] 4.5 `rm -rf openspec/specs/human-evaluation-trace/`.
- [x] 4.6 Repoint all cross-references.

## 5. Rename `rule-evaluation` → `rule-decisions`

- [x] 5.1 `mkdir openspec/specs/rule-decisions/`.
- [x] 5.2 Move `spec.md`.
- [x] 5.3 Edit the title line: `# rule-evaluation Specification` →
  `# Rule-Decisions Specification`.
- [x] 5.4 Edit the Purpose to use *decisions* throughout. Retain
  `Trust-relevant: no.`
- [x] 5.5 `rm -rf openspec/specs/rule-evaluation/`.
- [x] 5.6 Repoint all cross-references.

## 6. Rename `claude-code-hook` → `harness-integration`

- [x] 6.1 `mkdir openspec/specs/harness-integration/`.
- [x] 6.2 Move `spec.md`.
- [x] 6.3 Edit the title line: `# claude-code-hook Specification` →
  `# Harness-Integration Specification`.
- [x] 6.4 Rewrite the Purpose to position the spec as the umbrella
  harness-input contract (Claude Code is one adapter; OpenCode and
  generic stdin are others). The post-consolidation Purpose already
  covers OpenCode + stdin, so this is mostly a name-update pass.
- [x] 6.5 `rm -rf openspec/specs/claude-code-hook/`.
- [x] 6.6 Repoint all cross-references.

## 7. Verify

- [x] 7.1 `ls openspec/specs/ | grep -E 'pattern-expressions|trace-system|human-evaluation-trace|rule-evaluation|claude-code-hook'`
  returns empty (old directories all removed).
- [x] 7.2 Each renamed spec passes `spec-conventions` Requirement 1
  (canonical scaffold).
- [x] 7.3 Each renamed spec passes the *Spec names use user vocabulary*
  requirement.
- [x] 7.4 No dangling cross-references to old names anywhere in
  `openspec/`, `.claude/`, root markdown files, or source code comments
  that reference spec docs.
- [x] 7.5 `openspec validate rename-specs-to-vocab --strict` passes.
