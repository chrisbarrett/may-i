## 1. Fold absorbed specs into `claude-code-hook`

For each move, copy the `### Requirement: NAME` block — body and
`#### Scenario:` children — verbatim from the source file. Append after
the existing 4 requirements.

### 1a. From `opencode-context` → `claude-code-hook`

- [ ] 1a.1 *Eval ingests explicit OpenCode agent context* — copy verbatim.
- [ ] 1a.2 *OpenCode context can gate rule evaluation* — copy verbatim.
- [ ] 1a.3 *OpenCode context remains inspectable in eval output* — copy
  verbatim.

### 1b. From `eval-stdin` → `claude-code-hook`

- [ ] 1b.1 *Eval reads command from stdin when piped* — copy verbatim.
- [ ] 1b.2 *Ambiguous input detection* — copy verbatim.
- [ ] 1b.3 *Missing input detection* — copy verbatim.

## 2. Update `claude-code-hook` Purpose

- [ ] 2.1 Append a sentence noting that the spec now also covers
  OpenCode context ingestion and stdin command-reading semantics.

## 3. Remove absorbed spec directories

- [ ] 3.1 `rm -rf openspec/specs/opencode-context/`
- [ ] 3.2 `rm -rf openspec/specs/eval-stdin/`

## 4. Update cross-references

- [ ] 4.1 `grep -rln 'opencode-context\|eval-stdin' openspec/specs/ .claude/ CONTEXT.md CLAUDE.md README.md`
  — repoint each hit to `claude-code-hook`.

## 5. Verify

- [ ] 5.1 Each absorbed requirement appears once and only once in
  `claude-code-hook`.
- [ ] 5.2 `openspec validate consolidate-cli-hooks --strict` passes.

## 6. Note: rename deferred

- [ ] 6.1 The rename `claude-code-hook` → `harness-integration` (broader
  umbrella for harness adapters) is deferred to the
  `rename-specs-to-vocab` change.
