## 1. OpenCode integration contract

- [ ] 1.1 Update the current OpenCode-to-`may-i` integration to pass `MAYI_OPENCODE_AGENT=<active-agent>` to the `may-i` evaluation subprocess.
- [ ] 1.2 Keep the new variable scoped to the `may-i` subprocess and document the OpenCode-to-`may-i` contract in comments or docs where appropriate.

## 2. Runtime ingestion in may-i

- [ ] 2.1 Extend the `eval` command path to build runtime context facts from `MAYI_OPENCODE_AGENT` before evaluation.
- [ ] 2.2 Emit `:client/opencode` and `:opencode/agent` only when the OpenCode agent variable is present and non-empty.
- [ ] 2.3 Ensure human-readable and JSON `eval` output continue to reflect context-aware traces for OpenCode-gated rules.

## 3. Verification and examples

- [ ] 3.1 Add tests covering matching and non-matching OpenCode agent context on the `eval` path.
- [ ] 3.2 Add tests covering the conservative case where `MAYI_OPENCODE_AGENT` is absent.
- [ ] 3.3 Update examples and docs with a representative rule using `(context (= :opencode/agent "plan"))`.
