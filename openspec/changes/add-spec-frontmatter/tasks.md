## 1. Devshell and validator script

- [ ] 1.1 Add `yq-go` to the `packages` list in `builder.nix` devshell. Enter the devshell and confirm `yq --version` resolves to the `yq-go` binary.
- [ ] 1.2 Create `scripts/validate-spec-frontmatter.sh`: `set -euo pipefail`, iterates `openspec/specs/*/spec.md`, extracts frontmatter via `yq`, validates `audience` enum (`user`|`contributor`), `bucket` enum (10 documented values), optional `trust-relevant` boolean, and the `audience: user` + `bucket: contributor-internals` invariant. Exit code: 0 on clean pass, 1 on any violation with one diagnostic per offending file on stderr.
- [ ] 1.3 Make the script executable (`chmod +x`). Run it against `openspec/specs/` before any backfill — confirm it currently reports 31 missing-frontmatter errors (sanity check the iteration).
- [ ] 1.4 Author a small fixture-based shell test or `bats` test (if `bats` is in nixpkgs) that exercises each rejection path: missing frontmatter, unknown audience, unknown bucket, missing required field, contradictory `user`/`contributor-internals` combination. Place under `scripts/tests/` or similar. If `bats` is too heavy, inline test cases as `# self-test` block at the bottom of the script gated on `--self-test`.

## 2. Backfill frontmatter on all 31 stable specs

Backfill table (audience / bucket / trust-relevant). Verify each row against the spec's body before committing; rows flagged `REVIEW` require careful reading because the spec's name or content makes audience or bucket non-obvious.

| Spec | audience | bucket | trust-relevant | Notes |
|---|---|---|---|---|
| `code-quality` | contributor | contributor-internals | false | |
| `decision-trace` | user | tracing-and-output | false | |
| `dsl-form-list-syntax` | user | parsing | false | REVIEW name vs. content |
| `fact-predicates-in-args` | contributor | parsing | false | REVIEW: "predicates" is contributor vocab — confirm content is internals |
| `facts` | user | facts | false | |
| `fmt-command` | user | cli | false | |
| `harness-integration` | user | cli | false | hook-protocol surface is user-visible |
| `load-directive` | user | loading | true | `(load …)` participation gated by trust |
| `migration-diff-display` | user | migration | false | |
| `migration-system` | user | migration | true | migrations can affect hashes |
| `oracle-trace-testing` | contributor | testing | false | |
| `parser-bindings` | user | parsing | false | `#var` bindings are DSL surface |
| `parser-engine-invariants` | contributor | contributor-internals | false | |
| `patterns` | user | parsing | false | |
| `per-rule-trust` | user | trust | true | |
| `pretty-printing` | user | tracing-and-output | false | |
| `repo-local-config` | user | loading | true | trust-loaded config |
| `rule-combination` | user | rules-and-evaluation | false | combinators don't affect hashing |
| `rule-decisions` | user | rules-and-evaluation | false | |
| `shell-command-security-model` | user | parsing | true | REVIEW: confirm bucket — could plausibly be its own area |
| `spec-conventions` | contributor | contributor-internals | false | |
| `test-infrastructure` | contributor | testing | false | |
| `testing-strategy` | contributor | testing | false | |
| `traces` | user | tracing-and-output | false | |
| `trust-advisory-boxes` | user | trust | true | |
| `trust-command` | user | trust | true | |
| `trust-gate` | user | trust | true | |
| `trust-hashing` | contributor | trust | true | hashing is internal mechanism |
| `trust-provenance` | user | trust | true | |
| `trust-store` | user | trust | true | |
| `wordpart-source-spans` | contributor | contributor-internals | false | REVIEW: name uses contributor vocab — confirm bucket vs. parsing |

- [ ] 2.1 Resolve every `REVIEW` row by reading the spec body and (if necessary) flagging in PR for human decision before committing the backfill.
- [ ] 2.2 For each row above, prepend a YAML frontmatter block to the spec file:

  ```
  ---
  audience: <value>
  bucket: <value>
  trust-relevant: <true | omitted>
  ---
  ```

  Place above the existing `# <Capability> Specification` title. Omit `trust-relevant` entirely when its value is `false` (per the spec delta).
- [ ] 2.3 For each spec whose Purpose currently contains a `Trust-relevant: yes` line: delete the line. Keep the cross-reference prose sentence intact (it moves from the same line into a standalone sentence if necessary).
- [ ] 2.4 For each contributor-facing spec whose Purpose currently leads with `Contributor-only.` or `Internal.` declaration: keep the prose lead-in (it aids human readers); the frontmatter `audience: contributor` is now the authoritative declaration. No deletion required.
- [ ] 2.5 Run `scripts/validate-spec-frontmatter.sh` against `openspec/specs/`. Confirm zero violations.
- [ ] 2.6 Run `openspec validate --all --strict --no-interactive` to confirm OpenSpec itself still parses every spec cleanly (frontmatter is tolerated per the source audit; this step is the empirical check).

## 3. Spec-conventions delta application

- [ ] 3.1 Apply the ADDED requirement "Stable specs declare metadata in YAML frontmatter" from `openspec/changes/add-spec-frontmatter/specs/spec-conventions/spec.md` to `openspec/specs/spec-conventions/spec.md`.
- [ ] 3.2 Apply the MODIFIED requirement "User-facing and contributor-facing specs do not mix audiences" — replace the existing requirement block in `openspec/specs/spec-conventions/spec.md` byte-for-byte with the new version.
- [ ] 3.3 Apply the MODIFIED requirement "Trust-relevance is declared in frontmatter" — replace the existing "Trust-relevance is declared in the Purpose" requirement block with the new version (note the heading renames; treat as MODIFIED, not REMOVE+ADD, because the underlying obligation is the same).
- [ ] 3.4 Apply the MODIFIED requirement "Pre-merge checklist applies to every spec-touching change" — replace the existing block, grown from 7 to 8 checklist items.
- [ ] 3.5 Add the frontmatter block to `spec-conventions/spec.md` itself (`audience: contributor`, `bucket: contributor-internals`, `trust-relevant` omitted).

## 4. Prek hook integration

- [ ] 4.1 Add a new entry to `prek.toml` under `[[repos]].hooks`:
  ```toml
  {
    id = "validate-spec-frontmatter",
    name = "validate spec frontmatter",
    entry = "scripts/validate-spec-frontmatter.sh",
    language = "system",
    files = "^openspec/specs/",
    pass_filenames = false,
    stages = ["pre-commit"],
  },
  ```
- [ ] 4.2 Run `prek install` (already invoked by the devshell `shellHook`, but re-run after editing `prek.toml`).
- [ ] 4.3 Stage a deliberately invalid spec frontmatter (e.g., `audience: nobody`), attempt `git commit`, confirm the hook blocks. Restore the file before continuing.

## 5. Rule and documentation updates

- [ ] 5.1 Update `.claude/rules/openspec-specs.md`:
  - Add a bullet under the existing checklist describing frontmatter (fields, enums, validator name).
  - Add the grep recipe: `yq '. | select(.audience == "user") | filename' openspec/specs/*/spec.md` for the user-facing whitelist.
  - Update the checklist count in the rule body from "seven-point" / 7 to "eight-point" / 8 wherever it appears.
  - Update item 4's wording to reference `trust-relevant: true` in frontmatter rather than `Trust-relevant: yes` in Purpose.
- [ ] 5.2 No changes to `CONTEXT.md` or `AGENTS.md` are required — `CONTEXT.md` is vocabulary, `AGENTS.md` is project orientation; both are upstream of the spec-conventions rule which is the authority for this convention.

## 6. Verification

- [ ] 6.1 Run `scripts/validate-spec-frontmatter.sh` — expect 0 violations.
- [ ] 6.2 Run `openspec validate --all --strict --no-interactive` — expect 0 violations.
- [ ] 6.3 Run `openspec change show add-spec-frontmatter --json` (or equivalent) and confirm the spec-conventions delta operations (ADDED + MODIFIED × 3) all match the existing requirement headings whitespace-insensitively.
- [ ] 6.4 Run `prek run --all-files validate-spec-frontmatter` (or whatever prek's invocation form is) to confirm the hook runs cleanly post-backfill.
- [ ] 6.5 Spot-check the audience grep recipe: `yq '. | select(.audience == "user") | filename' openspec/specs/*/spec.md` returns the user-facing spec list and no contributor specs.
- [ ] 6.6 Spot-check the bucket query: `yq '.bucket' openspec/specs/*/spec.md | sort | uniq -c` shows distribution roughly matching the table above (trust cluster is the largest, etc.).
