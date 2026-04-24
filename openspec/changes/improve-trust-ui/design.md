## Context

The trust system gates evaluation of rules from `(load ...)` files behind user approval. Currently `Provenance` is a unit enum (`PrimaryConfig | Loaded`) with no file path, `TrustHashes` discards canonical forms after hashing, and the trust store only persists hashes. This means no component in the pipeline has enough data to tell the user *what* they're trusting or *where* it came from.

The layout crate provides `Layout::Columns`, `Layout::Note`, `Layout::Text`, and `Layout::Stack` primitives already used by trace and check output. The trust UI should use the same primitives.

## Goals / Non-Goals

**Goals:**
- Users can see which files contribute untrusted rules and what those rules say before approving.
- Changed rules show a diff against the previously-trusted version.
- The `may-i trust` listing groups information by file for scannability.
- Block messages (eval + hook) name the source files involved.
- JSON output includes all metadata for programmatic consumption.

**Non-Goals:**
- Syntax-aware structural diffing of rule s-expressions. Line-level diff of canonical forms is sufficient.
- Showing rule content inline in the hook block response (JSON reason string stays short; detail available via `may-i trust`).

## Decisions

### 1. Provenance carries PathBuf

`Provenance::Loaded { path: PathBuf }` instead of unit variant. Every `expand_loads` call already knows the file path — thread it through.

**Alternative**: Separate side-table mapping spans to file paths. Rejected — provenance is the natural carrier and avoids a second data structure.

### 2. Trust store format: versioned with canonical forms

New format:
```json
{
  "version": 2,
  "programs": {
    "git": {
      "hash": "sha256:...",
      "rules": ["(rule \"git\" (effect :allow))"]
    }
  }
}
```

No backward compatibility needed — no consumers yet. Old v1 store files are discarded on load (programs re-appear as NEW). Clean implementation.

**Integrity**: The hash is the source of truth. Stored canonical forms are untrusted display metadata. On load, each entry's forms are re-hashed using the same algorithm as `compute_trust_hashes` (join with `\n`, SHA-256). Entries that pass verification load normally. Entries that fail are flagged as *suspect*.

### 2a. Interactive integrity repair

When suspect entries are detected, `may-i trust` gates all operations behind an interactive repair session. This prevents a tampered trust store from poisoning diff output.

**Flow:**
1. `TrustStore::load` returns both the store and a `Vec<SuspectEntry>` (program name, stored hash, unverified forms).
2. If suspects exist and the session is interactive (TTY on stdin, no `--json`), `cmd_trust` enters repair mode before the requested operation.
3. For each suspect entry, display: program name, stored hash, the stored (unverified) forms.
4. User chooses per-entry: **re-approve** (re-hash the stored forms → new hash, keeping the forms) or **drop** (remove entry entirely, program becomes NEW on next check).
5. Save the repaired store, then proceed with the originally requested operation.

**Non-interactive fallback**: In hook mode, piped stdin, or `--json`, skip repair. Treat suspect forms as unavailable (empty). Emit a stderr warning directing the user to run `may-i trust` interactively.

**Interactive prompting**: Use `dialoguer` for the per-entry confirm/select prompt (already common in Rust CLI tools). If not already a dependency, it's small and well-maintained. Alternative: raw stdin line reading, but `dialoguer` handles TTY detection and gives a consistent UX.

**Alternative considered**: Silent discard of tampered forms. Rejected — user should know their trust store may have been modified by another tool, and should explicitly decide whether to accept or reject the stored forms.

**Alternative**: Store forms in a separate file. Rejected — single file is simpler and the data is small.

### 2b. Interactive approval for trust operations

Trust approval (`may-i trust --all`, `may-i trust <program>`) becomes interactive when on a TTY. Instead of blindly writing hashes, the system walks the user through each pending entry.

**Flow for `may-i trust --all`:**
1. Collect all NEW/CHANGED entries.
2. For each entry, display: program name, status badge, source file(s), canonical rule forms. For CHANGED, also show the diff against previously-trusted forms.
3. Prompt: approve or skip.
4. Approved entries are written to the store. Skipped entries remain pending.
5. Save store after all entries are processed.

**Flow for `may-i trust <program>`:**
Same as above but for a single entry. Display detail, prompt confirm.

**Flow for `may-i trust` (no args):**
Show the listing (grouped-by-file for trusted, detail for pending). If pending entries exist, offer to walk through them for approval.

**Non-interactive fallback:** When stdin is not a TTY or `--json` is set, approve without prompting (preserves existing batch behavior for scripts and CI). This ensures `may-i trust --all` in a pipeline still works.

**Shared interactive primitive:** Both integrity repair (section 2a) and approval use the same pattern: display entry detail, prompt per-entry action. Factor into a shared `interactive_review` function that takes a list of entries and action choices, returns user decisions.

**Interactive prompting library:** Use `dialoguer` for TTY-aware prompts. Gives consistent UX (select/confirm), handles raw mode, and is lightweight.

### 3. TrustHashes expanded with ProgramMeta

```rust
pub struct ProgramMeta {
    pub hash: String,
    pub canonical_rules: Vec<String>,
    pub source_files: BTreeSet<PathBuf>,
}

pub struct TrustHashes {
    pub programs: BTreeMap<String, ProgramMeta>,
}
```

`compute_trust_hashes` already builds canonical strings and iterates rules — retain them instead of discarding.

### 4. Trust listing layout

**All trusted**: Group programs by source file, two-column packed layout using `Layout::Columns` with `ColContent::Breakable` for program names.

```
  echo, cat, ls                ~/rules/basics.lisp
  git, gh                      ~/rules/vcs.lisp

  All trusted.
```

**Untrusted entries exist**: Use `Layout::Note` (warn level) containing a `Layout::Stack` of per-program detail blocks. Each block shows: program name + status badge + file path, then indented rule forms. For CHANGED, show line-level diff with `-`/`+` prefixes (red/green).

### 5. Diff rendering

Simple line-by-line diff of canonical rule strings (one rule per line). Use the `similar` crate's `TextDiff` for unified diff hunks — it's lightweight and already commonly used. If not already a dependency, add it; otherwise hand-roll a basic LCS diff since the inputs are small (typically 1-5 lines per program).

**Alternative**: Shell out to `diff`. Rejected — adds process overhead and platform dependency.

### 6. Block message includes file paths

Eval block message changes from:
```
Loaded config rules for 'echo' need trust approval. Run: may-i trust "echo"
```
to:
```
Untrusted rules for 'echo' (from ~/rules/basics.lisp). Run: may-i trust "echo"
```

Hook JSON adds `untrustedFiles` to the reason but keeps `permissionDecision` as `"ask"`. The reason string includes file paths. Structured file list goes in JSON trust listing, not in the hook response (to avoid breaking hook consumers).

### 7. Trust advisory boxes via Layout::Note

All user-facing subcommands (eval, check, trust, migrate, parse) SHALL render trust warnings using the `Advisory` → `Layout::Note` box UI, matching the existing migration note pattern. Hook mode and help/reference are excluded.

Two box types with distinct levels:

**Warning (NoteLevel::Warn) — untrusted rules:**

The box adapts based on the number of untrusted programs:

*Single program:*
```
╭─ ⚠ Untrusted rules: git ──────────────────────────╮
│ Rules from ~/.config/may-i/config.lisp need        │
│ approval before they take effect.                  │
│                                                    │
│ Approve by running:                                │
│                                                    │
│ $ may-i trust "git"                                │
╰────────────────────────────────────────────────────╯
```

*Multiple programs:*
```
╭─ ⚠ Untrusted rules ───────────────────────────────╮
│ 7 programs have rules that need approval: git,     │
│ cargo, npm, docker, kubectl (and 2 more).          │
│                                                    │
│ Review and approve by running:                     │
│                                                    │
│ $ may-i trust                                      │
╰────────────────────────────────────────────────────╯
```

When there are 5 or fewer, all names are listed. Above 5, take the first 5 and show "(and N more)".

**Error (NoteLevel::Error) — trust store integrity failure:**

The box shows the path to the trust store file and names the affected entries.

*Specific entries tampered:*
```
╭─ ✗ Trust store integrity failure ──────────────────╮
│ 3 entries in ~/.local/share/may-i/trust.json have  │
│ mismatched hashes: git, cargo, npm.                │
│                                                    │
│ This may indicate tampering. Resolve by running:   │
│                                                    │
│ $ may-i trust                                      │
╰────────────────────────────────────────────────────╯
```

Entry names follow the same take-5 rule as the warning box.

*Whole file corrupt/unreadable:*
```
╭─ ✗ Trust store corrupted ──────────────────────────╮
│ ~/.local/share/may-i/trust.json could not be       │
│ loaded. The file may be corrupted or tampered.     │
│ All programs will require re-approval.             │
╰────────────────────────────────────────────────────╯
```

**Implementation:** Build `trust_warning_note()` and `trust_integrity_note()` in `src/output/mod.rs`, parallel to the existing `migration_note()`. Each subcommand calls these after loading config and trust store, rendering to stderr.

### 8. Eval no longer blocks on untrusted rules

Previously, `cmd_eval` returned early when trust failed, preventing evaluation. The new behavior: show the warning box, then proceed with evaluation. Untrusted rules default to `:ask`. This gives the user trace output alongside the trust warning, making it clear what would happen once they approve.

Hook mode is unchanged — it continues to block with a JSON `:ask` response, since it must give Claude Code a definitive answer.

### 9. Check subcommand gains trust awareness

`cmd_check` currently has no trust checking — a gap. It will gain the same advisory box rendering. Checks still run (results may reflect unapproved rules), but the user sees the warning and understands the context.

### 10. Per-rule trust granularity

Trust moves from per-program to per-rule. Each canonical rule form is individually hashed and tracked.

**Three states per rule:**
- **Approved** — rule participates in evaluation.
- **Ignored** — rule is filtered out before evaluation, as if it doesn't exist in the config.
- **Pending** — rule has never been reviewed (new) or has changed since last review. Treated as inactive (same as ignored) until explicitly approved.

**Rule identity:** Each rule is identified by its canonical form hash (`sha256:...`). When a rule's canonical form changes, the old hash disappears and the new hash appears as pending. There is no concept of "same rule, modified" at the store level — the interactive UI infers change by matching on program name + rule index within a program's rule list.

**Store format v3:**
```json
{
  "version": 3,
  "rules": {
    "sha256:abc...": {
      "program": "git",
      "form": "(rule \"git\" (effect :allow))",
      "status": "approved"
    },
    "sha256:def...": {
      "program": "git",
      "form": "(rule \"git\" (when (dir \"/tmp\") (effect :deny)))",
      "status": "ignored"
    }
  }
}
```

**Migration from v2:** On load, if `version == 2`, convert each program's `rules` array into individual rule entries, all with `status: "approved"`. This preserves existing approvals.

**Eval pipeline filtering:** Before evaluation, the engine receives only rules whose canonical hash is `approved` in the store. Ignored and pending rules are excluded. Primary config rules (not loaded) are always included — trust only applies to `(load ...)` rules.

### 11. Interactive `git add -p` style review

The `may-i trust` interactive flow changes from per-program confirm to per-rule review with single-key actions.

**Keybindings:**
- `y` — approve this rule
- `n` — ignore this rule (will not participate in eval)
- `s` — skip (decide later; rule stays pending)
- `q` — quit (remaining rules stay in current state)

**Display per rule:**
```
  (rule "git" (effect :allow))                              NEW
    file: ~/.config/may-i/rules/vcs.lisp

  [y] approve  [n] ignore  [s] skip  [q] quit ?
```

For changed rules (program has a previously-approved rule at the same position that no longer matches):
```
  (rule "git" (effect :allow))                          CHANGED
    file: ~/.config/may-i/rules/vcs.lisp
    -(rule "git" (effect :allow))
    +(rule "git" (effect :allow "safe for work"))

  [y] approve  [n] ignore  [s] skip  [q] quit ?
```

**Change detection heuristic:** For each program, zip the current canonical rules against the previously-stored rules (by position). If a current rule's hash matches a stored hash, it's unchanged. If it doesn't match and there's a stored rule at the same position, show it as CHANGED with diff. Extra rules beyond the stored count are NEW. Stored rules beyond the current count are implicitly removed (their store entries become orphaned and are cleaned up on save).

**Summary after review:**
```
  Approved: 3  Ignored: 1  Skipped: 2
```

**`--all` flag:** In non-interactive mode (piped stdin or `--json`), `--all` approves all pending rules. In interactive mode, `--all` enters the per-rule review flow for all pending rules (same as bare `may-i trust` when pending rules exist).

### 12. Orphan cleanup

After interactive review, any store entries whose canonical hash no longer appears in the current config are removed. This prevents the store from growing unboundedly as rules are edited over time.

## Risks / Trade-offs

- **Trust store format change** → v2→v3 migration is handled on load. Old binaries seeing v3 will fail to parse and re-create from scratch (all rules become pending). Acceptable pre-1.0.
- **PathBuf in Provenance increases struct size** → Minimal concern; rules are few (tens, not thousands). Could use `Arc<Path>` if needed later.
- **Adding `similar` crate** → Small dependency. Check if it's already transitive. If not, it's ~15KB and well-maintained.
- **Per-rule granularity increases store size** → Each rule gets its own entry instead of one per program. Typical configs have 10-50 rules, so the store stays small.
- **Pending rules are inactive** → A freshly-loaded config with no approvals contributes zero rules to eval. This is the intended security posture but may surprise users. The trust advisory box makes this visible.
- **Change detection by position is imperfect** → Inserting a rule shifts all subsequent positions, causing false "changed" diffs. Acceptable tradeoff — the diff is cosmetic (helps user understand what changed), and the approve/ignore decision is what matters.
