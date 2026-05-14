---
audience: user
bucket: loading
trust-relevant: true
---
# repo-local-config Specification

## Purpose

Discovery layer that merges project-scoped config files from the
current repository or worktree root into the loaded config. Lets
projects ship `.may-i.lisp` (and friends) alongside their source so
that contributors get the same command-authorisation policy without
hand-configuring `MAYI_CONFIG`. Discovered rules are treated as loaded
content and stay inert until approved via `may-i trust` — see
`trust-store` for how repo-local discovery carries provenance and is
gated by the trust store.

## Requirements

### Requirement: Resolver discovers repo-local config files

The config resolver SHALL, after determining the primary config path,
attempt to locate the current repository or worktree root and merge
project-scoped config files from that root into the loaded config.

The repo root is determined by:

1. Invoking `git rev-parse --show-toplevel` against the current
   working directory; if it succeeds and produces an existing path,
   that path is the repo root.
2. Otherwise, walking ancestors of the current working directory
   looking for a `.git`, `.hg`, or `.jj` directory or file. The first
   ancestor containing one of these markers is the repo root.
3. If neither method finds a root, no repo-local discovery occurs and
   the resolver behaves exactly as it does without this layer.

#### Scenario: Repo discovered via git rev-parse
- **GIVEN** the current working directory is inside a git repository
- **AND** `git rev-parse --show-toplevel` returns `/home/u/project`
- **WHEN** the resolver runs
- **THEN** it SHALL look for repo-local config files at
  `/home/u/project`

#### Scenario: Linked worktree root
- **GIVEN** the current working directory is inside a linked worktree
  whose root is `/home/u/project-feature`
- **AND** the main repository is at `/home/u/project`
- **WHEN** `git rev-parse --show-toplevel` is invoked
- **THEN** it SHALL return `/home/u/project-feature`
- **AND** the resolver SHALL discover repo-local files at the
  worktree root, NOT the main repo root

#### Scenario: git unavailable, falls back to marker walk
- **GIVEN** `git` is not on `PATH`
- **AND** the current working directory has an ancestor `/home/u/project`
  containing `.git`
- **WHEN** the resolver runs
- **THEN** it SHALL identify `/home/u/project` as the repo root via
  ancestor walk

#### Scenario: No repo found
- **GIVEN** the current working directory is `/tmp` with no `.git`,
  `.hg`, or `.jj` ancestor
- **WHEN** the resolver runs
- **THEN** discovery SHALL contribute nothing
- **AND** the resolver SHALL produce the same result as if the
  repo-local layer were absent

### Requirement: Discovered file set and order

At the repo root, the resolver SHALL look for the following files,
in this order, and merge any that exist:

1. `.may-i.lisp`
2. `.may-i/**/*.lisp` — all `.lisp` files under the `.may-i/`
   directory, sorted lexically by full path
3. `.may-i.local.lisp`
4. `.claude/may-i.lisp`
5. `.claude/may-i.local.lisp`

Missing files SHALL be silently skipped. The order affects
`reason` tie-breaking only (per `rule-decisions`), since
`Decision` selection is order-independent.

#### Scenario: Only one file present
- **GIVEN** a repo root containing `.may-i.lisp` only
- **WHEN** discovery runs
- **THEN** that single file is loaded as loaded content

#### Scenario: All five locations present
- **GIVEN** a repo root containing all five file types
- **WHEN** discovery runs
- **THEN** all five SHALL be loaded
- **AND** their relative order in the merged rule list SHALL be:
  `.may-i.lisp`, then files under `.may-i/` in lexical order, then
  `.may-i.local.lisp`, then `.claude/may-i.lisp`, then
  `.claude/may-i.local.lisp`

#### Scenario: Glob expansion under .may-i/
- **GIVEN** a repo root containing `.may-i/git.lisp` and
  `.may-i/cargo.lisp`
- **WHEN** discovery runs
- **THEN** both files SHALL be loaded
- **AND** they SHALL appear in lexical order:
  `.may-i/cargo.lisp` before `.may-i/git.lisp`

### Requirement: Resolver layer order

The complete resolver precedence SHALL be:

1. Command-line `--config FILE` (highest priority)
2. `$MAYI_CONFIG`
3. XDG `$XDG_CONFIG_HOME/may-i/config.lisp`
4. Home `~/.config/may-i/config.lisp`

After the primary config is loaded, repo-local discovery (this
capability) SHALL run as a post-load step that adds discovered
files as loaded rules. Discovery does NOT alter selection of the
primary config; it only contributes additional loaded rules.

#### Scenario: --config wins over MAYI_CONFIG
- **GIVEN** both `--config /tmp/a.lisp` and `MAYI_CONFIG=/tmp/b.lisp`
- **WHEN** the resolver runs
- **THEN** the primary config SHALL be `/tmp/a.lisp`

#### Scenario: Repo-local layer always runs after primary selection
- **GIVEN** any primary config selection (CLI flag, env, XDG, or home)
- **WHEN** the resolver runs in a repo
- **THEN** repo-local discovery SHALL run and contribute loaded
  rules in addition to the primary config
