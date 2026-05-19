Cut a new release tag, push it, and write curated release notes.

## Steps

1. `git fetch --tags`
2. Show 5 most recent: `git tag --list --sort=-v:refname | head -5`
3. Ask user for next tag.
4. Heavy proptest sweep: `PROPTEST_CASES=10000 cargo test --workspace`. Pre-push only runs 256 cases per proptest, so rare inputs (e.g. `$'\n'` ANSI-C quoting) routinely surface only on CI. If this run produces new `proptest-regressions/**` seeds or fails, **abort the release** — commit the seed, fix the bug, then restart `/release`.
5. Bump `version` in root `Cargo.toml` to match (no leading `v`).
6. `cargo check`
7. Commit `Cargo.toml` + `Cargo.lock` with message `Bump version to <version>`.
8. `git tag -a <tag> -m "<tag>"` then `git push && git push origin <tag>`.
9. Find workflow run: `gh run list --workflow=release --limit=1 --json databaseId,url`.
10. Once `gh release view <tag>` succeeds, write curated notes (see below) and apply with `gh release edit <tag> --notes "$(cat <<'EOF' … EOF)"`.
11. Report tag, workflow URL, release URL.

## Release notes format

Study `git log --oneline <prev-tag>..<tag>`. Group commits thematically; omit version bumps, archived OpenSpec changes, and formatting-only commits unless they are the release.

Template:

```markdown
One sentence capturing the theme of the release.

### Theme heading

- **Change name.** Short explanation. Use inline code for forms (`(allow …)`), commands (`may-i fmt`), identifiers.
- **Another change.** …

### Another theme

- …

**Full Changelog**: https://github.com/<org>/<repo>/compare/<prev-tag>...<tag>
```

Typical themes: Configuration language, Trace and pretty-printer, CLI and harness, Internals, Bug fixes, Quality and tooling. Skip themes with no entries.
