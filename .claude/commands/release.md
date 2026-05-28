Cut a release tag, push, write curated notes.

## Steps

1. `git fetch --tags && git tag --list --sort=-v:refname | head -5`
2. Ask user for next version (no leading `v`).
3. `scripts/release.sh <version>`. On failure, fix and rerun — script leaves tree untouched.
4. `gh run list --workflow=release --limit=1 --json databaseId,url`
5. When `gh release view v<version>` succeeds, apply curated notes:
   ```
   gh release edit v<version> --notes "$(cat <<'EOF'
   …
   EOF
   )"
   ```
6. Report tag, workflow URL, release URL.

## Notes format

Study `git log --oneline <prev-tag>..v<version>`. Group thematically. Omit version bumps, archived OpenSpec changes, formatting-only commits.

```markdown
One sentence capturing the release theme.

### Theme heading

- **Change name.** Short explanation. Inline code for forms (`(allow …)`), commands (`may-i fmt`), identifiers.

### Another theme

- …

**Full Changelog**: https://github.com/<org>/<repo>/compare/<prev-tag>...v<version>
```

Typical themes: Configuration language, Trace and pretty-printer, CLI and harness, Internals, Bug fixes, Quality and tooling. Skip empty themes.
