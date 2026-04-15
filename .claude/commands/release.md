Cut a new release tag and push it.

Steps:
1. Run `git fetch --tags` to sync tags from origin.
2. List the 5 most recent tags with `git tag --list --sort=-v:refname | head -5` and show them to the user.
3. Ask the user what tag to use for the next release.
4. Extract the version number from the tag (strip leading `v` if present).
5. Update the `version` field in the root `Cargo.toml` to match.
6. Run `cargo check` to verify the version bump is valid.
7. Stage `Cargo.toml` and `Cargo.lock`, then commit with message: `Bump version to <version>`.
8. Create an annotated tag: `git tag -a <tag> -m "<tag>"`.
9. Push the commit and tag: `git push && git push origin <tag>`.
10. Wait a few seconds, then find the triggered workflow run with `gh run list --workflow=release --limit=1 --json databaseId,url`.
11. Report success with the tag name and the workflow run URL so the user can monitor the build.
