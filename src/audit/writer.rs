// Append-only, best-effort audit writer.
//
// Default location is `$XDG_STATE_HOME/may-i/audit.jsonl`, falling back to
// `~/.local/state/may-i/audit.jsonl`. The directory is created `0700` and the
// file `0600` because the trail records verbatim commands. Each record is one
// complete line emitted in a single append write; POSIX makes that atomic on a
// local filesystem, so concurrent hook processes never interleave partial
// lines (no advisory lock needed). A write failure is swallowed: it must never
// alter a decision, the rendered output, or the exit code.

use std::path::{Path, PathBuf};

/// Resolve the default audit file location from the process environment.
pub fn default_audit_path() -> Option<PathBuf> {
    let xdg = std::env::var("XDG_STATE_HOME")
        .ok()
        .filter(|s| !s.is_empty());
    default_audit_path_from(xdg.as_deref(), dirs::home_dir().as_deref())
}

/// Pure path resolution: `$XDG_STATE_HOME/may-i/audit.jsonl` when set,
/// otherwise `<home>/.local/state/may-i/audit.jsonl`. `None` only when neither
/// is available.
fn default_audit_path_from(xdg_state_home: Option<&str>, home: Option<&Path>) -> Option<PathBuf> {
    let base = match xdg_state_home {
        Some(x) => PathBuf::from(x),
        None => home?.join(".local").join("state"),
    };
    Some(base.join("may-i").join("audit.jsonl"))
}

/// Best-effort append. On any failure the error is dropped — the audit attempt
/// is abandoned silently so it cannot perturb the decision or exit code.
pub fn append_best_effort(path: &Path, line: &str) {
    let _ = append_line(path, line);
}

/// Append one record line (plus a trailing newline) to `path` in a single
/// append write, creating the parent directory (`0700`) and the file (`0600`)
/// if needed. Returns the IO error on failure; callers that must stay
/// decision-neutral go through [`append_best_effort`].
fn append_line(path: &Path, line: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        create_dir_secure(parent)?;
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;

    // One buffer, one write: O_APPEND makes a single write() atomic on a local
    // fs, so concurrent writers don't interleave. `write_all` may loop on a
    // partial write, so this non-interleaving guarantee holds only while the
    // record fits one write() — true for any realistic command (stdin is
    // capped at 64 KiB upstream), well under a page.
    let mut buf = Vec::with_capacity(line.len() + 1);
    buf.extend_from_slice(line.as_bytes());
    buf.push(b'\n');
    std::io::Write::write_all(&mut file, &buf)
}

#[cfg(unix)]
fn create_dir_secure(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if dir.is_dir() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(not(unix))]
fn create_dir_secure(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_path_uses_xdg_state_home_when_set() {
        let p = default_audit_path_from(Some("/xdg/state"), Some(Path::new("/home/u"))).unwrap();
        assert_eq!(p, PathBuf::from("/xdg/state/may-i/audit.jsonl"));
    }

    #[test]
    fn default_path_falls_back_to_home_local_state() {
        let p = default_audit_path_from(None, Some(Path::new("/home/u"))).unwrap();
        assert_eq!(p, PathBuf::from("/home/u/.local/state/may-i/audit.jsonl"));
    }

    #[cfg(unix)]
    #[test]
    fn creates_dir_0700_and_file_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("may-i").join("audit.jsonl");
        append_line(&path, r#"{"v":1}"#).unwrap();

        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "dir mode");
        assert_eq!(file_mode, 0o600, "file mode");

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "{\"v\":1}\n");
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_writers_do_not_interleave() {
        use std::sync::Arc;
        use std::thread;

        let tmp = tempfile::tempdir().unwrap();
        let path = Arc::new(tmp.path().join("audit.jsonl"));

        let writers = 8;
        let per_writer = 50;
        let handles: Vec<_> = (0..writers)
            .map(|w| {
                let path = Arc::clone(&path);
                thread::spawn(move || {
                    for i in 0..per_writer {
                        // A non-trivial line so a torn write would be detectable.
                        let line =
                            format!(r#"{{"writer":{w},"seq":{i},"pad":"xxxxxxxxxxxxxxxxxxxx"}}"#);
                        append_line(&path, &line).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let contents = std::fs::read_to_string(&*path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), writers * per_writer, "all lines present");
        for line in lines {
            let v: serde_json::Value =
                serde_json::from_str(line).unwrap_or_else(|e| panic!("torn line {line:?}: {e}"));
            assert!(v.get("writer").is_some());
        }
    }

    #[test]
    fn default_audit_path_reads_xdg_state_home_env() {
        temp_env::with_var("XDG_STATE_HOME", Some("/xdg/st"), || {
            assert_eq!(
                default_audit_path(),
                Some(PathBuf::from("/xdg/st/may-i/audit.jsonl"))
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn append_best_effort_writes_on_success() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        append_best_effort(&path, r#"{"v":1}"#);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"v\":1}\n");
    }

    #[cfg(unix)]
    #[test]
    fn unwritable_target_errors_but_best_effort_swallows() {
        // A path whose parent is a regular file cannot be created.
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("not-a-dir");
        std::fs::write(&blocker, b"x").unwrap();
        let path = blocker.join("audit.jsonl");

        assert!(append_line(&path, "{}").is_err(), "write should fail");
        // Best-effort variant must not panic or propagate.
        append_best_effort(&path, "{}");
    }
}
