// Shared display helpers for trace output.

/// Shorten a path by replacing the home directory with `~`.
pub fn shorten_home(path: &std::path::Path) -> String {
    let path_str = path.to_string_lossy();
    if let Ok(home) = std::env::var("HOME")
        && let Some(rest) = path_str.strip_prefix(&home) {
            return format!("~{}", rest);
        }
    path_str.to_string()
}
