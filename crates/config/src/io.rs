// Configuration IO — file discovery, loading, and starter config creation.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use may_i_core::ast::Provenance;
use may_i_sexpr::Sexpr;
use miette::{Context, IntoDiagnostic};

/// Result of loading a config file, separating core config from load metadata.
#[derive(Debug)]
pub struct LoadResult {
    pub config: may_i_core::ast::Config,
    pub source_text: Option<String>,
    pub pre_migration_forms: Option<Vec<(may_i_core::Span, may_i_core::Doc)>>,
    pub config_path: PathBuf,
}

/// Load and parse a config file at the given path.
///
/// Reads the file, expands any `(load ...)` directives (recursively with cycle
/// detection), attempts legacy migration per-file, then parses into Config.
pub fn load(path: &Path) -> miette::Result<LoadResult> {
    let content = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to read {}", path.display()))?;

    let config_path = path.to_path_buf();

    // Seed the seen set with the root file for cycle detection.
    let canonical = path
        .canonicalize()
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to canonicalize {}", path.display()))?;
    let mut seen = HashSet::new();
    seen.insert(canonical.clone());

    let base_dir = path
        .parent()
        .ok_or_else(|| miette::miette!("cannot determine parent dir of {}", path.display()))?;

    let filename = path.display().to_string();

    // Try canonical parse first to get sexprs.
    let (forms, parse_errors) = may_i_sexpr::parse(&content);
    if parse_errors.is_empty() {
        // Expand loads, then parse config with provenance tagging.
        let expanded = expand_loads(forms, base_dir, &mut seen, Provenance::PrimaryConfig)?;
        match crate::config::parse_config_from_tagged_sexprs(&expanded) {
            Ok(config) => {
                return Ok(LoadResult {
                    config,
                    source_text: Some(content),
                    pre_migration_forms: None,
                    config_path,
                });
            }
            Err(config_err) => {
                // Config parsing failed — try migration before giving up.
                // Use a fresh `seen` so re-expansion of `(load …)` on the
                // migrated forms is not blocked by the failed attempt above.
                let mut retry_seen = HashSet::new();
                retry_seen.insert(canonical.clone());
                match try_migrate_and_parse(&content, &config_path, base_dir, &mut retry_seen) {
                    Some(result) => return Ok(result),
                    None => {
                        return Err(
                            crate::ConfigError::from_raw(config_err, &content, &filename).into(),
                        );
                    }
                }
            }
        }
    }

    // Sexpr parse itself failed — try migration from legacy syntax.
    match try_migrate_and_parse(&content, &config_path, base_dir, &mut seen) {
        Some(result) => Ok(result),
        None => Err(crate::ConfigError::from_raw(
            parse_errors.into_iter().next().unwrap(),
            &content,
            &filename,
        )
        .into()),
    }
}

/// Attempt to parse a config by migrating legacy CST forms to canonical syntax.
///
/// Returns `Some(config)` if migration succeeds, `None` otherwise.
fn try_migrate_and_parse(
    content: &str,
    config_path: &Path,
    base_dir: &Path,
    seen: &mut HashSet<PathBuf>,
) -> Option<LoadResult> {
    let (cst_nodes, cst_errors) = may_i_sexpr::parse_cst(content);
    if !cst_errors.is_empty() {
        return None;
    }

    // Capture pre-migration Doc trees before rewriting.
    let pre_migration_forms: Vec<(may_i_core::Span, may_i_core::Doc)> = cst_nodes
        .iter()
        .map(|node| (node.ann.span, node.to_doc()))
        .collect();

    let migrated = crate::migrate::migrate_forms(cst_nodes);
    let sexprs: Vec<_> = migrated.iter().map(|n| n.to_sexpr()).collect();

    let expanded = expand_loads(sexprs, base_dir, seen, Provenance::PrimaryConfig).ok()?;
    let config = crate::config::parse_config_from_tagged_sexprs(&expanded).ok()?;
    Some(LoadResult {
        config,
        source_text: Some(content.to_string()),
        pre_migration_forms: Some(pre_migration_forms),
        config_path: config_path.to_path_buf(),
    })
}

/// Extract and validate the string argument from a `(load ...)` sexpr.
///
/// Requires exactly one argument which must be a string literal.
fn parse_load_arg(list: &[Sexpr]) -> miette::Result<&str> {
    // list[0] is "load", args are list[1..]
    let args = &list[1..];
    match args.len() {
        0 => miette::bail!("load requires a path argument"),
        1 => match args[0].as_str() {
            Some(s) => Ok(s),
            None => miette::bail!("load argument must be a string, got: {}", args[0]),
        },
        _ => miette::bail!("load takes exactly one argument, got {}", args.len()),
    }
}

/// Read a file, parse to sexprs, and attempt migration if canonical parsing fails.
///
/// Returns the sexprs ready for further expansion. Each file independently
/// attempts legacy migration, matching the behaviour of `load()`.
fn load_file_sexprs(path: &Path) -> miette::Result<Vec<Sexpr>> {
    let content = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to read {}", path.display()))?;

    let filename = path.display().to_string();

    // Try sexpr parse first.
    let (forms, parse_errors) = may_i_sexpr::parse(&content);
    if parse_errors.is_empty() {
        // Sexprs parsed fine — check if they're valid config forms (ignoring
        // load forms which will be expanded later).
        let non_load: Vec<_> = forms
            .iter()
            .filter(|f| {
                f.as_list()
                    .and_then(|l| l.first())
                    .and_then(|t| t.as_atom())
                    != Some("load")
            })
            .cloned()
            .collect();

        if non_load.is_empty() || crate::parse_config_from_sexprs(&non_load).is_ok() {
            return Ok(forms);
        }

        // Config parsing failed — fall through to migration.
    }

    // Try migration from legacy syntax.
    let (cst_nodes, cst_errors) = may_i_sexpr::parse_cst(&content);
    if !cst_errors.is_empty() {
        let err = parse_errors.into_iter().next().unwrap();
        return Err(crate::ConfigError::from_raw(err, &content, &filename).into());
    }

    let migrated = crate::migrate::migrate_forms(cst_nodes);
    let sexprs: Vec<_> = migrated.iter().map(|n| n.to_sexpr()).collect();

    // Verify migrated forms parse as a config.
    if crate::parse_config_from_sexprs(&sexprs).is_err() {
        if let Some(err) = parse_errors.into_iter().next() {
            return Err(crate::ConfigError::from_raw(err, &content, &filename).into());
        }
        miette::bail!("failed to parse {}", filename);
    }

    crate::record_advisory(format!(
        "warning: {} uses deprecated syntax and was auto-migrated",
        path.display()
    ));
    Ok(sexprs)
}

/// Walk the `(load …)` graph rooted at `start`, returning every reachable
/// file path in load order (root first). Globs are expanded; cycles are
/// dedupped via canonical paths.
///
/// The walker skips files that fail to read or parse — those will surface
/// as errors when the migration tool tries to process them.
pub fn walk_load_graph(start: &Path) -> miette::Result<Vec<PathBuf>> {
    let canonical = start
        .canonicalize()
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to canonicalize {}", start.display()))?;
    let mut seen = HashSet::new();
    seen.insert(canonical.clone());
    let mut result: Vec<PathBuf> = vec![canonical];
    walk_into(start, &mut seen, &mut result)?;
    Ok(result)
}

fn walk_into(
    file: &Path,
    seen: &mut HashSet<PathBuf>,
    result: &mut Vec<PathBuf>,
) -> miette::Result<()> {
    let Ok(content) = std::fs::read_to_string(file) else {
        return Ok(());
    };
    let (forms, _errors) = may_i_sexpr::parse(&content);
    let base_dir = file
        .parent()
        .ok_or_else(|| miette::miette!("cannot determine parent dir of {}", file.display()))?;
    for form in &forms {
        let Some(list) = form.as_list() else {
            continue;
        };
        if list.is_empty() || list[0].as_atom() != Some("load") {
            continue;
        }
        let pattern_str = parse_load_arg(list)?;
        let resolved = if Path::new(pattern_str).is_absolute() {
            pattern_str.to_string()
        } else {
            base_dir.join(pattern_str).display().to_string()
        };
        let matches: Vec<PathBuf> = if is_glob_pattern(&resolved) {
            let mut m: Vec<PathBuf> = glob::glob(&resolved)
                .into_diagnostic()
                .wrap_err_with(|| format!("invalid glob pattern: {resolved}"))?
                .filter_map(|e| e.ok())
                .collect();
            m.sort();
            m
        } else {
            let p = PathBuf::from(&resolved);
            if p.exists() { vec![p] } else { vec![] }
        };
        for path in matches {
            let canonical = match path.canonicalize() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if seen.insert(canonical.clone()) {
                result.push(canonical.clone());
                walk_into(&path, seen, result)?;
            }
        }
    }
    Ok(())
}

/// Returns true if the pattern contains glob metacharacters.
fn is_glob_pattern(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

/// Expand all `(load ...)` forms in a list of sexprs, tagging each with provenance.
///
/// Forms from the current level keep `current_provenance`. Forms from loaded
/// files get `Loaded` provenance. Glob patterns are expanded with lexical sort
/// order. Cycle detection uses a set of canonical paths.
fn expand_loads(
    forms: Vec<Sexpr>,
    base_dir: &Path,
    seen: &mut HashSet<PathBuf>,
    current_provenance: Provenance,
) -> miette::Result<Vec<(Sexpr, Provenance)>> {
    let mut result = Vec::new();

    for form in &forms {
        let list = match form.as_list() {
            Some(l) if !l.is_empty() && l[0].as_atom() == Some("load") => l,
            _ => {
                result.push((form.clone(), current_provenance.clone()));
                continue;
            }
        };

        let pattern_str = parse_load_arg(list)?;

        // Resolve path relative to containing file's directory.
        let resolved_pattern = if Path::new(pattern_str).is_absolute() {
            pattern_str.to_string()
        } else {
            base_dir.join(pattern_str).display().to_string()
        };

        if is_glob_pattern(&resolved_pattern) {
            // Glob expansion.
            let mut matches: Vec<PathBuf> = glob::glob(&resolved_pattern)
                .into_diagnostic()
                .wrap_err_with(|| format!("invalid glob pattern: {resolved_pattern}"))?
                .filter_map(|entry| entry.ok())
                .collect();
            matches.sort();

            if matches.is_empty() {
                crate::record_advisory(format!(
                    "warning: load pattern matched no files: {pattern_str}"
                ));
                continue;
            }

            for path in matches {
                let canonical = path
                    .canonicalize()
                    .into_diagnostic()
                    .wrap_err_with(|| format!("Failed to canonicalize {}", path.display()))?;

                if !seen.insert(canonical.clone()) {
                    miette::bail!("circular load detected: {}", path.display());
                }

                let child_sexprs = load_file_sexprs(&path)?;
                let child_dir = path.parent().ok_or_else(|| {
                    miette::miette!("cannot determine parent dir of {}", path.display())
                })?;
                let expanded = expand_loads(
                    child_sexprs,
                    child_dir,
                    seen,
                    Provenance::Loaded { path: canonical },
                )?;
                result.extend(expanded);
            }
        } else {
            // Literal file path.
            let path = PathBuf::from(&resolved_pattern);
            if !path.exists() {
                miette::bail!("loaded file not found: {}", path.display());
            }

            let canonical = path
                .canonicalize()
                .into_diagnostic()
                .wrap_err_with(|| format!("Failed to canonicalize {}", path.display()))?;

            if !seen.insert(canonical.clone()) {
                miette::bail!("circular load detected: {}", path.display());
            }

            let child_sexprs = load_file_sexprs(&path)?;
            let child_dir = path.parent().ok_or_else(|| {
                miette::miette!("cannot determine parent dir of {}", path.display())
            })?;
            let expanded = expand_loads(
                child_sexprs,
                child_dir,
                seen,
                Provenance::Loaded { path: canonical },
            )?;
            result.extend(expanded);
        }
    }

    Ok(result)
}

/// Load and resolve a config file: resolve path, parse, and validate named predicates.
///
/// This is the standard config loading pipeline shared by eval, check, and hook commands.
/// After loading the primary config, repo-local discovery (per the
/// `repo-local-config` capability) attempts to find additional `Loaded`
/// rules from project-scoped files and splices them in.
pub fn load_and_resolve(override_path: Option<&Path>) -> miette::Result<LoadResult> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    load_and_resolve_with_cwd(override_path, &cwd)
}

/// Like [`load_and_resolve`] but uses an explicit `cwd` for repo-local
/// discovery instead of `std::env::current_dir()`. Test entry point.
pub(crate) fn load_and_resolve_with_cwd(
    override_path: Option<&Path>,
    cwd: &Path,
) -> miette::Result<LoadResult> {
    let config_file = resolve_path(override_path)?;
    let mut result = load(&config_file)?;
    splice_repo_local(&mut result, cwd)?;
    let resolved_rules =
        crate::resolve::validate_and_resolve(&result.config.rules, &result.config.defines)
            .map_err(|errs| miette::miette!("Predicate resolution failed: {}", errs[0].message))?;
    result.config.rules = resolved_rules;
    Ok(result)
}

/// Run repo-local discovery from `cwd` and splice any discovered files
/// into the loaded config as `Loaded` rules.
///
/// Files already present (transitively) in the primary load tree are
/// skipped via canonical-path dedup so a discovered file that the
/// primary already loaded is not double-counted.
fn splice_repo_local(result: &mut LoadResult, cwd: &Path) -> miette::Result<()> {
    let Some(repo_root) = discover_repo_root(cwd) else {
        return Ok(());
    };
    let files = discover_repo_local_files(&repo_root);
    if files.is_empty() {
        return Ok(());
    }

    let mut seen: HashSet<PathBuf> = HashSet::new();
    if let Ok(p) = result.config_path.canonicalize() {
        seen.insert(p);
    }
    for rule in &result.config.rules {
        if let Some(p) = rule.provenance.path() {
            seen.insert(p.to_path_buf());
        }
    }
    for define in &result.config.defines {
        if let Some(p) = define.provenance.path() {
            seen.insert(p.to_path_buf());
        }
    }

    for file in files {
        let canonical = match file.canonicalize() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if !seen.insert(canonical.clone()) {
            continue;
        }

        let sexprs = load_file_sexprs(&canonical)?;
        let parent = canonical.parent().ok_or_else(|| {
            miette::miette!("cannot determine parent dir of {}", canonical.display())
        })?;
        let expanded = expand_loads(
            sexprs,
            parent,
            &mut seen,
            Provenance::Loaded {
                path: canonical.clone(),
            },
        )?;
        let extra = crate::config::parse_config_from_tagged_sexprs(&expanded).map_err(|e| {
            miette::miette!(
                "failed to parse repo-local file {}: {}",
                canonical.display(),
                e.message,
            )
        })?;
        merge_config(&mut result.config, extra);
    }
    Ok(())
}

/// Append every rule, define, security entry, parser, and style spec
/// from `extra` into `target`. Rules and defines preserve source order.
fn merge_config(target: &mut may_i_core::ast::Config, extra: may_i_core::ast::Config) {
    target.rules.extend(extra.rules);
    target.defines.extend(extra.defines);
    target.checks.extend(extra.checks);
    for spec in extra.style_specs {
        if !crate::prelude::prelude_style_specs()
            .iter()
            .any(|p| p.name == spec.name)
        {
            target.style_specs.push(spec);
        }
    }
    for parser in extra.parsers {
        if !crate::prelude::prelude_parsers()
            .iter()
            .any(|p| p.program == parser.program)
        {
            target.parsers.push(parser);
        }
    }
    // A merged file's entries are loaded from the target's perspective,
    // whichever set they parsed into — they stay under the
    // `:safe-env-vars` trust scope.
    let mut any_loaded = extra.security.has_loaded_env_vars;
    for var in extra
        .security
        .safe_env_vars
        .into_iter()
        .chain(extra.security.loaded_safe_env_vars)
    {
        target.security.loaded_safe_env_vars.insert(var);
        any_loaded = true;
    }
    if any_loaded {
        target.security.has_loaded_env_vars = true;
    }
    // `(env …)` and `(redirect …)` capabilities from a merged file are
    // loaded from the target's perspective, whichever set they parsed into;
    // they stay under their per-axis trust scope (`:env` / `:redirect`).
    let any_env_cap = extra.security.has_loaded_env_caps || !extra.security.env_caps.is_empty();
    target
        .security
        .loaded_env_caps
        .extend(extra.security.env_caps);
    target
        .security
        .loaded_env_caps
        .extend(extra.security.loaded_env_caps);
    if any_env_cap {
        target.security.has_loaded_env_caps = true;
    }
    let any_redirect_cap =
        extra.security.has_loaded_redirect_caps || !extra.security.redirect_caps.is_empty();
    target
        .security
        .loaded_redirect_caps
        .extend(extra.security.redirect_caps);
    target
        .security
        .loaded_redirect_caps
        .extend(extra.security.loaded_redirect_caps);
    if any_redirect_cap {
        target.security.has_loaded_redirect_caps = true;
    }
}

/// Discover the repository root containing `cwd`, if any.
///
/// Tries `git rev-parse --show-toplevel` first (handles linked
/// worktrees correctly). On failure walks ancestors of `cwd` looking
/// for a `.git`, `.hg`, or `.jj` marker.
pub(crate) fn discover_repo_root(cwd: &Path) -> Option<PathBuf> {
    if let Some(root) = git_show_toplevel(cwd) {
        return Some(root);
    }
    marker_walk(cwd)
}

fn git_show_toplevel(cwd: &Path) -> Option<PathBuf> {
    let mut cmd = std::process::Command::new("git");
    cmd.args(["rev-parse", "--show-toplevel"]).current_dir(cwd);
    // Scrub inherited git environment so the spawned `git` resolves
    // the repo from `cwd`, not from whatever ambient git context the
    // parent process was invoked under. Pre-commit hooks export
    // `GIT_DIR`, `GIT_INDEX_FILE` and friends; those take precedence
    // over `current_dir(...)` and would otherwise make the child
    // ignore `cwd` and report the hosting repo's toplevel (or, with a
    // linked-worktree `GIT_DIR`, just echo `cwd` back). Both break
    // tempdir-based discovery callers and any production use from
    // inside a hook.
    for var in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
        "GIT_CEILING_DIRECTORIES",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_NAMESPACE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_PREFIX",
    ] {
        cmd.env_remove(var);
    }
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return None;
    }
    let path = PathBuf::from(trimmed);
    path.is_dir().then_some(path)
}

fn marker_walk(cwd: &Path) -> Option<PathBuf> {
    let mut current = cwd
        .canonicalize()
        .ok()
        .or_else(|| Some(cwd.to_path_buf()))?;
    loop {
        for marker in [".git", ".hg", ".jj"] {
            if current.join(marker).exists() {
                return Some(current);
            }
        }
        if !current.pop() {
            return None;
        }
    }
}

/// List the project-scoped config files at `repo_root` that exist on
/// disk, in the documented discovery order. Missing files are skipped.
pub(crate) fn discover_repo_local_files(repo_root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let direct = repo_root.join(".may-i.lisp");
    if direct.is_file() {
        out.push(direct);
    }
    let dir = repo_root.join(".may-i");
    if dir.is_dir() {
        let pattern = dir.join("**/*.lisp").display().to_string();
        if let Ok(matches) = glob::glob(&pattern) {
            let mut paths: Vec<PathBuf> = matches.filter_map(Result::ok).collect();
            paths.sort();
            out.extend(paths);
        }
    }
    let local = repo_root.join(".may-i.local.lisp");
    if local.is_file() {
        out.push(local);
    }
    let claude = repo_root.join(".claude/may-i.lisp");
    if claude.is_file() {
        out.push(claude);
    }
    let claude_local = repo_root.join(".claude/may-i.local.lisp");
    if claude_local.is_file() {
        out.push(claude_local);
    }
    out
}

/// Resolve the config file path.
///
/// If `override_path` is provided it takes precedence, then `$MAYI_CONFIG`,
/// then `$XDG_CONFIG_HOME/may-i/config.lisp` or `~/.config/may-i/config.lisp`.
/// Creates a starter config if no file exists at the default location.
pub fn resolve_path(override_path: Option<&Path>) -> miette::Result<PathBuf> {
    match override_path {
        Some(p) => {
            if !p.exists() {
                miette::bail!("Config file not found: {}", p.display());
            }
            Ok(p.to_path_buf())
        }
        None => match env_or_default_path()? {
            Some(path) => Ok(path),
            None => {
                let path = default_config_path()
                    .ok_or_else(|| miette::miette!("cannot determine config directory"))?;
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .into_diagnostic()
                        .wrap_err_with(|| format!("Failed to create {}", parent.display()))?;
                }
                std::fs::write(&path, include_str!("starter_config.lisp"))
                    .into_diagnostic()
                    .wrap_err_with(|| format!("Failed to write {}", path.display()))?;
                crate::record_advisory(format!("Created starter config at {}", path.display()));
                Ok(path)
            }
        },
    }
}

/// Find an existing config file: `$MAYI_CONFIG` then XDG/default.
///
/// Returns `Err` when `MAYI_CONFIG` is set but the path does not exist.
/// Returns `Ok(None)` when no config file is found via env or default.
fn env_or_default_path() -> miette::Result<Option<PathBuf>> {
    if let Ok(p) = std::env::var("MAYI_CONFIG") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Ok(Some(path));
        }
        miette::bail!("MAYI_CONFIG points to nonexistent file: {}", path.display());
    }
    Ok(default_config_path().filter(|p| p.exists()))
}

/// The preferred config path (XDG or ~/.config fallback).
fn default_config_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg).join("may-i/config.lisp"));
    }
    dirs::home_dir().map(|h| h.join(".config/may-i/config.lisp"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_success() {
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(temp_file, r#"(safe-env-vars "HOME")"#).unwrap();
        let result = load(temp_file.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_file_not_found() {
        let path = PathBuf::from("/nonexistent/path/config.lisp");
        let result = load(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_parse_error() {
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(temp_file, "(invalid").unwrap();
        let result = load(temp_file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_load_legacy_wrapper_config_succeeds() {
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            r#"(wrapper "ssh" (positional [:host *] :command+args))"#
        )
        .unwrap();
        let result = load(temp_file.path());
        assert!(result.is_ok(), "legacy config should load via migration");
    }

    #[test]
    fn test_load_canonical_config_skips_migration() {
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            r#"(rule "git" (and (positional "status") (allow)))"#
        )
        .unwrap();
        let result = load(temp_file.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_invalid_config_returns_original_error() {
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(temp_file, "(unknown-form)").unwrap();
        let result = load(temp_file.path());
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("unknown top-level form"),
            "should return original error, got: {err_msg}"
        );
    }

    #[test]
    fn test_migrated_config_preserves_spans_for_error_reporting() {
        // A legacy config with a valid wrapper followed by an unknown form.
        // The wrapper should migrate fine, but the unknown form should cause
        // an error whose span points to the correct position in the original source.
        let input = r#"(wrapper "ssh" (positional [:host *] :command+args))
(bad-form)"#;

        let (cst_nodes, errors) = may_i_sexpr::parse_cst(input);
        assert!(errors.is_empty());

        let migrated = crate::migrate::migrate_forms(cst_nodes);
        let sexprs: Vec<_> = migrated.iter().map(|n| n.to_sexpr()).collect();

        let err = crate::parse_config_from_sexprs(&sexprs).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown top-level form"),
            "expected 'unknown top-level form', got: {msg}"
        );

        // The span should point into the original source text where "bad-form" is.
        let bad_form_offset = input.find("bad-form").unwrap();
        assert!(
            err.span.start >= bad_form_offset
                && err.span.start < bad_form_offset + "bad-form".len(),
            "span start {} should be within bad-form at offset {}",
            err.span.start,
            bad_form_offset
        );
    }

    #[test]
    fn test_spans_flow_through_cst_migrate_sexpr_ast() {
        // Verify spans are preserved through the full chain for a valid legacy config.
        let input = r#"(wrapper "ssh" (positional [:host *] :command+args))"#;

        let (cst_nodes, errors) = may_i_sexpr::parse_cst(input);
        assert!(errors.is_empty());

        // Verify CST node spans point into the original source
        let original_span = cst_nodes[0].ann.span;
        assert_eq!(original_span.start, 0);

        let migrated = crate::migrate::migrate_forms(cst_nodes);
        let sexprs: Vec<_> = migrated.iter().map(|n| n.to_sexpr()).collect();

        // The migrated forms should parse successfully
        let config = crate::parse_config_from_sexprs(&sexprs).unwrap();
        assert!(!config.rules.is_empty(), "should have at least one rule");
    }

    #[test]
    fn test_resolve_path_with_override() {
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(temp_file, r#"(safe-env-vars "HOME")"#).unwrap();
        let result = resolve_path(Some(temp_file.path()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), temp_file.path());
    }

    #[test]
    fn test_resolve_path_override_not_found() {
        let path = PathBuf::from("/nonexistent/path/config.lisp");
        let result = resolve_path(Some(&path));
        assert!(result.is_err());
    }

    #[test]
    fn test_env_or_default_path_with_mayi_config() {
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(temp_file, r#"(safe-env-vars "HOME")"#).unwrap();

        temp_env::with_var("MAYI_CONFIG", Some(temp_file.path().as_os_str()), || {
            let result = env_or_default_path().unwrap();
            assert_eq!(result, Some(temp_file.path().to_path_buf()));
        });
    }

    #[test]
    fn test_env_or_default_path_nonexistent_mayi_config_errors() {
        temp_env::with_var("MAYI_CONFIG", Some("/nonexistent/path/config.lisp"), || {
            let result = env_or_default_path();
            assert!(
                result.is_err(),
                "should error when MAYI_CONFIG points to nonexistent file"
            );
            let err_msg = format!("{}", result.unwrap_err());
            assert!(
                err_msg.contains("/nonexistent/path/config.lisp"),
                "error should contain the path, got: {err_msg}"
            );
        });
    }

    #[test]
    fn test_default_config_path_with_xdg() {
        temp_env::with_var("XDG_CONFIG_HOME", Some("/tmp/xdg_test"), || {
            let result = default_config_path();
            assert!(result.is_some());
        });
    }

    #[test]
    fn test_default_config_path_without_xdg() {
        temp_env::with_var("XDG_CONFIG_HOME", None::<&str>, || {
            let _result = default_config_path();
        });
    }

    // --- Load directive tests ---

    fn write_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn load_single_file_splices_forms() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "rules.lisp", r#"(rule "echo" (allow "safe"))"#);
        let root = write_file(
            dir.path(),
            "config.lisp",
            r#"(safe-env-vars "HOME")
(load "rules.lisp")"#,
        );
        let result = load(&root).unwrap();
        assert_eq!(result.config.rules.len(), 1);
        assert!(result.config.security.safe_env_vars.contains("HOME"));
    }

    #[test]
    fn load_glob_multiple_files_in_lexical_order() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "rules/02-git.lisp",
            r#"(rule "git" (allow "git"))"#,
        );
        write_file(
            dir.path(),
            "rules/01-echo.lisp",
            r#"(rule "echo" (allow "echo"))"#,
        );
        let root = write_file(dir.path(), "config.lisp", r#"(load "rules/*.lisp")"#);
        let result = load(&root).unwrap();
        assert_eq!(result.config.rules.len(), 2);
        // Lexical order: 01-echo before 02-git
        // Lexical order: 01-echo before 02-git
        assert!(
            result.config.rules[0]
                .command_effect
                .value
                .matches_command("echo")
        );
        assert!(
            result.config.rules[1]
                .command_effect
                .value
                .matches_command("git")
        );
    }

    #[test]
    fn load_glob_zero_matches_warns_not_errors() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_file(
            dir.path(),
            "config.lisp",
            r#"(safe-env-vars "HOME")
(load "nonexistent/*.lisp")"#,
        );
        // Should succeed with just the safe-env-vars
        let result = load(&root).unwrap();
        assert!(result.config.security.safe_env_vars.contains("HOME"));
    }

    #[test]
    fn load_paths_relative_to_containing_file() {
        let dir = tempfile::tempdir().unwrap();
        // nested: rules/main.lisp loads sub/extra.lisp
        write_file(
            dir.path(),
            "rules/sub/extra.lisp",
            r#"(rule "cat" (allow "cat"))"#,
        );
        write_file(
            dir.path(),
            "rules/main.lisp",
            r#"(rule "echo" (allow "echo"))
(load "sub/extra.lisp")"#,
        );
        let root = write_file(dir.path(), "config.lisp", r#"(load "rules/main.lisp")"#);
        let result = load(&root).unwrap();
        assert_eq!(result.config.rules.len(), 2);
    }

    #[test]
    fn load_circular_detected() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "a.lisp", r#"(load "b.lisp")"#);
        write_file(dir.path(), "b.lisp", r#"(load "a.lisp")"#);
        let root = dir.path().join("a.lisp");
        let result = load(&root);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("circular load"), "got: {msg}");
    }

    #[test]
    fn load_self_referential_detected() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_file(dir.path(), "config.lisp", r#"(load "config.lisp")"#);
        let result = load(&root);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("circular load"), "got: {msg}");
    }

    #[test]
    fn load_legacy_file_is_migrated() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "legacy.lisp",
            r#"(wrapper "ssh" (positional [:host *] :command+args))"#,
        );
        let root = write_file(dir.path(), "config.lisp", r#"(load "legacy.lisp")"#);
        let result = load(&root);
        assert!(
            result.is_ok(),
            "legacy loaded file should migrate: {:?}",
            result.err()
        );
    }

    #[test]
    fn load_missing_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_file(dir.path(), "config.lisp", r#"(load "nonexistent.lisp")"#);
        let result = load(&root);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("not found"), "got: {msg}");
    }

    #[test]
    fn load_no_args_errors() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_file(dir.path(), "config.lisp", r#"(load)"#);
        let result = load(&root);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("requires a path"), "got: {msg}");
    }

    #[test]
    fn load_too_many_args_errors() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_file(dir.path(), "config.lisp", r#"(load "a.lisp" "b.lisp")"#);
        let result = load(&root);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("exactly one"), "got: {msg}");
    }

    #[test]
    fn load_non_string_arg_errors() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_file(dir.path(), "config.lisp", r#"(load foo)"#);
        let result = load(&root);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("must be a string"), "got: {msg}");
    }

    // --- Provenance tests ---

    #[test]
    fn root_config_rules_get_primary_config_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_file(dir.path(), "config.lisp", r#"(rule "git" (allow))"#);
        let result = load(&root).unwrap();
        assert_eq!(result.config.rules.len(), 1);
        assert_eq!(result.config.rules[0].provenance, Provenance::PrimaryConfig);
    }

    #[test]
    fn root_config_defines_get_primary_config_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_file(
            dir.path(),
            "config.lisp",
            r#"(define safe-cmd (positional "status"))"#,
        );
        let result = load(&root).unwrap();
        assert_eq!(result.config.defines.len(), 1);
        assert_eq!(
            result.config.defines[0].provenance,
            Provenance::PrimaryConfig
        );
    }

    #[test]
    fn loaded_file_rules_get_loaded_provenance() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "rules.lisp", r#"(rule "echo" (allow))"#);
        let root = write_file(
            dir.path(),
            "config.lisp",
            r#"(rule "git" (allow))
(load "rules.lisp")"#,
        );
        let result = load(&root).unwrap();
        assert_eq!(result.config.rules.len(), 2);
        assert_eq!(
            result.config.rules[0].provenance,
            Provenance::PrimaryConfig,
            "root rule should be PrimaryConfig"
        );
        assert!(
            result.config.rules[1].provenance.is_loaded(),
            "loaded rule should be Loaded"
        );
    }

    #[test]
    fn loaded_file_defines_get_loaded_provenance() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "defs.lisp",
            r#"(define remote-cmd (fact? :via/ssh))"#,
        );
        let root = write_file(
            dir.path(),
            "config.lisp",
            r#"(define local-cmd (fact? :via/local))
(load "defs.lisp")"#,
        );
        let result = load(&root).unwrap();
        assert_eq!(result.config.defines.len(), 2);
        assert_eq!(
            result.config.defines[0].provenance,
            Provenance::PrimaryConfig
        );
        assert!(result.config.defines[1].provenance.is_loaded());
    }

    #[test]
    fn recursively_loaded_rules_get_loaded_provenance() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "inner.lisp", r#"(rule "cat" (allow))"#);
        write_file(
            dir.path(),
            "outer.lisp",
            r#"(rule "echo" (allow))
(load "inner.lisp")"#,
        );
        let root = write_file(dir.path(), "config.lisp", r#"(load "outer.lisp")"#);
        let result = load(&root).unwrap();
        assert_eq!(result.config.rules.len(), 2);
        assert!(
            result.config.rules[0].provenance.is_loaded(),
            "outer loaded rule should be Loaded"
        );
        assert!(
            result.config.rules[1].provenance.is_loaded(),
            "recursively loaded rule should be Loaded"
        );
    }

    #[test]
    fn loaded_rule_records_source_file_path() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "rules.lisp", r#"(rule "echo" (allow))"#);
        let root = write_file(dir.path(), "config.lisp", r#"(load "rules.lisp")"#);
        let result = load(&root).unwrap();
        let path = result.config.rules[0]
            .provenance
            .path()
            .expect("should have path");
        let expected = dir.path().join("rules.lisp").canonicalize().unwrap();
        assert_eq!(path, expected);
    }

    #[test]
    fn loaded_define_records_source_file_path() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            "defs.lisp",
            r#"(define remote-cmd (fact? :via/ssh))"#,
        );
        let root = write_file(dir.path(), "config.lisp", r#"(load "defs.lisp")"#);
        let result = load(&root).unwrap();
        let path = result.config.defines[0]
            .provenance
            .path()
            .expect("should have path");
        let expected = dir.path().join("defs.lisp").canonicalize().unwrap();
        assert_eq!(path, expected);
    }

    #[test]
    fn recursively_loaded_rules_record_their_own_file_path() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "inner.lisp", r#"(rule "cat" (allow))"#);
        write_file(
            dir.path(),
            "outer.lisp",
            r#"(rule "echo" (allow))
(load "inner.lisp")"#,
        );
        let root = write_file(dir.path(), "config.lisp", r#"(load "outer.lisp")"#);
        let result = load(&root).unwrap();

        let outer_path = result.config.rules[0].provenance.path().unwrap();
        let inner_path = result.config.rules[1].provenance.path().unwrap();

        let expected_outer = dir.path().join("outer.lisp").canonicalize().unwrap();
        let expected_inner = dir.path().join("inner.lisp").canonicalize().unwrap();

        assert_eq!(
            outer_path, expected_outer,
            "rule from outer.lisp should point to outer.lisp"
        );
        assert_eq!(
            inner_path, expected_inner,
            "rule from inner.lisp should point to inner.lisp"
        );
    }

    // --- Repo-local discovery tests ---

    /// Write a minimal but valid `.git/` so that `git rev-parse
    /// --show-toplevel` cannot fall through to a parent repo.
    ///
    /// An empty `.git/` directory is implementation-defined input to git —
    /// some versions accept it as a toplevel marker, some reject it and let
    /// discovery walk into an ancestor. Writing `HEAD` and `config` gives
    /// git the minimum it accepts as a valid repo without forking `git init`.
    fn init_git(path: &Path) {
        let git_dir = path.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(
            git_dir.join("config"),
            "[core]\n\trepositoryformatversion = 0\n",
        )
        .unwrap();
    }

    #[test]
    fn discover_repo_root_finds_marker_via_walk() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        init_git(&root);
        let nested = root.join("a/b/c");
        std::fs::create_dir_all(&nested).unwrap();
        // Use marker walk by passing a deep cwd; git may also find it but
        // either resolves to the same path.
        let found = discover_repo_root(&nested).unwrap();
        let canonical_found = found.canonicalize().unwrap();
        assert_eq!(canonical_found, root);
    }

    #[test]
    fn discover_repo_root_returns_inner_when_ancestor_is_also_a_repo() {
        // Simulate `$TMPDIR` itself being inside another git repo: outer is a
        // valid repo, inner is a nested fixture also init'd as a repo.
        // `discover_repo_root(inner)` MUST return inner, not outer, regardless
        // of git version. Before fixing `init_git` to write HEAD + config,
        // some git versions would reject the empty `.git/` in inner and walk
        // up to outer.
        let outer = tempfile::tempdir().unwrap();
        let outer_root = outer.path().canonicalize().unwrap();
        init_git(&outer_root);
        let inner = outer_root.join("a/b");
        std::fs::create_dir_all(&inner).unwrap();
        init_git(&inner);

        let found = discover_repo_root(&inner).unwrap();
        assert_eq!(
            found.canonicalize().unwrap(),
            inner.canonicalize().unwrap(),
            "discovery must stop at the inner repo, not walk up to the ancestor"
        );
    }

    /// Lock for env-mutating tests. Modifying process env is global
    /// state; any test that touches `GIT_DIR` / `GIT_WORK_TREE`
    /// / similar must hold this lock to remain safe under
    /// `cargo test`'s parallel execution.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn discover_repo_root_ignores_inherited_git_env() {
        // Regression: a pre-commit hook sets GIT_DIR (and friends) in
        // the environment. Without scrubbing, the child `git rev-parse
        // --show-toplevel` would inherit those vars, ignore its
        // `current_dir(...)`, and report nonsense for tempdir-based
        // callers — breaking every test that init_git()s a tempdir.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        init_git(&root);
        let nested = root.join("a/b/c");
        std::fs::create_dir_all(&nested).unwrap();

        let _guard = ENV_LOCK.lock().unwrap();
        let prev_dir = std::env::var_os("GIT_DIR");
        let prev_work = std::env::var_os("GIT_WORK_TREE");
        // SAFETY: serialised via ENV_LOCK; mutation is reverted below.
        unsafe {
            std::env::set_var("GIT_DIR", "/nonexistent/.git");
            std::env::set_var("GIT_WORK_TREE", "/nonexistent");
        }
        let found = discover_repo_root(&nested);
        // SAFETY: see above.
        unsafe {
            match prev_dir {
                Some(v) => std::env::set_var("GIT_DIR", v),
                None => std::env::remove_var("GIT_DIR"),
            }
            match prev_work {
                Some(v) => std::env::set_var("GIT_WORK_TREE", v),
                None => std::env::remove_var("GIT_WORK_TREE"),
            }
        }
        assert_eq!(
            found
                .expect("discovery must succeed")
                .canonicalize()
                .unwrap(),
            root,
            "inherited GIT_DIR must not override `current_dir(cwd)`"
        );
    }

    #[test]
    fn discover_repo_root_outside_repo_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        // No marker, no git toplevel.
        let found = discover_repo_root(dir.path());
        // Could be None or, if running inside a repo, Some(somewhere
        // ancestor). On a CI without a parent .git this is None. Allow
        // both: just assert it does not pick the dir itself.
        if let Some(p) = found {
            assert_ne!(
                p.canonicalize().unwrap(),
                dir.path().canonicalize().unwrap()
            );
        }
    }

    #[test]
    fn discover_repo_local_files_returns_documented_order() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_file(root, ".may-i.lisp", "");
        write_file(root, ".may-i/cargo.lisp", "");
        write_file(root, ".may-i/git.lisp", "");
        write_file(root, ".may-i.local.lisp", "");
        write_file(root, ".claude/may-i.lisp", "");
        write_file(root, ".claude/may-i.local.lisp", "");
        let files = discover_repo_local_files(root);
        let names: Vec<String> = files
            .iter()
            .map(|p| p.strip_prefix(root).unwrap().display().to_string())
            .collect();
        assert_eq!(
            names,
            vec![
                ".may-i.lisp",
                ".may-i/cargo.lisp",
                ".may-i/git.lisp",
                ".may-i.local.lisp",
                ".claude/may-i.lisp",
                ".claude/may-i.local.lisp",
            ]
        );
    }

    #[test]
    fn discover_repo_local_files_skips_missing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_file(root, ".may-i.lisp", "");
        let files = discover_repo_local_files(root);
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn load_and_resolve_with_cwd_splices_repo_local_rules() {
        let dir = tempfile::tempdir().unwrap();
        let primary_dir = tempfile::tempdir().unwrap();
        let primary = write_file(
            primary_dir.path(),
            "primary.lisp",
            r#"(rule "echo" (allow))"#,
        );
        init_git(dir.path());
        write_file(
            dir.path(),
            ".may-i.lisp",
            r#"(rule "git" (allow "from repo-local"))"#,
        );

        let result = load_and_resolve_with_cwd(Some(&primary), dir.path()).unwrap();
        // primary echo rule + repo-local git rule
        assert_eq!(result.config.rules.len(), 2);
        let primary_rule = &result.config.rules[0];
        let local_rule = &result.config.rules[1];
        assert_eq!(
            primary_rule.provenance,
            Provenance::PrimaryConfig,
            "first rule comes from primary"
        );
        assert!(
            local_rule.provenance.is_loaded(),
            "second rule comes from repo-local discovery as Loaded"
        );
        let expected_path = dir.path().join(".may-i.lisp").canonicalize().unwrap();
        assert_eq!(local_rule.provenance.path().unwrap(), expected_path);
    }

    #[test]
    fn load_and_resolve_with_cwd_no_repo_is_silent() {
        let primary_dir = tempfile::tempdir().unwrap();
        let primary = write_file(
            primary_dir.path(),
            "primary.lisp",
            r#"(rule "echo" (allow))"#,
        );
        // cwd has no marker — discover_repo_root should return None (or
        // at most an unrelated ancestor that has no .may-i files).
        let outside = tempfile::tempdir().unwrap();
        let result = load_and_resolve_with_cwd(Some(&primary), outside.path()).unwrap();
        // At least the primary rule loads. Repo-local files at the
        // discovered root (if any) are unrelated to this test's primary.
        assert!(!result.config.rules.is_empty());
        assert_eq!(result.config.rules[0].provenance, Provenance::PrimaryConfig);
    }

    #[test]
    fn repo_local_glob_files_load_in_lexical_order() {
        let dir = tempfile::tempdir().unwrap();
        let primary_dir = tempfile::tempdir().unwrap();
        let primary = write_file(
            primary_dir.path(),
            "primary.lisp",
            r#"(rule "echo" (allow))"#,
        );
        init_git(dir.path());
        write_file(dir.path(), ".may-i/02-git.lisp", r#"(rule "git" (allow))"#);
        write_file(
            dir.path(),
            ".may-i/01-cargo.lisp",
            r#"(rule "cargo" (allow))"#,
        );

        let result = load_and_resolve_with_cwd(Some(&primary), dir.path()).unwrap();
        // primary echo + cargo (01) + git (02)
        assert_eq!(result.config.rules.len(), 3);
        assert!(
            result.config.rules[1]
                .command_effect
                .value
                .matches_command("cargo")
        );
        assert!(
            result.config.rules[2]
                .command_effect
                .value
                .matches_command("git")
        );
    }

    #[test]
    fn repo_local_already_loaded_is_not_double_loaded() {
        let dir = tempfile::tempdir().unwrap();
        init_git(dir.path());
        let local = write_file(
            dir.path(),
            ".may-i.lisp",
            r#"(rule "git" (allow "shared"))"#,
        );
        // Primary explicitly loads the repo-local file.
        let primary = write_file(
            dir.path(),
            "primary.lisp",
            &format!(r#"(load {:?})"#, local.display().to_string()),
        );

        let result = load_and_resolve_with_cwd(Some(&primary), dir.path()).unwrap();
        // Without dedup we'd see 2 rules. With dedup, 1.
        assert_eq!(
            result.config.rules.len(),
            1,
            "discovered file already loaded by primary should be deduplicated"
        );
    }

    #[test]
    fn repo_local_rule_hash_matches_load_directive_hash() {
        // Same rule file reached either way must produce the same
        // trust hash, so approvals carry across.
        let dir = tempfile::tempdir().unwrap();
        init_git(dir.path());
        let local = write_file(dir.path(), ".may-i.lisp", r#"(rule "echo" (allow))"#);
        let primary_load_dir = tempfile::tempdir().unwrap();
        let primary_load = write_file(
            primary_load_dir.path(),
            "primary.lisp",
            &format!(r#"(load {:?})"#, local.display().to_string()),
        );
        // Path 1: reach via explicit `(load …)` from a primary outside
        // the repo (so discovery contributes nothing).
        let outside = tempfile::tempdir().unwrap();
        let via_load = load_and_resolve_with_cwd(Some(&primary_load), outside.path()).unwrap();
        // Path 2: reach via repo-local discovery, primary outside repo.
        let neutral_primary_dir = tempfile::tempdir().unwrap();
        let neutral_primary = write_file(
            neutral_primary_dir.path(),
            "primary.lisp",
            r#"(rule "noop" (allow))"#,
        );
        // Re-create the dir + .git + .may-i.lisp to avoid filesystem
        // collisions with the first arm.
        let dir2 = tempfile::tempdir().unwrap();
        init_git(dir2.path());
        write_file(dir2.path(), ".may-i.lisp", r#"(rule "echo" (allow))"#);
        let via_discovery = load_and_resolve_with_cwd(Some(&neutral_primary), dir2.path()).unwrap();

        let metas_load = may_i_engine::trust::compute_trust_views(&via_load.config);
        let metas_disc = may_i_engine::trust::compute_trust_views(&via_discovery.config);
        let echo_load: Vec<&may_i_engine::trust::TrustViewMeta> =
            metas_load.iter().filter(|m| m.program == "echo").collect();
        let echo_disc: Vec<&may_i_engine::trust::TrustViewMeta> =
            metas_disc.iter().filter(|m| m.program == "echo").collect();
        assert_eq!(echo_load.len(), 1);
        assert_eq!(echo_disc.len(), 1);
        assert_eq!(echo_load[0].hash, echo_disc[0].hash);
    }

    #[test]
    fn repo_local_rule_surfaces_with_source_path_in_trust() {
        let dir = tempfile::tempdir().unwrap();
        init_git(dir.path());
        write_file(dir.path(), ".may-i.lisp", r#"(rule "git" (allow))"#);
        let primary_dir = tempfile::tempdir().unwrap();
        let primary = write_file(
            primary_dir.path(),
            "primary.lisp",
            r#"(rule "noop" (allow))"#,
        );
        let result = load_and_resolve_with_cwd(Some(&primary), dir.path()).unwrap();
        let views = may_i_engine::trust::compute_trust_views(&result.config);
        let git = views
            .iter()
            .find(|m| m.program == "git")
            .expect("git rule should be present");
        let expected_path = dir.path().join(".may-i.lisp").canonicalize().unwrap();
        assert_eq!(git.source_file.as_deref(), Some(expected_path.as_path()));
    }

    #[test]
    fn repo_local_load_widening_is_neutralised_by_combine() {
        // Engine-level guarantee: a permissive repo-local rule cannot
        // widen a primary `:deny` for the same command, because the
        // most-strict-wins combine selects `:deny`.
        use may_i_core::ContextFacts;
        let dir = tempfile::tempdir().unwrap();
        let primary_dir = tempfile::tempdir().unwrap();
        let primary = write_file(
            primary_dir.path(),
            "primary.lisp",
            r#"(rule "rm" (deny "primary deny"))"#,
        );
        init_git(dir.path());
        write_file(
            dir.path(),
            ".may-i.lisp",
            r#"(rule "rm" (allow "loaded allow"))"#,
        );
        let result = load_and_resolve_with_cwd(Some(&primary), dir.path()).unwrap();
        let facts = ContextFacts::default();
        let r = may_i_engine::evaluate("rm", &[], &result.config, &facts).unwrap();
        assert_eq!(r.decision, may_i_core::Decision::Deny);
    }
}
