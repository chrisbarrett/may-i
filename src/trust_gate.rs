// Single Trust gate consulted by CLI commands before evaluating a shell command.
//
// Owns trust-store loading, program-name extraction, untrusted-rule filtering,
// and per-mode advisory/block construction. Replaces ad-hoc trust orchestration
// previously duplicated across `cmd_eval`, `cmd_check`, and
// `cmd_claude_code_hook`.

use std::collections::BTreeSet;

use may_i_core::{Decision, ast::Config};
use may_i_engine::trust::compute_trust_hashes;
use may_i_layout::Layout;
use may_i_shell_parser as parser;

use crate::output;
use crate::trust_advisory;
use crate::trust_store::{self, TrustStatus, TrustStore};

/// The mode driving how the gate produces its outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateMode {
    /// Human-readable text output (`eval`, `check`).
    Text,
    /// Machine-readable JSON output (`eval --json`).
    Json,
    /// Claude Code PreToolUse hook response (default subcommand).
    Hook,
}

/// Outcome of a Trust evaluation.
///
/// `Proceed` carries a full `Config` (the trust-filtered rule set) and an
/// optional `Layout` for the advisory. Boxed because the variants are
/// asymmetric in size; clippy's `large_enum_variant` lint flags the gap.
pub enum GateOutcome {
    /// Continue with evaluation. The carried `config` has untrusted Loaded
    /// rules removed; the optional `advisory` is a pre-built warning layout
    /// for the caller to render where appropriate (text mode only).
    Proceed {
        config: Box<Config>,
        advisory: Option<Layout>,
    },
    /// Block: the gate has decided that the command must not run.
    /// The caller serialises this in its mode-appropriate response shape.
    Block {
        decision: Decision,
        reason: String,
        files: Vec<String>,
    },
}

/// Consult Trust for `command` against `config` in the requested `mode`.
///
/// Trust-store load failures degrade silently: the gate behaves as if the
/// store were empty (no filtering, no advisory, no block).
pub fn evaluate(config: Config, command: &str, mode: GateMode) -> GateOutcome {
    match mode {
        GateMode::Text => evaluate_text(config),
        GateMode::Json => evaluate_json(config, command),
        GateMode::Hook => evaluate_hook(config, command),
    }
}

fn evaluate_text(mut config: Config) -> GateOutcome {
    let advisory = trust_advisory::build_warning_layout(&config);
    if let Some(store) = load_store() {
        trust_advisory::filter_trusted_rules(&mut config, &store);
    }
    GateOutcome::Proceed {
        config: Box::new(config),
        advisory,
    }
}

fn evaluate_json(mut config: Config, command: &str) -> GateOutcome {
    if let Some(block) = json_block(&config, command) {
        return block;
    }
    if let Some(store) = load_store() {
        trust_advisory::filter_trusted_rules(&mut config, &store);
    }
    GateOutcome::Proceed {
        config: Box::new(config),
        advisory: None,
    }
}

fn evaluate_hook(mut config: Config, command: &str) -> GateOutcome {
    if let Some(block) = hook_block(&config, command) {
        return block;
    }
    if let Some(store) = load_store() {
        trust_advisory::filter_trusted_rules(&mut config, &store);
    }
    GateOutcome::Proceed {
        config: Box::new(config),
        advisory: None,
    }
}

/// JSON-mode block: any program in the command with untrusted rules triggers a
/// block listing all matched programs (deduped, in command order).
fn json_block(config: &Config, command: &str) -> Option<GateOutcome> {
    let state = trust_advisory::compute(config)?;
    if state.untrusted().is_empty() {
        return None;
    }

    let untrusted_names: BTreeSet<&str> = state.untrusted().iter().map(|e| e.program()).collect();

    let mut matched = Vec::new();
    let mut matched_files = Vec::new();
    let mut seen = BTreeSet::new();

    for text in segment_texts(command) {
        let program = program_name(text);
        if !seen.insert(program.to_string()) {
            continue;
        }
        if untrusted_names.contains(program) {
            matched.push(program.to_string());
            if let Some(entry) = state.untrusted().iter().find(|e| e.program() == program) {
                matched_files.extend(entry.display_files().iter().cloned());
            }
        }
    }

    if matched.is_empty() {
        return None;
    }

    let reason = format!(
        "Untrusted rules for {}. Run: may-i trust",
        matched.join(", ")
    );
    Some(GateOutcome::Block {
        decision: Decision::Ask,
        reason,
        files: matched_files,
    })
}

/// Hook-mode block: only the first segment's program is consulted; reason
/// embeds the source file list.
fn hook_block(config: &Config, command: &str) -> Option<GateOutcome> {
    let hashes = compute_trust_hashes(config);
    if hashes.is_empty() {
        return None;
    }
    let programs = hashes.programs();

    let segment_text = first_segment_text(command);
    let program = program_name(segment_text);

    let meta = programs.get(program)?;
    let store = load_store()?;

    match store.check(program, &meta.hash) {
        TrustStatus::Trusted => None,
        TrustStatus::Changed | TrustStatus::New => {
            let files: Vec<String> = meta
                .source_files
                .iter()
                .map(|p| output::shorten_home(p))
                .collect();
            let from_clause = if files.is_empty() {
                String::new()
            } else {
                format!(" (from {})", files.join(", "))
            };
            let reason = format!(
                "Untrusted rules for '{program}'{from_clause}. Run: may-i trust \"{program}\""
            );
            Some(GateOutcome::Block {
                decision: Decision::Ask,
                reason,
                files,
            })
        }
    }
}

/// Extract the program name from a command segment: first whitespace-separated
/// token, then last component after `/`.
fn program_name(text: &str) -> &str {
    let first = text.split_whitespace().next().unwrap_or(text);
    first.rsplit('/').next().unwrap_or(first)
}

/// First non-operator command segment, or the whole command when no segments
/// were parsed.
fn first_segment_text(command: &str) -> &str {
    let segments = parser::segment(command);
    if segments.is_empty() {
        command
    } else {
        &command[segments[0].start..segments[0].end]
    }
}

/// Non-operator command segments. Falls back to the whole command when no
/// segments parsed.
fn segment_texts(command: &str) -> Vec<&str> {
    let segments = parser::segment(command);
    if segments.is_empty() {
        vec![command]
    } else {
        segments
            .iter()
            .filter(|s| !s.is_operator)
            .map(|s| &command[s.start..s.end])
            .collect()
    }
}

/// Load the trust store from the default path. Silent on any IO failure.
fn load_store() -> Option<TrustStore> {
    let path = trust_store::default_trust_store_path()?;
    let load_result = TrustStore::load(&path).ok()?;
    Some(load_result.store)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use may_i_core::ast::{Config, Effect, Provenance, Rule, Spanned};
    use may_i_core::pattern::CommandPattern;
    use may_i_core::span::Span;
    use may_i_engine::trust::{canonical_rule, hash_rule};
    use proptest::prelude::*;

    fn spanned<T>(value: T) -> Spanned<T> {
        Spanned::new(value, Span::new(0, 0))
    }

    fn make_rule(cmd: &str, decision: Decision, provenance: Provenance) -> Rule {
        Rule {
            command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(cmd.into()))),
            effect: spanned(Effect::Terminal {
                decision,
                reason: None,
            }),
            checks: vec![],
            span: Span::new(0, 0),
            provenance,
        }
    }

    fn make_config(rules: Vec<Rule>) -> Config {
        Config {
            rules,
            ..Config::default()
        }
    }

    fn loaded_rule(cmd: &str, path: &str) -> Rule {
        make_rule(
            cmd,
            Decision::Allow,
            Provenance::Loaded {
                path: PathBuf::from(path),
            },
        )
    }

    /// Set XDG_DATA_HOME to a fresh empty dir so the gate sees an empty store.
    fn with_empty_store<F: FnOnce() -> R, R>(f: F) -> R {
        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("XDG_DATA_HOME");
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: see ENV_LOCK contract above
        unsafe {
            std::env::set_var("XDG_DATA_HOME", dir.path());
        }
        let r = f();
        // SAFETY: see ENV_LOCK contract above
        unsafe {
            match prev {
                Some(v) => std::env::set_var("XDG_DATA_HOME", v),
                None => std::env::remove_var("XDG_DATA_HOME"),
            }
        }
        r
    }

    /// Set XDG_DATA_HOME and write a populated trust store there for the gate
    /// to read. `populate` mutates the store before save.
    fn with_populated_store<F, P, R>(populate: P, f: F) -> R
    where
        P: FnOnce(&mut TrustStore),
        F: FnOnce() -> R,
    {
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("may-i/trust.json");
        std::fs::create_dir_all(store_path.parent().unwrap()).unwrap();
        let mut store = TrustStore::default();
        populate(&mut store);
        store.save(&store_path).unwrap();

        let prev = std::env::var_os("XDG_DATA_HOME");
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: see ENV_LOCK contract above
        unsafe {
            std::env::set_var("XDG_DATA_HOME", dir.path());
        }
        let r = f();
        // SAFETY: see ENV_LOCK contract above
        unsafe {
            match prev {
                Some(v) => std::env::set_var("XDG_DATA_HOME", v),
                None => std::env::remove_var("XDG_DATA_HOME"),
            }
        }
        r
    }

    /// Process-global lock for env-mutation tests in this binary.
    ///
    /// Any test that calls `unsafe { env::set_var(...) }` or
    /// `env::remove_var(...)` MUST take this lock before mutating and hold
    /// it until the variable is restored. Cargo runs tests in parallel by
    /// default, so unguarded mutations race with each other and with reads
    /// in other modules.
    ///
    /// If a future test in this binary needs to mutate env vars, share this
    /// lock — do not introduce a parallel one.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn render_text(layout: &Layout) -> String {
        let term = output::Terminal::new(80);
        let mut buf = Vec::new();
        output::write_layout(&mut buf, layout, &term);
        let raw = String::from_utf8(buf).unwrap();
        may_i_layout::strip_ansi(&raw)
    }

    // ── Spec scenarios ───────────────────────────────────────────────

    #[test]
    fn text_mode_no_loaded_rules_proceeds_without_advisory() {
        let config = make_config(vec![make_rule(
            "ls",
            Decision::Allow,
            Provenance::PrimaryConfig,
        )]);
        let outcome = with_empty_store(|| evaluate(config, "ls", GateMode::Text));
        match outcome {
            GateOutcome::Proceed { advisory, .. } => assert!(advisory.is_none()),
            GateOutcome::Block { .. } => panic!("text mode should not block"),
        }
    }

    #[test]
    fn text_mode_untrusted_returns_advisory_and_filtered_config() {
        let loaded = loaded_rule("git", "/tmp/rules.lisp");
        let config = make_config(vec![loaded]);
        let outcome = with_empty_store(|| evaluate(config, "echo hi", GateMode::Text));
        match outcome {
            GateOutcome::Proceed { config, advisory } => {
                assert!(advisory.is_some(), "advisory should be built");
                let rendered = render_text(&advisory.unwrap());
                assert!(rendered.contains("Untrusted rules"), "{rendered}");
                assert!(rendered.contains("git"), "{rendered}");
                assert!(
                    config.rules.is_empty(),
                    "untrusted loaded rule must be filtered out"
                );
            }
            GateOutcome::Block { .. } => panic!("text mode should not block"),
        }
    }

    #[test]
    fn json_mode_blocks_when_command_program_is_untrusted() {
        let loaded = loaded_rule("git", "/tmp/rules.lisp");
        let config = make_config(vec![loaded]);
        let outcome = with_empty_store(|| evaluate(config, "git status", GateMode::Json));
        match outcome {
            GateOutcome::Block {
                decision,
                reason,
                files,
            } => {
                assert_eq!(decision, Decision::Ask);
                assert!(reason.starts_with("Untrusted rules for git"), "{reason}");
                assert!(reason.contains("Run: may-i trust"), "{reason}");
                assert!(!files.is_empty(), "files should list source");
            }
            GateOutcome::Proceed { .. } => panic!("json mode should block on untrusted program"),
        }
    }

    #[test]
    fn json_mode_proceeds_when_command_program_not_untrusted() {
        let loaded = loaded_rule("git", "/tmp/rules.lisp");
        let config = make_config(vec![loaded]);
        let outcome = with_empty_store(|| evaluate(config, "echo hi", GateMode::Json));
        match outcome {
            GateOutcome::Proceed { advisory, config } => {
                assert!(advisory.is_none(), "json mode never carries advisory");
                assert!(config.rules.is_empty(), "loaded rule filtered");
            }
            GateOutcome::Block { .. } => panic!("should not block; command program not untrusted"),
        }
    }

    #[test]
    fn hook_mode_blocks_with_file_path_in_reason() {
        let loaded = loaded_rule("git", "/home/me/rules/basics.lisp");
        let config = make_config(vec![loaded]);
        let outcome = with_empty_store(|| evaluate(config, "git push", GateMode::Hook));
        match outcome {
            GateOutcome::Block {
                decision, reason, ..
            } => {
                assert_eq!(decision, Decision::Ask);
                assert!(
                    reason.contains("basics.lisp") || reason.contains("/rules/"),
                    "reason should embed source file path: {reason}"
                );
                assert!(reason.contains("git"), "{reason}");
            }
            GateOutcome::Proceed { .. } => panic!("hook mode should block on untrusted program"),
        }
    }

    #[test]
    fn hook_mode_compound_first_segment_decides() {
        let loaded = loaded_rule("git", "/tmp/rules.lisp");
        let config = make_config(vec![loaded]);
        let outcome =
            with_empty_store(|| evaluate(config, "git push && echo done", GateMode::Hook));
        match outcome {
            GateOutcome::Block { reason, .. } => {
                assert!(reason.contains("git"), "{reason}");
            }
            GateOutcome::Proceed { .. } => panic!("first-segment program governs hook block"),
        }
    }

    #[test]
    fn proceed_filters_unapproved_loaded_rules() {
        // Approved loaded rule should remain after Proceed.
        let approved_rule = loaded_rule("git", "/tmp/rules.lisp");
        let pending_rule = loaded_rule("rm", "/tmp/rules.lisp");
        let primary_rule = make_rule("ls", Decision::Allow, Provenance::PrimaryConfig);

        let form = canonical_rule(&approved_rule);
        let hash = hash_rule(&form);

        let config = make_config(vec![
            primary_rule,
            approved_rule.clone(),
            pending_rule.clone(),
        ]);

        let outcome = with_populated_store(
            move |store| store.approve_rule(hash, "git".into(), form),
            || evaluate(config, "true", GateMode::Text),
        );
        match outcome {
            GateOutcome::Proceed { config, .. } => {
                assert_eq!(
                    config.rules.len(),
                    2,
                    "primary + approved kept, pending removed"
                );
            }
            GateOutcome::Block { .. } => panic!("text mode should not block"),
        }
    }

    // ── Property tests ────────────────────────────────────────────────

    proptest! {
        /// Program-name extraction matches the verbatim algorithm copied from
        /// the prior call sites.
        #[test]
        fn prop_program_name_matches_verbatim(
            cmd in "[a-zA-Z0-9_/. ]{0,40}"
        ) {
            let expected = {
                let first = cmd.split_whitespace().next().unwrap_or(&cmd);
                first.rsplit('/').next().unwrap_or(first).to_string()
            };
            let got = program_name(&cmd).to_string();
            prop_assert_eq!(got, expected);
        }
    }
}
