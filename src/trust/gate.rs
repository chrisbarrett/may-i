// Per-mode Trust block-detection logic.
//
// The pipeline owns store loading + catalog construction; this module decides
// whether the command should be blocked in JSON or Hook mode and produces a
// `TrustBlock` payload.

use std::collections::BTreeSet;

use may_i_core::Decision;
use may_i_shell_parser as parser;

use crate::trust::TrustBlock;
use crate::trust::advisory;
use crate::trust::view::{TrustCatalog, TrustState};

/// JSON-mode block: any program in the command with untrusted rules triggers a
/// block listing all matched programs (deduped, in command order).
pub(crate) fn json_block(catalog: &TrustCatalog, command: &str) -> Option<TrustBlock> {
    if catalog.is_empty() {
        return None;
    }
    let entries = advisory::untrusted_entries(catalog);
    if entries.is_empty() {
        return None;
    }

    let untrusted_names: BTreeSet<&str> = entries.iter().map(|e| e.program()).collect();

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
            if let Some(entry) = entries.iter().find(|e| e.program() == program) {
                matched_files.extend(entry.display_files().iter().cloned());
            }
        }
    }

    if matched.is_empty() {
        return None;
    }

    Some(TrustBlock {
        decision: Decision::Ask,
        reason: format!(
            "Untrusted rules for {}. Run: may-i trust",
            matched.join(", ")
        ),
        files: matched_files,
    })
}

/// Hook-mode block: only the first segment's program is consulted; reason
/// embeds the source file list.
pub(crate) fn hook_block(catalog: &TrustCatalog, command: &str) -> Option<TrustBlock> {
    if catalog.is_empty() {
        return None;
    }

    let segment_text = first_segment_text(command);
    let program = program_name(segment_text);

    // Find the views for this program; if none, no trust concern for this
    // command.
    let groups = catalog.group_by_program();
    let views = groups.get(program)?;
    let any_untrusted = views.iter().any(|v| v.state() != TrustState::Approved);
    if !any_untrusted {
        return None;
    }

    let mut files: BTreeSet<String> = BTreeSet::new();
    for v in views {
        if let Some(p) = v.source_file() {
            files.insert(crate::output::shorten_home(p));
        }
    }
    let files: Vec<String> = files.into_iter().collect();
    let from_clause = if files.is_empty() {
        String::new()
    } else {
        format!(" (from {})", files.join(", "))
    };
    Some(TrustBlock {
        decision: Decision::Ask,
        reason: format!(
            "Untrusted rules for '{program}'{from_clause}. Run: may-i trust \"{program}\""
        ),
        files,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use may_i_core::ast::{Config, Effect, Provenance, Rule, Spanned};
    use may_i_core::pattern::CommandPattern;
    use may_i_core::span::Span;
    use may_i_engine::trust::{canonical_rule, hash_rule};
    use proptest::prelude::*;

    use crate::trust::store::TrustStore;
    use crate::trust::view::build_catalog;

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

    #[test]
    fn json_mode_blocks_when_command_program_is_untrusted() {
        let config = make_config(vec![loaded_rule("git", "/tmp/rules.lisp")]);
        let cat = build_catalog(&config, TrustStore::default());
        let block = json_block(&cat, "git status").expect("should block");
        assert_eq!(block.decision, Decision::Ask);
        assert!(block.reason.starts_with("Untrusted rules for git"));
        assert!(block.reason.contains("Run: may-i trust"));
    }

    #[test]
    fn json_mode_proceeds_when_command_program_not_untrusted() {
        let config = make_config(vec![loaded_rule("git", "/tmp/rules.lisp")]);
        let cat = build_catalog(&config, TrustStore::default());
        assert!(json_block(&cat, "echo hi").is_none());
    }

    #[test]
    fn hook_mode_blocks_with_file_path_in_reason() {
        let config = make_config(vec![loaded_rule("git", "/home/me/rules/basics.lisp")]);
        let cat = build_catalog(&config, TrustStore::default());
        let block = hook_block(&cat, "git push").expect("should block");
        assert_eq!(block.decision, Decision::Ask);
        assert!(
            block.reason.contains("basics.lisp") || block.reason.contains("/rules/"),
            "reason should embed source file path: {}",
            block.reason
        );
        assert!(block.reason.contains("git"));
    }

    #[test]
    fn hook_mode_compound_first_segment_decides() {
        let config = make_config(vec![loaded_rule("git", "/tmp/rules.lisp")]);
        let cat = build_catalog(&config, TrustStore::default());
        let block = hook_block(&cat, "git push && echo done").expect("should block");
        assert!(block.reason.contains("git"));
    }

    #[test]
    fn approved_rule_does_not_block() {
        let rule = loaded_rule("git", "/tmp/rules.lisp");
        let form = canonical_rule(&rule);
        let hash = hash_rule(&form);
        let mut store = TrustStore::default();
        store.approve_rule(hash, "git".into(), form);

        let config = make_config(vec![rule]);
        let cat = build_catalog(&config, store);
        assert!(json_block(&cat, "git status").is_none());
        assert!(hook_block(&cat, "git push").is_none());
    }

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
