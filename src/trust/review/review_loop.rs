// Pure interactive-review loops. The bodies of the per-rule review, the
// integrity-repair walk, and the legacy program-level approval flow live
// here; the only IO seam is `UserPrompt`. The terminal impl lives in
// `crate::interactive`; tests use a scripted `FakeUserPrompt`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use may_i_output::Style;

use super::render::paint;

use crate::output::{Terminal, write_layout};
use crate::trust::review::prompt::{
    RepairAction, ReviewAction, ReviewSummary, StoreOp, UserPrompt,
};
use crate::trust::review::render::{
    render_entry_detail, render_key_legend, render_progress_label, render_rule_detail,
    render_separator, render_summary, render_suspect_detail, render_trusted_summary,
};
use crate::trust::store::SuspectEntry;

/// Snapshot of one pending rule supplied to the per-rule review loop.
#[derive(Debug, Clone)]
pub struct PendingRule {
    pub hash: String,
    pub program: String,
    pub canonical_form: String,
    pub source_file: Option<PathBuf>,
    /// `"NEW"` or `"CHANGED"`.
    pub badge: &'static str,
    /// Previous stored form when the badge is `"CHANGED"`.
    pub prev_form: Option<String>,
}

/// Counts of already-trusted rules and files at the start of the review.
#[derive(Debug, Clone, Default)]
pub struct TrustedSummary {
    pub rule_count: usize,
    pub files: BTreeSet<PathBuf>,
}

/// Snapshot of one program supplied to the legacy program-level review loop.
#[derive(Debug, Clone)]
pub struct ProgramReviewEntry {
    pub program: String,
    pub hashes: Vec<String>,
    pub canonical_rules: Vec<String>,
    pub source_files: BTreeSet<PathBuf>,
    /// `"NEW"` or `"CHANGED"`.
    pub badge: &'static str,
    /// Previous stored forms when the badge is `"CHANGED"`.
    pub prev_forms: Option<Vec<String>>,
}

const REVIEW_KEYS: &[char] = &['y', 'Y', 'n', 'N', 's', 'S', 'q', 'Q'];

/// Map a single keystroke from `REVIEW_KEYS` to the domain action it
/// represents. The closed-set contract on `UserPrompt::read_key` means the
/// fallthrough is unreachable.
fn classify_review_key(ch: char) -> ReviewAction {
    match ch {
        'y' | 'Y' => ReviewAction::Approve,
        'n' | 'N' => ReviewAction::Block,
        's' | 'S' => ReviewAction::Skip,
        'q' | 'Q' => ReviewAction::Quit,
        _ => unreachable!("read_key returned a key outside the closed set"),
    }
}

/// Map a 0/1 choice from `UserPrompt::choose` (in the two-item integrity
/// repair menu) to the domain repair action.
fn classify_repair_choice(idx: usize) -> RepairAction {
    match idx {
        0 => RepairAction::Reapprove,
        1 => RepairAction::Drop,
        _ => unreachable!("choose returned an index outside the requested item set"),
    }
}

/// Drive the per-rule review loop. Pure over `UserPrompt`; emits a
/// `StoreOp` per approve / block decision (skip produces nothing) and the
/// final `ReviewSummary`.
pub fn run_review(
    prompt: &mut dyn UserPrompt,
    pending: &[PendingRule],
    initial_trusted: TrustedSummary,
    pp_width: usize,
    term: &Terminal,
) -> miette::Result<(Vec<StoreOp>, ReviewSummary)> {
    let mut summary = ReviewSummary::default();
    let mut ops: Vec<StoreOp> = Vec::new();
    let total = pending.len();
    let mut trusted_rule_count = initial_trusted.rule_count;
    let mut trusted_files = initial_trusted.files;
    let mut trusted_file_count = trusted_files.len();

    for (idx, rule) in pending.iter().enumerate() {
        prompt.clear_screen();

        let mut block = String::new();
        block.push_str(&render_trusted_summary(
            trusted_rule_count,
            trusted_file_count,
        ));
        let label = render_progress_label(idx, total, rule.badge);
        block.push_str(&render_separator(label, term));
        block.push('\n');
        block.push_str(&render_rule_detail(
            rule.source_file.as_deref(),
            &rule.canonical_form,
            rule.prev_form.as_deref(),
            pp_width,
        ));
        block.push_str(&render_key_legend());
        prompt.render(&block);

        let ch = prompt.read_key(REVIEW_KEYS)?;
        let action = classify_review_key(ch);
        match action {
            ReviewAction::Approve => {
                ops.push(StoreOp::ApproveRule {
                    hash: rule.hash.clone(),
                    program: rule.program.clone(),
                    form: rule.canonical_form.clone(),
                });
                summary.approved += 1;
                trusted_rule_count += 1;
                if let Some(f) = &rule.source_file
                    && trusted_files.insert(f.clone())
                {
                    trusted_file_count += 1;
                }
            }
            ReviewAction::Block => {
                ops.push(StoreOp::BlockRule {
                    hash: rule.hash.clone(),
                    program: rule.program.clone(),
                    form: rule.canonical_form.clone(),
                });
                summary.blocked += 1;
            }
            ReviewAction::Skip => {
                summary.skipped += 1;
            }
            ReviewAction::Quit => {
                prompt.clear_screen();
                prompt.render(&render_summary(&summary));
                return Ok((ops, summary));
            }
        }
    }

    prompt.clear_screen();
    prompt.render(&render_summary(&summary));
    Ok((ops, summary))
}

/// Drive the integrity-repair walk. In the non-interactive branch the
/// advisory is rendered via the existing `output` layout pipeline and no
/// prompts are issued; the returned op list is empty.
pub fn run_integrity_repair(
    prompt: &mut dyn UserPrompt,
    suspects: &[SuspectEntry],
    interactive: bool,
    store_path: Option<&Path>,
    term: &Terminal,
) -> miette::Result<Vec<StoreOp>> {
    if suspects.is_empty() {
        return Ok(Vec::new());
    }

    if !interactive {
        if let Some(path) = store_path {
            let names: Vec<&str> = suspects.iter().map(|s| s.program.as_str()).collect();
            let note = crate::trust::advisory::build_integrity_layout(path, Some(&names));
            let mut buf: Vec<u8> = Vec::new();
            write_layout(&mut buf, &note, term);
            prompt.render(&String::from_utf8_lossy(&buf));
        }
        return Ok(Vec::new());
    }

    let color = crate::sink::stderr_color();
    let mut header = String::new();
    header.push_str(&format!(
        "\n{}\n",
        paint(
            "Trust store integrity check found suspect entries:",
            Style::Ask,
            color
        )
    ));
    header.push_str(&format!(
        "{}\n\n",
        paint(
            "Stored canonical forms do not match their hashes.",
            Style::Dimmed,
            color
        )
    ));
    prompt.render(&header);

    let mut ops = Vec::new();
    for suspect in suspects {
        prompt.render(&render_suspect_detail(suspect));

        let choice = prompt.choose(
            &format!("  {} → action", suspect.program),
            &[
                "Re-approve (accept stored forms, recompute hash)",
                "Drop (remove entry)",
            ],
            0,
        )?;

        let action = classify_repair_choice(choice);
        match action {
            RepairAction::Reapprove => {
                ops.push(StoreOp::Reapprove {
                    program: suspect.program.clone(),
                });
                prompt.render(&format!(
                    "  {} re-approved\n",
                    paint(&suspect.program, Style::AllowSoft, color)
                ));
            }
            RepairAction::Drop => {
                ops.push(StoreOp::Drop {
                    program: suspect.program.clone(),
                });
                prompt.render(&format!(
                    "  {} dropped\n",
                    paint(&suspect.program, Style::DenySoft, color)
                ));
            }
        }
    }
    Ok(ops)
}

/// Drive the legacy program-level approval loop. Returns one
/// `StoreOp::ApproveRule` per (hash, form) in every confirmed program.
pub fn run_program_review(
    prompt: &mut dyn UserPrompt,
    programs: &[ProgramReviewEntry],
) -> miette::Result<Vec<StoreOp>> {
    let color = crate::sink::stderr_color();
    let mut ops: Vec<StoreOp> = Vec::new();
    for entry in programs {
        prompt.render(&render_entry_detail(
            &entry.program,
            entry.badge,
            &entry.canonical_rules,
            &entry.source_files,
            entry.prev_forms.as_deref(),
        ));

        let confirm = prompt.confirm(&format!("  Approve {}?", entry.program), true)?;
        if confirm {
            for (hash, form) in entry.hashes.iter().zip(entry.canonical_rules.iter()) {
                ops.push(StoreOp::ApproveRule {
                    hash: hash.clone(),
                    program: entry.program.clone(),
                    form: form.clone(),
                });
            }
            prompt.render(&format!(
                "  {} approved\n\n",
                paint(&entry.program, Style::AllowSoft, color)
            ));
        } else {
            prompt.render(&format!(
                "  {} skipped\n\n",
                paint(&entry.program, Style::AskSoft, color)
            ));
        }
    }
    Ok(ops)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    /// Scripted `UserPrompt` for unit tests. Records every render, pops
    /// canned answers from per-method queues. Panics if a scripted key is
    /// not a member of the closed set passed to `read_key`.
    #[derive(Default)]
    struct FakeUserPrompt {
        rendered: Vec<String>,
        confirms: VecDeque<bool>,
        choices: VecDeque<usize>,
        keys: VecDeque<char>,
        clear_calls: usize,
    }

    impl FakeUserPrompt {
        fn with_keys(keys: &[char]) -> Self {
            Self {
                keys: keys.iter().copied().collect(),
                ..Self::default()
            }
        }

        fn with_choices(choices: &[usize]) -> Self {
            Self {
                choices: choices.iter().copied().collect(),
                ..Self::default()
            }
        }
    }

    impl UserPrompt for FakeUserPrompt {
        fn render(&mut self, block: &str) {
            self.rendered.push(block.to_string());
        }
        fn confirm(&mut self, _prompt: &str, _default: bool) -> miette::Result<bool> {
            Ok(self
                .confirms
                .pop_front()
                .expect("FakeUserPrompt: no scripted confirm answer"))
        }
        fn choose(
            &mut self,
            _prompt: &str,
            items: &[&str],
            _default: usize,
        ) -> miette::Result<usize> {
            let idx = self
                .choices
                .pop_front()
                .expect("FakeUserPrompt: no scripted choose answer");
            assert!(
                idx < items.len(),
                "FakeUserPrompt: scripted choose index {idx} out of range (items={})",
                items.len()
            );
            Ok(idx)
        }
        fn read_key(&mut self, keys: &[char]) -> miette::Result<char> {
            let ch = self
                .keys
                .pop_front()
                .expect("FakeUserPrompt: no scripted key");
            assert!(
                keys.contains(&ch),
                "FakeUserPrompt: scripted key {ch:?} not in closed set {keys:?}"
            );
            Ok(ch)
        }
        fn clear_screen(&mut self) {
            self.clear_calls += 1;
        }
    }

    fn rule(program: &str, hash: &str, form: &str) -> PendingRule {
        PendingRule {
            hash: hash.into(),
            program: program.into(),
            canonical_form: form.into(),
            source_file: None,
            badge: "NEW",
            prev_form: None,
        }
    }

    fn suspect(program: &str) -> SuspectEntry {
        SuspectEntry {
            hash: format!("hash-{program}"),
            program: program.into(),
            stored_form: format!(r#"(rule "{program}" allow)"#),
        }
    }

    #[test]
    fn run_review_emits_approve_block_skip_in_order() {
        let mut prompt = FakeUserPrompt::with_keys(&['y', 'n', 's']);
        let pending = vec![
            rule("alpha", "h1", r#"(rule "alpha" allow)"#),
            rule("beta", "h2", r#"(rule "beta" allow)"#),
            rule("gamma", "h3", r#"(rule "gamma" allow)"#),
        ];
        let term = Terminal::detect();

        let (ops, summary) =
            run_review(&mut prompt, &pending, TrustedSummary::default(), 80, &term)
                .expect("loop succeeds");

        assert_eq!(
            ops,
            vec![
                StoreOp::ApproveRule {
                    hash: "h1".into(),
                    program: "alpha".into(),
                    form: r#"(rule "alpha" allow)"#.into(),
                },
                StoreOp::BlockRule {
                    hash: "h2".into(),
                    program: "beta".into(),
                    form: r#"(rule "beta" allow)"#.into(),
                },
            ],
        );
        assert_eq!(
            summary,
            ReviewSummary {
                approved: 1,
                blocked: 1,
                skipped: 1
            }
        );
    }

    /// `run_review` is faithful to its input slice: it does not deduplicate.
    /// Two `PendingRule`s sharing a hash yield two prompts and two ops. This
    /// pins the contract that dedup is the caller's job (`build_pending`), so
    /// the loop stays pure over "unique by hash" input.
    #[test]
    fn run_review_does_not_dedup_duplicate_hash_inputs() {
        let mut prompt = FakeUserPrompt::with_keys(&['y', 'y']);
        let pending = vec![
            rule("git", "h1", r#"(rule (or "git" "gh") allow)"#),
            rule("gh", "h1", r#"(rule (or "git" "gh") allow)"#),
        ];
        let term = Terminal::detect();

        let (ops, summary) =
            run_review(&mut prompt, &pending, TrustedSummary::default(), 80, &term)
                .expect("loop succeeds");

        assert_eq!(ops.len(), 2, "loop prompts once per input, no dedup");
        assert!(
            ops.iter()
                .all(|op| matches!(op, StoreOp::ApproveRule { hash, .. } if hash == "h1"))
        );
        assert_eq!(summary.approved, 2);
        assert!(prompt.keys.is_empty(), "both prompts consumed a keystroke");
    }

    #[test]
    fn run_review_quit_short_circuits_remaining_rules() {
        let mut prompt = FakeUserPrompt::with_keys(&['y', 'q']);
        let pending: Vec<PendingRule> = (0..5)
            .map(|i| {
                rule(
                    &format!("p{i}"),
                    &format!("h{i}"),
                    &format!("(rule \"p{i}\" allow)"),
                )
            })
            .collect();
        let term = Terminal::detect();

        let (ops, _summary) =
            run_review(&mut prompt, &pending, TrustedSummary::default(), 80, &term)
                .expect("loop succeeds");

        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], StoreOp::ApproveRule { hash, .. } if hash == "h0"));
        assert!(prompt.keys.is_empty(), "quit must consume no further keys");
    }

    #[test]
    fn run_integrity_repair_emits_reapprove_then_drop() {
        let mut prompt = FakeUserPrompt::with_choices(&[0, 1]);
        let suspects = vec![suspect("alpha"), suspect("beta")];
        let term = Terminal::detect();

        let ops =
            run_integrity_repair(&mut prompt, &suspects, true, None, &term).expect("loop succeeds");

        assert_eq!(
            ops,
            vec![
                StoreOp::Reapprove {
                    program: "alpha".into()
                },
                StoreOp::Drop {
                    program: "beta".into()
                },
            ],
        );
        let combined = prompt.rendered.join("");
        assert!(combined.contains("alpha"));
        assert!(combined.contains("beta"));
    }

    #[test]
    fn run_integrity_repair_non_interactive_emits_nothing_without_prompting() {
        let mut prompt = FakeUserPrompt::default();
        let suspects = vec![suspect("alpha")];
        let term = Terminal::detect();

        let ops = run_integrity_repair(&mut prompt, &suspects, false, None, &term)
            .expect("loop succeeds");

        assert!(ops.is_empty());
        assert!(prompt.confirms.is_empty());
        assert!(prompt.choices.is_empty());
        assert!(prompt.keys.is_empty());
    }

    #[test]
    fn run_review_with_source_file_updates_trusted_file_count_and_renders_diff() {
        let mut prompt = FakeUserPrompt::with_keys(&['y']);
        let mut rule = rule("alpha", "h1", r#"(rule "alpha" allow)"#);
        rule.source_file = Some(PathBuf::from("/tmp/example.lisp"));
        rule.badge = "CHANGED";
        rule.prev_form = Some(r#"(rule "alpha" deny)"#.into());
        let term = Terminal::detect();

        let (ops, summary) = run_review(&mut prompt, &[rule], TrustedSummary::default(), 80, &term)
            .expect("loop succeeds");

        assert_eq!(ops.len(), 1);
        assert_eq!(summary.approved, 1);
        let combined = prompt.rendered.join("");
        assert!(
            combined.contains("example.lisp"),
            "rendered output must reference the source file"
        );
        // CHANGED branch routes through `render_pretty_diff`, which emits diff
        // markers around the changed atom.
        assert!(
            combined.contains('+') || combined.contains('-'),
            "expected diff markers in rendered output"
        );
    }

    #[test]
    fn run_integrity_repair_empty_suspects_returns_empty_without_rendering() {
        let mut prompt = FakeUserPrompt::default();
        let term = Terminal::detect();
        let ops = run_integrity_repair(&mut prompt, &[], true, None, &term).expect("loop succeeds");
        assert!(ops.is_empty());
        assert!(prompt.rendered.is_empty());
    }

    #[test]
    fn run_integrity_repair_non_interactive_with_path_renders_advisory() {
        let mut prompt = FakeUserPrompt::default();
        let suspects = vec![suspect("alpha")];
        let term = Terminal::detect();
        let path = PathBuf::from("/tmp/trust-store.lisp");

        let ops = run_integrity_repair(&mut prompt, &suspects, false, Some(&path), &term)
            .expect("loop succeeds");

        assert!(ops.is_empty());
        assert_eq!(
            prompt.rendered.len(),
            1,
            "non-interactive branch renders the advisory exactly once"
        );
    }

    #[test]
    fn run_program_review_approves_then_skips() {
        let mut prompt = FakeUserPrompt::default();
        prompt.confirms.extend([true, false]);

        let programs = vec![
            ProgramReviewEntry {
                program: "alpha".into(),
                hashes: vec!["h1".into(), "h2".into()],
                canonical_rules: vec![
                    r#"(rule "alpha" allow)"#.into(),
                    r#"(rule "alpha" deny)"#.into(),
                ],
                source_files: BTreeSet::new(),
                badge: "NEW",
                prev_forms: None,
            },
            ProgramReviewEntry {
                program: "beta".into(),
                hashes: vec!["h3".into()],
                canonical_rules: vec![r#"(rule "beta" allow)"#.into()],
                source_files: BTreeSet::new(),
                badge: "NEW",
                prev_forms: None,
            },
        ];

        let ops = run_program_review(&mut prompt, &programs).expect("loop succeeds");

        assert_eq!(
            ops,
            vec![
                StoreOp::ApproveRule {
                    hash: "h1".into(),
                    program: "alpha".into(),
                    form: r#"(rule "alpha" allow)"#.into(),
                },
                StoreOp::ApproveRule {
                    hash: "h2".into(),
                    program: "alpha".into(),
                    form: r#"(rule "alpha" deny)"#.into(),
                },
            ],
        );
    }
}
