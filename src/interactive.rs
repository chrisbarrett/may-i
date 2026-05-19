// Terminal `UserPrompt` impl plus thin shims that wire `crate::trust::review`
// into the live `TrustCatalog` / `TrustStore` mutation surface. All loop
// logic, rendering, and prompting semantics live in `crate::trust::review`;
// this file only handles the terminal IO and the StoreOp → catalog/store
// projection.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use crate::output::Terminal;
use crate::trust::review::{
    PendingRule, ProgramReviewEntry, StoreOp, TrustedSummary, UserPrompt, run_integrity_repair,
    run_program_review, run_review,
};
use crate::trust::store::{SuspectEntry, TrustStore, default_trust_store_path};
use crate::trust::view::{TrustCatalog, TrustState, TrustView};

pub use crate::trust::review::{ReviewSummary, pretty_form};

/// Whether the session is interactive (TTY on stdin, no --json).
pub fn is_interactive(json_mode: bool) -> bool {
    !json_mode && std::io::stdin().is_terminal()
}

/// Terminal-backed `UserPrompt` — direct delegation to `console::Term` and
/// `dialoguer`. The seam exists so loop logic stays testable without a TTY;
/// this impl is the production wiring and is intentionally trivial.
pub(crate) struct TerminalPrompt {
    term: console::Term,
}

impl TerminalPrompt {
    pub(crate) fn new() -> Self {
        Self {
            term: console::Term::stderr(),
        }
    }
}

impl UserPrompt for TerminalPrompt {
    fn render(&mut self, block: &str) {
        let _ = self.term.write_all(block.as_bytes());
    }

    fn confirm(&mut self, prompt: &str, default: bool) -> miette::Result<bool> {
        dialoguer::Confirm::new()
            .with_prompt(prompt)
            .default(default)
            .interact()
            .map_err(|e| miette::miette!("prompt failed: {e}"))
    }

    fn choose(&mut self, prompt: &str, items: &[&str], default: usize) -> miette::Result<usize> {
        dialoguer::Select::new()
            .with_prompt(prompt)
            .items(items)
            .default(default)
            .interact()
            .map_err(|e| miette::miette!("prompt failed: {e}"))
    }

    fn read_key(&mut self, keys: &[char]) -> miette::Result<char> {
        loop {
            let ch = self
                .term
                .read_char()
                .map_err(|e| miette::miette!("read key failed: {e}"))?;
            if keys.contains(&ch) {
                return Ok(ch);
            }
        }
    }

    fn clear_screen(&mut self) {
        let _ = self.term.clear_screen();
    }
}

/// Run integrity repair for suspect entries. Returns true if the store was
/// modified.
pub fn repair_integrity(
    store: &mut TrustStore,
    suspects: &[SuspectEntry],
    interactive: bool,
) -> miette::Result<bool> {
    let mut prompt = TerminalPrompt::new();
    let term = Terminal::detect();
    let store_path = default_trust_store_path();
    let ops = run_integrity_repair(
        &mut prompt,
        suspects,
        interactive,
        store_path.as_deref(),
        &term,
    )?;
    let modified = !ops.is_empty();
    for op in ops {
        apply_store_op(store, op);
    }
    Ok(modified)
}

/// Interactive per-rule review with single-key `y/n/s/q` keybindings.
pub fn interactive_review(
    catalog: &mut TrustCatalog,
) -> miette::Result<(Vec<String>, ReviewSummary)> {
    let mut prompt = TerminalPrompt::new();
    let term = Terminal::detect();
    let (pp_width, _term_width) = compute_pp_width();

    let pending = build_pending(catalog);
    let initial_trusted = compute_initial_trusted(catalog);
    let (ops, summary) = run_review(&mut prompt, &pending, initial_trusted, pp_width, &term)?;

    let mut approved_programs = Vec::new();
    for op in ops {
        if let StoreOp::ApproveRule { program, .. } = &op {
            approved_programs.push(program.clone());
        }
        apply_catalog_op(catalog, op);
    }
    Ok((approved_programs, summary))
}

/// Legacy program-level interactive approval over the catalog.
pub fn interactive_approve_programs(
    catalog: &mut TrustCatalog,
    programs: &[String],
) -> miette::Result<Vec<String>> {
    let mut prompt = TerminalPrompt::new();
    let entries = build_program_entries(catalog, programs);
    let ops = run_program_review(&mut prompt, &entries)?;

    let mut approved: Vec<String> = Vec::new();
    for op in ops {
        if let StoreOp::ApproveRule { program, .. } = &op
            && approved.last().map(|p| p != program).unwrap_or(true)
        {
            approved.push(program.clone());
        }
        apply_catalog_op(catalog, op);
    }
    Ok(approved)
}

/// Non-interactive batch approval — approve all pending rules in the
/// catalog without prompting.
pub fn batch_approve(catalog: &mut TrustCatalog) -> Vec<String> {
    let to_approve: Vec<(String, String)> = catalog
        .iter()
        .filter(|v| v.state() != TrustState::Approved)
        .map(|v| (v.hash().to_string(), v.program().to_string()))
        .collect();
    let mut approved: Vec<String> = to_approve.iter().map(|(_, p)| p.clone()).collect();
    for (hash, _) in &to_approve {
        catalog.set_state(hash, TrustState::Approved);
    }
    approved.sort();
    approved.dedup();
    approved
}

/// Collect the lexically-ordered list of programs that have at least one
/// pending or blocked view in the catalog.
pub fn pending_programs(catalog: &TrustCatalog) -> Vec<String> {
    let groups: BTreeMap<&str, Vec<&TrustView>> = catalog.group_by_program();
    groups
        .into_iter()
        .filter_map(|(program, views)| {
            if views.iter().any(|v| v.state() != TrustState::Approved) {
                Some(program.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn compute_pp_width() -> (usize, usize) {
    let term = console::Term::stderr();
    let term_width = term.size().1 as usize;
    let pp_width = term_width.saturating_sub(4).max(40);
    (pp_width, term_width)
}

fn build_pending(catalog: &TrustCatalog) -> Vec<PendingRule> {
    let store = catalog.store();
    catalog
        .iter()
        .filter(|v| v.state() == TrustState::Pending)
        .map(|v| {
            let (badge, prev_form) = detect_change(
                &store.previous_rules(v.program()).unwrap_or_default(),
                v.canonical_form(),
                v.position(),
            );
            PendingRule {
                hash: v.hash().to_string(),
                program: v.program().to_string(),
                canonical_form: v.canonical_form().to_string(),
                source_file: v.source_file().map(|p| p.to_path_buf()),
                badge,
                prev_form,
            }
        })
        .collect()
}

fn compute_initial_trusted(catalog: &TrustCatalog) -> TrustedSummary {
    let rule_count = catalog
        .iter()
        .filter(|v| v.state() == TrustState::Approved)
        .count();
    let files: BTreeSet<PathBuf> = catalog
        .iter()
        .filter(|v| v.state() == TrustState::Approved)
        .filter_map(|v| v.source_file().map(|p| p.to_path_buf()))
        .collect();
    TrustedSummary { rule_count, files }
}

fn build_program_entries(catalog: &TrustCatalog, programs: &[String]) -> Vec<ProgramReviewEntry> {
    let mut entries = Vec::new();
    for program in programs {
        let views_for_program: Vec<(String, String, Option<PathBuf>, TrustState)> = catalog
            .iter()
            .filter(|v| v.program() == program.as_str())
            .map(|v| {
                (
                    v.hash().to_string(),
                    v.canonical_form().to_string(),
                    v.source_file().map(|p| p.to_path_buf()),
                    v.state(),
                )
            })
            .collect();

        if views_for_program.is_empty()
            || views_for_program
                .iter()
                .all(|(_, _, _, s)| *s == TrustState::Approved)
        {
            continue;
        }

        let any_with_prior = catalog.store().previous_rules(program).is_some();
        let badge = if any_with_prior { "CHANGED" } else { "NEW" };
        let prev_forms = if badge == "CHANGED" {
            catalog.store().previous_rules(program)
        } else {
            None
        };

        let hashes: Vec<String> = views_for_program
            .iter()
            .map(|(h, _, _, _)| h.clone())
            .collect();
        let canonical_rules: Vec<String> = views_for_program
            .iter()
            .map(|(_, f, _, _)| f.clone())
            .collect();
        let source_files: BTreeSet<PathBuf> = views_for_program
            .iter()
            .filter_map(|(_, _, sf, _)| sf.clone())
            .collect();

        entries.push(ProgramReviewEntry {
            program: program.clone(),
            hashes,
            canonical_rules,
            source_files,
            badge,
            prev_forms,
        });
    }
    entries
}

fn detect_change(
    stored_forms: &[String],
    canonical_form: &str,
    position: usize,
) -> (&'static str, Option<String>) {
    if stored_forms.is_empty() {
        return ("NEW", None);
    }
    if let Some(old_form) = stored_forms.get(position)
        && *old_form != canonical_form
    {
        return ("CHANGED", Some(old_form.clone()));
    }
    ("NEW", None)
}

fn apply_catalog_op(catalog: &mut TrustCatalog, op: StoreOp) {
    match op {
        StoreOp::ApproveRule { hash, .. } => catalog.set_state(&hash, TrustState::Approved),
        StoreOp::BlockRule { hash, .. } => catalog.set_state(&hash, TrustState::Blocked),
        // Per-rule and program-level review loops never emit Reapprove/Drop;
        // those flow through `repair_integrity`'s `&mut TrustStore` shim.
        StoreOp::Reapprove { .. } | StoreOp::Drop { .. } => {
            unreachable!("review loops do not emit integrity-repair ops")
        }
    }
}

fn apply_store_op(store: &mut TrustStore, op: StoreOp) {
    match op {
        StoreOp::ApproveRule {
            hash,
            program,
            form,
        } => store.approve_rule(hash, program, form),
        StoreOp::BlockRule {
            hash,
            program,
            form,
        } => store.block_rule(hash, program, form),
        StoreOp::Reapprove { program } => store.reapprove(&program),
        StoreOp::Drop { program } => store.drop_entry(&program),
    }
}
