// Trust — owns the per-invocation Trust concern:
// store loading, untrusted-rule filtering, integrity/warning advisories,
// and the block decision for each `TrustMode`.
//
// The pipeline (`crate::pipeline::CommandPipeline`) is the sole entry point
// for evaluation subcommands. `cmd_trust` is the carve-out and may call
// `TrustStore` directly for its administrative operations.

pub mod advisory;
pub mod gate;
pub mod store;

use std::io::Write;
use std::path::PathBuf;

use colored::Colorize;
use may_i_config::LoadResult;
use may_i_core::Decision;
use may_i_core::ast::Config;
use may_i_layout::{Advisory, Layout, NoteHeading, NoteLevel};

use crate::output::{self, Terminal};
use crate::trust::store::{SuspectEntry, TrustStore, default_trust_store_path};

/// Mode driving how the gate produces its outcome for one invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustMode {
    /// Human-readable text output (`eval`, `check`).
    Text,
    /// Machine-readable JSON output (`eval --json`).
    Json,
    /// Claude Code PreToolUse hook response (default subcommand).
    Hook,
}

impl TrustMode {
    /// Pick text vs json for the `eval` subcommand.
    pub fn for_eval(json: bool) -> Self {
        if json {
            TrustMode::Json
        } else {
            TrustMode::Text
        }
    }
}

/// Block payload from the gate. Callers serialise in mode-appropriate form.
#[derive(Debug, Clone)]
pub struct TrustBlock {
    pub decision: Decision,
    pub reason: String,
    pub files: Vec<String>,
}

/// Snapshot of the trust store as loaded for this invocation. Carries the
/// store, any integrity-suspect entries, the `was_corrupt` flag, and the
/// store path for advisory rendering.
pub struct TrustStoreState {
    pub store: TrustStore,
    pub suspects: Vec<SuspectEntry>,
    pub was_corrupt: bool,
    pub store_path: PathBuf,
}

/// Production trust-store loader. Returns `None` when the store path cannot
/// be determined; IO failures collapse into a state with `was_corrupt: true`
/// and an empty store so callers can render the integrity advisory.
pub fn default_store_loader() -> Option<TrustStoreState> {
    let store_path = default_trust_store_path()?;
    let state = match TrustStore::load(&store_path) {
        Ok(load_result) => TrustStoreState {
            store: load_result.store,
            suspects: load_result.suspects,
            was_corrupt: load_result.was_corrupt,
            store_path,
        },
        Err(_) => TrustStoreState {
            store: TrustStore::default(),
            suspects: Vec::new(),
            was_corrupt: true,
            store_path,
        },
    };
    Some(state)
}

/// Render the migration note advisory if the loaded config came from a
/// transparent migration.
pub(crate) fn migration_note(loaded: &LoadResult) -> Option<Layout> {
    loaded.pre_migration_forms.as_ref()?;
    let prog = std::env::args()
        .next()
        .map(|s| {
            std::path::Path::new(&s)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or(s)
        })
        .unwrap_or_else(|| "may-i".into());
    let display_path = output::shorten_home(&loaded.config_path);
    let prefix = "Migrations available:";
    let heading = NoteHeading {
        text: format!("{} {}", prefix.yellow().bold(), display_path.bold()),
        visible_width: prefix.len() + 1 + display_path.len(),
    };
    Some(
        Advisory {
            level: NoteLevel::Warn,
            heading: String::new(),
            detail: "Your config uses an older syntax that has been automatically \
                 translated. Trace output reflects the translated rules, which \
                 may not match the file on disk."
                .into(),
            suggestion: "Apply pending migrations by running:".into(),
            command: format!("{prog} migrate"),
            children: vec![],
        }
        .into_note_with_heading(heading),
    )
}

/// Render trust-store integrity advisories to the supplied writer.
///
/// No-op when `config` has no loaded rules (trust is irrelevant) or when no
/// store state was loaded (path unavailable).
pub(crate) fn render_integrity_advisories(
    config: &Config,
    state: Option<&TrustStoreState>,
    term: &Terminal,
    w: &mut impl Write,
) {
    use may_i_engine::trust::compute_trust_hashes;

    if compute_trust_hashes(config).is_empty() {
        return;
    }
    let Some(state) = state else {
        return;
    };

    let mut stack: Vec<Layout> = Vec::new();
    if state.was_corrupt {
        stack.push(advisory::build_integrity_layout(&state.store_path, None));
    }
    if !state.suspects.is_empty() {
        let names: Vec<&str> = state.suspects.iter().map(|s| s.program.as_str()).collect();
        stack.push(advisory::build_integrity_layout(
            &state.store_path,
            Some(&names),
        ));
    }
    output::render_advisory_stack(w, term, &stack);
}

/// Build the warning advisory for untrusted Loaded rules in `config`.
///
/// Returns `None` when there are no loaded rules, when no store state is
/// available, or when every loaded program is trusted.
pub(crate) fn build_warning_advisory(
    config: &Config,
    store: Option<&TrustStore>,
) -> Option<Layout> {
    advisory::build_warning_layout(config, store)
}

/// Filter the config in place, removing Loaded rules whose hash is not
/// approved in `store`. Primary-config rules are kept. No-op when `store`
/// is `None`.
pub(crate) fn filter_untrusted(config: &mut Config, store: Option<&TrustStore>) {
    if let Some(store) = store {
        advisory::filter_trusted_rules(config, store);
    }
}

/// Check whether Trust should block the command in `mode`.
pub(crate) fn check_block(
    config: &Config,
    command: &str,
    mode: TrustMode,
    store: Option<&TrustStore>,
) -> Option<TrustBlock> {
    match mode {
        TrustMode::Text => None,
        TrustMode::Json => gate::json_block(config, command, store),
        TrustMode::Hook => gate::hook_block(config, command, store),
    }
}
