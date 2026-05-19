// Trust — owns the per-invocation Trust concern:
// store loading, untrusted-rule filtering, integrity/warning advisories,
// and the block decision for each `TrustMode`. All orchestration lives
// behind `InvocationTrust` (see `invocation`); this module re-exports the
// data carriers and submodules.
//
// The pipeline (`crate::pipeline::CommandPipeline`) reaches Trust only via
// the methods on its `InvocationTrust` field. `cmd_trust` is the carve-out
// and may call `TrustStore` directly for its administrative operations.

pub mod advisory;
pub mod gate;
pub mod invocation;
pub mod rehash;
pub mod review;
pub mod store;
pub mod view;

pub use invocation::{InvocationTrust, StoreLoader};
pub use rehash::rehash_after_migration;
pub use view::{TrustCatalog, TrustState, TrustView};

use std::path::PathBuf;

use may_i_core::Decision;

use crate::trust::store::{SuspectEntry, TrustStore};

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
/// store path for advisory rendering. `InvocationTrust` joins this with the
/// loaded config when it first builds its catalog. Public only as the
/// loader-seam boundary ([`StoreLoader`]).
pub struct TrustStoreState {
    pub store: TrustStore,
    pub suspects: Vec<SuspectEntry>,
    pub was_corrupt: bool,
    pub store_path: PathBuf,
}
