// Prompting seam for the interactive trust review and repair loops.
//
// `UserPrompt` is the swappable interface that both loops drive; the terminal
// impl lives in `crate::interactive`, and tests inject a scripted fake. The
// loops emit `StoreOp` values rather than mutating the trust store directly,
// keeping the loop logic decoupled from persistence.

/// Prompting primitives the review and repair loops need.
pub trait UserPrompt {
    /// Render a pre-formatted block (ANSI codes preserved on a real terminal,
    /// optionally stripped by a test impl).
    fn render(&mut self, block: &str);

    /// Yes/no prompt with a default answer.
    fn confirm(&mut self, prompt: &str, default: bool) -> miette::Result<bool>;

    /// Choose-one prompt; returns the index of the chosen item.
    fn choose(&mut self, prompt: &str, items: &[&str], default: usize) -> miette::Result<usize>;

    /// Read a single keystroke from a closed set. Re-prompts on input outside
    /// `keys` so the loop only sees a member.
    fn read_key(&mut self, keys: &[char]) -> miette::Result<char>;

    /// Clear the screen (no-op for non-TTY impls).
    fn clear_screen(&mut self);
}

/// User decision for a single pending rule in the per-rule review loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewAction {
    Approve,
    Block,
    Skip,
    Quit,
}

/// User decision for a single suspect entry in the integrity-repair loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairAction {
    Reapprove,
    Drop,
}

/// Projection of a user decision onto the trust store. The pure loops emit
/// these; the calling shim applies them to the real store between iterations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreOp {
    ApproveRule {
        hash: String,
        program: String,
        form: String,
    },
    BlockRule {
        hash: String,
        program: String,
        form: String,
    },
    Reapprove {
        program: String,
    },
    Drop {
        program: String,
    },
}

/// Summary of an interactive review session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReviewSummary {
    pub approved: usize,
    pub blocked: usize,
    pub skipped: usize,
}
