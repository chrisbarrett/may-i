// Pure interactive-review module: per-rule review, integrity repair, and the
// legacy program-level approval loop. Loop logic lives in `review_loop`; the
// prompting seam in `prompt`; rendering helpers in `render`. The terminal
// `UserPrompt` impl lives in `crate::interactive`.

pub(crate) mod prompt;
pub(crate) mod render;
pub(crate) mod review_loop;

pub use prompt::{RepairAction, ReviewAction, ReviewSummary, StoreOp, UserPrompt};
pub use render::pretty_form;
pub use review_loop::{
    PendingRule, ProgramReviewEntry, TrustedSummary, run_integrity_repair, run_program_review,
    run_review,
};
