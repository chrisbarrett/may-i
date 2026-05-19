// Per-invocation orchestration shared by evaluation subcommands.
//
// Owns the loaded config, the detected terminal, the json flag, and one
// `InvocationTrust` collaborator that holds the per-invocation Trust state
// (lazily-loaded catalog, idempotency flags, store-loader seam). Subcommands
// drive their flow through `CommandPipeline::run`; the prelude (migration
// note + integrity advisory) and Trust consultation delegate to
// `InvocationTrust` so they are not duplicated.

use std::io;
use std::path::Path;

use may_i_config::LoadResult;
use may_i_core::ast::Config;
use may_i_engine::EvalResult;
use may_i_engine::check::CheckResult;

use crate::annotation::TraceEntry;
use crate::cmd_check::TraceExtra;
use crate::output::{self, Terminal};
use crate::trust::{InvocationTrust, TrustBlock, TrustMode};

/// Which evaluation flow `CommandPipeline::run` should drive.
///
/// Each variant fixes three behaviours: whether the text-mode prelude
/// advisories render, whether the trust gate is consulted (with filtering)
/// or the trust warning is rendered (without filtering), and which response
/// shape `output::render_eval_outcome` produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvocationMode {
    /// `may-i eval`. Prelude advisories render in text mode. Trust gate is
    /// consulted; untrusted Loaded rules are filtered in place. JSON-vs-text
    /// renderer chosen from `pipeline.json()`.
    Eval,
    /// `may-i check`. Prelude advisories render in text mode. Trust warning
    /// renders (no filtering — `check` validates the config as authored).
    /// The `command` argument to `run` is unused for this mode.
    Check,
    /// Claude Code PreToolUse hook. No prelude (JSON-only by design). Trust
    /// gate is consulted; untrusted Loaded rules are filtered in place. The
    /// response is always wrapped in the `hookSpecificOutput` envelope.
    Hook,
}

impl InvocationMode {
    /// Project to the trust-side mode that drives block-reason phrasing.
    pub(crate) fn into_trust_mode(self, json: bool) -> TrustMode {
        match self {
            InvocationMode::Eval => TrustMode::for_eval(json),
            // Check never consults the gate via `run`; this is the no-op
            // value, returned only for symmetry.
            InvocationMode::Check => TrustMode::Text,
            InvocationMode::Hook => TrustMode::Hook,
        }
    }
}

/// Borrowed evaluation context handed to the closure in
/// [`CommandPipeline::run`]. Carries the loaded config and the per-invocation
/// terminal / path facts that the closure needs to evaluate and produce an
/// `EvalOutcome`. Crucially does *not* carry `&mut CommandPipeline` — the
/// closure cannot re-drive the prelude, re-consult trust, or re-pick the
/// renderer.
pub struct EvalContext<'a> {
    pub config: &'a Config,
    pub loaded: &'a LoadResult,
    pub terminal: &'a Terminal,
    pub config_path: &'a Path,
    pub display_path: String,
}

/// Renderable outcome produced by an evaluation handler's closure. Each
/// variant carries exactly the data `output::render_eval_outcome` needs to
/// emit either the text or JSON response shape for one `InvocationMode`.
pub enum EvalOutcome {
    Eval(EvalOutcomeBody),
    Check(CheckOutcomeBody),
    Hook(EvalResult),
}

/// Eval handler payload: one engine result, the captured trace, the
/// colourised command echo (used only by the text renderer), and the
/// pre-shortened config path.
pub struct EvalOutcomeBody {
    pub command: String,
    pub colored: String,
    pub result: EvalResult,
    pub traces: Vec<TraceEntry>,
    pub display_path: String,
}

/// Check handler payload: per-check results carrying their traces, the
/// `--verbose` flag, the pre-computed tallies, and the pre-shortened config
/// path.
pub struct CheckOutcomeBody {
    pub results: Vec<CheckResult<TraceExtra>>,
    pub verbose: bool,
    pub passed: usize,
    pub failed: usize,
    pub display_path: String,
}

pub struct CommandPipeline {
    loaded: LoadResult,
    terminal: Terminal,
    json: bool,
    trust: InvocationTrust,
}

impl CommandPipeline {
    /// Load config + detect terminal and build a pipeline using the default
    /// trust-store loader.
    pub fn load(config_path: Option<&Path>, json: bool) -> miette::Result<Self> {
        let loaded = may_i_config::load_and_resolve(config_path)?;
        Ok(Self::with_trust(loaded, json, InvocationTrust::new(json)))
    }

    /// Construct a pipeline with a pre-built `InvocationTrust`. Test
    /// entry-point — callers build the trust collaborator (typically via
    /// `InvocationTrust::with_loader`) so the single-load invariant can be
    /// asserted against a counting loader.
    pub fn with_trust(loaded: LoadResult, json: bool, trust: InvocationTrust) -> Self {
        Self {
            loaded,
            terminal: Terminal::detect(),
            json,
            trust,
        }
    }

    pub fn config(&self) -> &Config {
        &self.loaded.config
    }

    pub fn loaded(&self) -> &LoadResult {
        &self.loaded
    }

    pub fn terminal(&self) -> &Terminal {
        &self.terminal
    }

    pub fn config_path(&self) -> &Path {
        &self.loaded.config_path
    }

    pub fn json(&self) -> bool {
        self.json
    }

    /// Text-mode prelude: render the migration note (if applicable) then trust
    /// integrity advisories to stderr. No-op in JSON mode. Idempotent.
    pub(crate) fn render_prelude_advisories(&mut self) {
        self.trust
            .render_prelude(&self.loaded, &self.terminal, &mut io::stderr());
    }

    /// Consult Trust for `command` in `mode`. On `Ok`, the pipeline's config
    /// has untrusted Loaded rules filtered in place. On `Err`, the caller
    /// serialises the block in its mode-appropriate response shape.
    pub(crate) fn consult_trust(
        &mut self,
        command: &str,
        mode: TrustMode,
    ) -> Result<(), TrustBlock> {
        self.trust.consult(&mut self.loaded, command, mode)
    }

    /// Render the Trust warning advisory to stderr. No-op in JSON mode;
    /// idempotent across repeat calls within one invocation.
    pub(crate) fn render_trust_warning(&mut self) {
        self.trust.render_warning(&self.terminal, &mut io::stderr());
    }

    /// Sole evaluation entry point. Owns the per-invocation flow: prelude
    /// advisories (text modes only), trust consultation or warning (per
    /// mode), invoking `closure` with a borrowed `EvalContext`, mapping any
    /// trust block through `output::render_trust_block`, and dispatching the
    /// closure's `EvalOutcome` through `output::render_eval_outcome`.
    ///
    /// On trust block (Eval/Hook modes) the closure is NOT invoked: the
    /// block is serialised and `run` returns `Ok(())`.
    pub fn run<F>(&mut self, mode: InvocationMode, command: &str, closure: F) -> miette::Result<()>
    where
        F: FnOnce(&EvalContext<'_>) -> miette::Result<EvalOutcome>,
    {
        if mode != InvocationMode::Hook {
            self.render_prelude_advisories();
        }

        match mode {
            InvocationMode::Check => {
                self.render_trust_warning();
            }
            InvocationMode::Eval | InvocationMode::Hook => {
                let trust_mode = mode.into_trust_mode(self.json);
                if let Err(block) = self.consult_trust(command, trust_mode) {
                    output::render_trust_block(
                        &mut io::stdout(),
                        &mut io::stderr(),
                        &self.terminal,
                        &block,
                        mode,
                    );
                    return Ok(());
                }
                // Text-mode Eval still surfaces the warning advisory for
                // untrusted Loaded rules that weren't tied to the command;
                // `render_trust_warning` no-ops in JSON / Hook modes.
                if mode == InvocationMode::Eval {
                    self.render_trust_warning();
                }
            }
        }

        let display_path = output::shorten_home(&self.loaded.config_path);
        let outcome = {
            let ctx = EvalContext {
                config: &self.loaded.config,
                loaded: &self.loaded,
                terminal: &self.terminal,
                config_path: &self.loaded.config_path,
                display_path,
            };
            closure(&ctx)?
        };

        output::render_eval_outcome(
            &mut io::stdout(),
            &mut io::stderr(),
            &self.terminal,
            self.json,
            &outcome,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use may_i_config::LoadResult;
    use may_i_core::Decision;
    use may_i_core::ast::{Config, Effect, Provenance, Rule, Spanned};
    use may_i_core::pattern::CommandPattern;
    use may_i_core::span::Span;
    use may_i_engine::EvalResult;

    use crate::pipeline::{
        CheckOutcomeBody, CommandPipeline, EvalOutcome, EvalOutcomeBody, InvocationMode,
    };
    use crate::trust::{InvocationTrust, TrustMode, store::TrustStore};

    fn spanned<T>(value: T) -> Spanned<T> {
        Spanned::new(value, Span::new(0, 0))
    }

    fn loaded_rule(cmd: &str, path: &str) -> Rule {
        Rule {
            command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(cmd.into()))),
            effect: spanned(Effect::Terminal {
                decision: Decision::Allow,
                reason: None,
            }),
            checks: vec![],
            span: Span::new(0, 0),
            provenance: Provenance::Loaded {
                path: PathBuf::from(path),
            },
        }
    }

    fn loaded_result(rules: Vec<Rule>) -> LoadResult {
        LoadResult {
            config: Config {
                rules,
                ..Config::default()
            },
            source_text: None,
            pre_migration_forms: None,
            config_path: PathBuf::from("/tmp/test-config.lisp"),
        }
    }

    fn empty_state() -> crate::trust::TrustStoreState {
        crate::trust::TrustStoreState {
            store: TrustStore::default(),
            suspects: Vec::new(),
            was_corrupt: false,
            store_path: PathBuf::from("/tmp/test-trust.json"),
        }
    }

    /// Spec: `command-pipeline` / `Single trust-store load is observable` —
    /// thin forwarding test confirming the pipeline routes every trust-relevant
    /// call through its `InvocationTrust`. Single-load, idempotency, and
    /// JSON-mode invariants are exercised directly in
    /// `crate::trust::invocation::tests`.
    #[test]
    fn pipeline_forwards_to_invocation_trust() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let loader = Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            Some(empty_state())
        });
        let trust = InvocationTrust::with_loader(false, loader);
        let loaded = loaded_result(vec![loaded_rule("git", "/tmp/rules.lisp")]);
        let mut pipeline = CommandPipeline::with_trust(loaded, false, trust);

        pipeline.render_prelude_advisories();
        let _ = pipeline.consult_trust("git status", TrustMode::Hook);
        pipeline.render_trust_warning();

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "pipeline must drive every trust call through the same InvocationTrust"
        );
    }

    /// Spec: `command-pipeline` / `Check handler dispatches through run` —
    /// `run(Check, …)` invokes the closure on the no-filter path.
    #[test]
    fn run_check_invokes_closure() {
        let loaded = loaded_result(vec![]);
        let trust = InvocationTrust::with_loader(true, Box::new(|| None));
        let mut pipeline = CommandPipeline::with_trust(loaded, true, trust);
        let invoked = Cell::new(false);
        pipeline
            .run(InvocationMode::Check, "", |_ctx| {
                invoked.set(true);
                Ok(EvalOutcome::Check(CheckOutcomeBody {
                    results: vec![],
                    verbose: false,
                    passed: 0,
                    failed: 0,
                    display_path: "/tmp/cfg.lisp".into(),
                }))
            })
            .expect("run check");
        assert!(invoked.get(), "Check arm must invoke the closure");
    }

    /// Spec: `trust-gate` / `Hook mode block reason includes file paths` —
    /// `run(Hook, …)` short-circuits the closure on a trust block.
    #[test]
    fn run_hook_short_circuits_on_block() {
        let loaded = loaded_result(vec![loaded_rule("echo", "/tmp/rules.lisp")]);
        let trust = InvocationTrust::with_loader(true, Box::new(|| Some(empty_state())));
        let mut pipeline = CommandPipeline::with_trust(loaded, true, trust);
        let invoked = Cell::new(false);
        pipeline
            .run(InvocationMode::Hook, "echo hi", |_ctx| {
                invoked.set(true);
                Ok(EvalOutcome::Hook(EvalResult::new(Decision::Allow, None)))
            })
            .expect("run hook");
        assert!(
            !invoked.get(),
            "Hook closure must NOT run when trust blocks"
        );
    }

    /// Spec: `command-pipeline` / `Eval handler dispatches through run` —
    /// `run(Eval, …)` invokes the closure when trust allows.
    #[test]
    fn run_eval_invokes_closure_when_trust_allows() {
        let loaded = loaded_result(vec![]);
        let trust = InvocationTrust::with_loader(false, Box::new(|| None));
        let mut pipeline = CommandPipeline::with_trust(loaded, false, trust);
        let invoked = Cell::new(false);
        pipeline
            .run(InvocationMode::Eval, "echo hi", |_ctx| {
                invoked.set(true);
                Ok(EvalOutcome::Eval(EvalOutcomeBody {
                    command: "echo hi".into(),
                    colored: "echo hi".into(),
                    result: EvalResult::new(Decision::Allow, None),
                    traces: vec![],
                    display_path: "/tmp/cfg.lisp".into(),
                }))
            })
            .expect("run eval");
        assert!(invoked.get(), "Eval closure must run on trust allow");
    }

    #[test]
    fn into_trust_mode_projections() {
        assert_eq!(InvocationMode::Eval.into_trust_mode(true), TrustMode::Json);
        assert_eq!(InvocationMode::Eval.into_trust_mode(false), TrustMode::Text);
        assert_eq!(InvocationMode::Check.into_trust_mode(true), TrustMode::Text);
        assert_eq!(InvocationMode::Hook.into_trust_mode(false), TrustMode::Hook);
    }
}
