// Per-invocation orchestration shared by evaluation subcommands.
//
// Owns the loaded config, the detected terminal, the json flag, and the
// lazily-loaded trust store. Subcommands receive `&mut CommandPipeline` and
// drive their own logic; the prelude (migration note + integrity advisory)
// and Trust consultation live here so they are not duplicated.

use std::io;
use std::path::Path;

use may_i_config::LoadResult;
use may_i_core::ast::Config;
use may_i_engine::EvalResult;
use may_i_engine::check::CheckResult;

use crate::annotation::TraceEntry;
use crate::cmd_check::TraceExtra;
use crate::output::{self, Terminal};
use crate::trust::view::build_catalog;
use crate::trust::{self, TrustBlock, TrustCatalogState, TrustMode, TrustStoreState};

type StoreLoader = Box<dyn Fn() -> Option<TrustStoreState>>;

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
    store_loader: StoreLoader,
    catalog_cache: Option<TrustCatalogState>,
    catalog_attempted: bool,
    prelude_rendered: bool,
    trust_warning_rendered: bool,
}

impl CommandPipeline {
    /// Load config + detect terminal and build a pipeline using the default
    /// trust-store loader.
    pub fn load(config_path: Option<&Path>, json: bool) -> miette::Result<Self> {
        let loaded = may_i_config::load_and_resolve(config_path)?;
        Ok(Self::with_loaded(
            loaded,
            json,
            Box::new(trust::default_store_loader),
        ))
    }

    /// Construct a pipeline with an injected store loader. Test entry-point —
    /// the loader is invoked at most once per invocation, so a counting wrapper
    /// can verify the single-load invariant.
    pub fn with_store_loader(loaded: LoadResult, json: bool, loader: StoreLoader) -> Self {
        Self::with_loaded(loaded, json, loader)
    }

    fn with_loaded(loaded: LoadResult, json: bool, loader: StoreLoader) -> Self {
        let terminal = Terminal::detect();
        Self {
            loaded,
            terminal,
            json,
            store_loader: loader,
            catalog_cache: None,
            catalog_attempted: false,
            prelude_rendered: false,
            trust_warning_rendered: false,
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
    ///
    /// Reachable only from the per-subcommand builders in `crate::output`.
    pub(crate) fn render_prelude_advisories(&mut self) {
        if self.json || self.prelude_rendered {
            return;
        }
        self.prelude_rendered = true;

        if let Some(note) = trust::migration_note(&self.loaded) {
            output::write_layout(&mut io::stderr(), &note, &self.terminal);
        }

        self.ensure_trust_loaded();
        trust::render_integrity_advisories(
            self.catalog_cache.as_ref(),
            &self.terminal,
            &mut io::stderr(),
        );
    }

    /// Consult Trust for `command` in `mode`. On `Ok`, the pipeline's config
    /// has untrusted Loaded rules filtered in place. On `Err`, the caller
    /// serialises the block in its mode-appropriate response shape.
    ///
    /// Pure gate logic — emits no output. The trust warning advisory is
    /// rendered by the per-subcommand builder via
    /// [`Self::render_trust_warning`].
    pub(crate) fn consult_trust(
        &mut self,
        command: &str,
        mode: TrustMode,
    ) -> Result<(), TrustBlock> {
        self.ensure_trust_loaded();

        let catalog_ref = self.catalog_cache.as_ref().map(|s| &s.catalog);
        if let Some(block) = trust::check_block(command, mode, catalog_ref) {
            return Err(block);
        }

        let catalog_ref = self.catalog_cache.as_ref().map(|s| &s.catalog);
        trust::filter_untrusted(&mut self.loaded.config, catalog_ref);
        Ok(())
    }

    /// Render the Trust warning advisory to stderr. Reachable only from the
    /// per-subcommand builders in `crate::output`; no-op in JSON mode and
    /// idempotent across repeat calls within one invocation.
    pub(crate) fn render_trust_warning(&mut self) {
        if self.json || self.trust_warning_rendered {
            return;
        }
        self.trust_warning_rendered = true;
        self.ensure_trust_loaded();
        let catalog_ref = self.catalog_cache.as_ref().map(|s| &s.catalog);
        if let Some(layout) = trust::build_warning_advisory(catalog_ref) {
            output::write_layout(&mut io::stderr(), &layout, &self.terminal);
        }
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

    /// Lazily load the trust store and build the catalog. The injected loader
    /// is called at most once per invocation; the catalog is built once from
    /// the loader's result and the pipeline's loaded config.
    fn ensure_trust_loaded(&mut self) {
        if self.catalog_attempted {
            return;
        }
        self.catalog_attempted = true;
        let Some(state) = (self.store_loader)() else {
            return;
        };
        let catalog = build_catalog(&self.loaded.config, state.store);
        self.catalog_cache = Some(TrustCatalogState {
            catalog,
            suspects: state.suspects,
            was_corrupt: state.was_corrupt,
            store_path: state.store_path,
        });
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use may_i_config::LoadResult;
    use may_i_core::Decision;
    use may_i_core::ast::{Config, Effect, Provenance, Rule, Spanned};
    use may_i_core::pattern::CommandPattern;
    use may_i_core::span::Span;

    use crate::pipeline::CommandPipeline;
    use crate::trust::{TrustMode, TrustStoreState, store::TrustStore};

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

    fn config_with(rules: Vec<Rule>) -> Config {
        Config {
            rules,
            ..Config::default()
        }
    }

    fn loaded_result(rules: Vec<Rule>) -> LoadResult {
        LoadResult {
            config: config_with(rules),
            source_text: None,
            pre_migration_forms: None,
            config_path: PathBuf::from("/tmp/test-config.lisp"),
        }
    }

    fn empty_state() -> TrustStoreState {
        TrustStoreState {
            store: TrustStore::default(),
            suspects: Vec::new(),
            was_corrupt: false,
            store_path: PathBuf::from("/tmp/test-trust.json"),
        }
    }

    /// Spec: `trust-gate`/`Store loaded once per invocation` — the pipeline
    /// MUST load the store at most once even when an invocation renders the
    /// prelude advisories AND consults the gate.
    #[test]
    fn store_loads_once_per_invocation() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let loader = Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            Some(empty_state())
        });

        let loaded = loaded_result(vec![loaded_rule("git", "/tmp/rules.lisp")]);
        let mut pipeline = CommandPipeline::with_store_loader(loaded, false, loader);

        // Trigger every code path that needs the store.
        pipeline.render_prelude_advisories();
        let _ = pipeline.consult_trust("git status", TrustMode::Hook);
        let _ = pipeline.consult_trust("git status", TrustMode::Hook);
        pipeline.render_trust_warning();

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "store loader must be invoked exactly once per invocation"
        );
    }

    /// Spec: `command-pipeline`/`Idempotent on repeated calls` — the prelude
    /// is a one-shot.
    #[test]
    fn prelude_is_idempotent() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let loader = Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            Some(empty_state())
        });

        let loaded = loaded_result(vec![loaded_rule("git", "/tmp/rules.lisp")]);
        let mut pipeline = CommandPipeline::with_store_loader(loaded, false, loader);

        pipeline.render_prelude_advisories();
        pipeline.render_prelude_advisories();
        pipeline.render_prelude_advisories();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// Spec: `command-pipeline`/`JSON mode skips prelude advisories`.
    #[test]
    fn json_mode_prelude_is_noop() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let loader = Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            Some(empty_state())
        });

        let loaded = loaded_result(vec![loaded_rule("git", "/tmp/rules.lisp")]);
        let mut pipeline = CommandPipeline::with_store_loader(loaded, true, loader);
        pipeline.render_prelude_advisories();

        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "JSON-mode prelude must not load the store"
        );
    }

    use std::cell::Cell;

    use crate::pipeline::{CheckOutcomeBody, EvalOutcome, EvalOutcomeBody, InvocationMode};
    use may_i_engine::EvalResult;

    /// Spec: `command-pipeline`/`Check handler dispatches through run` —
    /// `run(Check, …)` invokes the closure on the no-filter path.
    #[test]
    fn run_check_invokes_closure() {
        let loaded = loaded_result(vec![]);
        let mut pipeline = CommandPipeline::with_store_loader(loaded, true, Box::new(|| None));
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

    /// Spec: `trust-gate`/`Hook mode block reason includes file paths` —
    /// `run(Hook, …)` short-circuits the closure on a trust block.
    #[test]
    fn run_hook_short_circuits_on_block() {
        let loaded = loaded_result(vec![loaded_rule("echo", "/tmp/rules.lisp")]);
        let mut pipeline =
            CommandPipeline::with_store_loader(loaded, true, Box::new(|| Some(empty_state())));
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

    /// Spec: `command-pipeline`/`Eval handler dispatches through run` —
    /// `run(Eval, …)` invokes the closure when trust allows.
    #[test]
    fn run_eval_invokes_closure_when_trust_allows() {
        let loaded = loaded_result(vec![]);
        let mut pipeline = CommandPipeline::with_store_loader(loaded, false, Box::new(|| None));
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
