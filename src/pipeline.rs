// Per-invocation orchestration shared by evaluation subcommands.
//
// Owns the loaded config, the detected terminal, the json flag, and one
// `InvocationTrust` collaborator that holds the per-invocation Trust state
// (lazily-loaded catalog, idempotency flags, store-loader seam). Subcommands
// drive their flow through one of the three typed entry points
// (`run_eval`, `run_check`, `run_hook`); the prelude (migration note +
// integrity advisory) and Trust consultation delegate to `InvocationTrust`
// so they are not duplicated.

use std::path::Path;

use may_i_config::LoadResult;
use may_i_core::ast::{AuditConfig, Config};
use may_i_engine::EvalResult;
use may_i_engine::check::CheckResult;

use crate::annotation::TraceEntry;
use crate::audit::{self, AuditMode, AuditRecord, AuditTap};
use crate::cmd_check::TraceExtra;
use crate::output::{self, Terminal};
use crate::trust::{InvocationTrust, TrustBlock, TrustMode};

/// Which agent harness is driving this hook invocation. Selected once at
/// hook entry from the parsed stdin payload, then threaded through
/// `run_hook` so renderers can branch on the harness-specific response
/// shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarnessProfile {
    /// Claude Code's PreToolUse hook protocol.
    ClaudeCode,
    /// Codex's PreToolUse hook protocol. Distinguished by the presence of
    /// a `turn_id` field in the stdin payload.
    Codex,
}

impl HarnessProfile {
    /// Select a profile from the parsed stdin payload. Codex iff the
    /// top-level object contains a `turn_id` key (presence only — the
    /// value is opaque); otherwise Claude Code.
    pub fn from_payload(payload: &serde_json::Value) -> Self {
        if payload.get("turn_id").is_some() {
            HarnessProfile::Codex
        } else {
            HarnessProfile::ClaudeCode
        }
    }

    /// The harness name recorded in audit records.
    pub fn name(self) -> &'static str {
        match self {
            HarnessProfile::ClaudeCode => "claude-code",
            HarnessProfile::Codex => "codex",
        }
    }
}

/// Borrowed evaluation context handed to the closure in one of the
/// pipeline's `run_*` entry points. Carries the loaded config and the
/// per-invocation terminal / path facts that the closure needs to produce
/// its typed body. Crucially does *not* carry `&mut CommandPipeline` — the
/// closure cannot re-drive the prelude, re-consult trust, or re-pick the
/// renderer.
pub struct EvalContext<'a> {
    pub config: &'a Config,
    pub loaded: &'a LoadResult,
    pub terminal: &'a Terminal,
    pub config_path: &'a Path,
    pub display_path: String,
}

/// Eval handler payload: one engine result, the captured trace, the
/// colourised command echo (used only by the text renderer), and the
/// pre-shortened config path.
pub struct EvalOutcomeBody {
    pub command: String,
    pub colored: may_i_output::Styled,
    pub result: EvalResult,
    pub traces: Vec<TraceEntry>,
    pub display_path: String,
    /// Audit data captured during evaluation, emitted by `run_eval` after
    /// rendering (gated by threshold). Not rendered.
    pub audit: AuditTap,
}

/// Hook handler payload: the engine result plus the audit data captured by
/// the same evaluation, emitted by `run_hook` after the JSON envelope.
pub struct HookOutcomeBody {
    pub result: EvalResult,
    pub audit: AuditTap,
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
    /// Names of scope-dependent env rules with no `(with-env …)` coverage.
    /// Rendered as a non-failing `warn` advisory.
    pub untested_scope_rules: Vec<String>,
}

pub struct CommandPipeline {
    loaded: LoadResult,
    terminal: Terminal,
    json: bool,
    trust: InvocationTrust,
    /// Effective audit settings (after flag/env/form resolution). Defaults
    /// to disabled; the CLI sets it before driving an eval/hook.
    audit: AuditConfig,
}

impl CommandPipeline {
    /// Load config + detect terminal and build a pipeline using the default
    /// trust-store loader.
    pub fn load(config_path: Option<&Path>, json: bool) -> miette::Result<Self> {
        let loaded = may_i_config::load_and_resolve(config_path)?;
        crate::sink::flush_config_advisories();
        // Shape check runs after parser resolution and before trust
        // filtering: a value-shape mismatch is a hard load error,
        // surfaced consistently across every command that loads config.
        let mismatches = may_i_engine::shape_check::check_config(&loaded.config);
        if let Some(source) = loaded.source_text.as_deref() {
            let path = loaded.config_path.display().to_string();
            if let Some(report) = crate::shape_diag::build_report(&mismatches, source, &path) {
                return Err(report);
            }
        }
        Ok(Self::with_trust(loaded, json, InvocationTrust::new(json)))
    }

    /// Construct a pipeline with a pre-built `InvocationTrust`. Test
    /// entry-point — callers build the trust collaborator (typically via
    /// `InvocationTrust::with_loader`) so the single-load invariant can be
    /// asserted against a counting loader.
    pub fn with_trust(loaded: LoadResult, json: bool, trust: InvocationTrust) -> Self {
        Self {
            loaded,
            terminal: crate::sink::terminal(),
            json,
            trust,
            audit: AuditConfig::default(),
        }
    }

    /// Set the effective audit configuration (after flag/env/form
    /// resolution). Called by the CLI before driving an eval or hook.
    pub fn set_audit(&mut self, audit: AuditConfig) {
        self.audit = audit;
    }

    /// Build and emit one audit record for `tap`, gated by the effective
    /// threshold. Best-effort: any write failure is swallowed and cannot
    /// alter the decision, the rendered output, or the exit code. This is the
    /// single emit seam for both the eval and hook terminal points.
    fn emit_audit(&self, mode: AuditMode, harness: Option<&str>, command: &str, tap: &AuditTap) {
        // A Trust-gate short-circuit carries an `ask` decision but is a
        // security-relevant block: it is recorded whenever auditing is on, so
        // the trail never silently omits a command blocked for approval.
        let force_trust_block =
            !self.audit.threshold.is_off() && tap.source == crate::audit::AuditSource::TrustBlock;
        if !force_trust_block
            && !audit::should_record(self.audit.threshold, tap.decision, tap.parse_ok)
        {
            return;
        }
        let record = AuditRecord::new(
            audit::timestamp_now(),
            mode,
            harness.map(str::to_string),
            command.to_string(),
            tap.decision,
            tap.reason.clone(),
            tap.source,
            tap.parse_ok,
            tap.diagnostic.clone(),
            tap.rules.clone(),
            self.loaded.config_path.display().to_string(),
            tap.cwd.clone(),
        );
        let Ok(line) = record.to_json_line() else {
            return;
        };
        if let Some(path) = self.audit.file.clone().or_else(audit::default_audit_path) {
            audit::append_best_effort(&path, &line);
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
        let loaded = &self.loaded;
        let terminal = &self.terminal;
        let trust = &mut self.trust;
        crate::sink::with_stderr(|w| trust.render_prelude(loaded, terminal, w));
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
        let terminal = &self.terminal;
        let trust = &mut self.trust;
        crate::sink::with_stderr(|w| trust.render_warning(terminal, w));
    }

    /// Shared prelude + trust flow used by `run_eval`, `run_check`, `run_hook`.
    ///
    /// `prelude` toggles text-mode advisories (skipped for Hook).
    /// `consult` selects the gate path (Eval/Hook) vs the warning-only path
    /// (Check); on the consult path, `Err(block)` short-circuits the caller.
    /// `warn_after` re-emits the trust warning after a successful gate
    /// consultation (Eval text mode only).
    fn prelude_and_trust(
        &mut self,
        command: &str,
        trust_mode: TrustMode,
        prelude: bool,
        consult: bool,
        warn_after: bool,
    ) -> Result<(), TrustBlock> {
        if prelude {
            self.render_prelude_advisories();
        }
        if consult {
            self.consult_trust(command, trust_mode)?;
            if warn_after {
                self.render_trust_warning();
            }
        } else {
            self.render_trust_warning();
        }
        Ok(())
    }

    /// `may-i eval` entry point. Drives the prelude + trust consultation,
    /// invokes the closure on the allow path, and dispatches its
    /// `EvalOutcomeBody` to the text-or-JSON renderer.
    pub fn run_eval<F>(&mut self, command: &str, closure: F) -> miette::Result<()>
    where
        F: FnOnce(&EvalContext<'_>) -> miette::Result<EvalOutcomeBody>,
    {
        let trust_mode = TrustMode::for_eval(self.json);
        if let Err(block) = self.prelude_and_trust(command, trust_mode, true, true, !self.json) {
            self.emit_audit(
                AuditMode::Eval,
                None,
                command,
                &AuditTap::trust_block(block.decision, block.reason.clone()),
            );
            let terminal = &self.terminal;
            let json = self.json;
            crate::sink::with_stdout(|out| {
                crate::sink::with_stderr(|err| {
                    output::render_eval_trust_block(out, err, terminal, &block, json);
                });
            });
            return Ok(());
        }

        let display_path = output::shorten_home(&self.loaded.config_path);
        let body = {
            let ctx = EvalContext {
                config: &self.loaded.config,
                loaded: &self.loaded,
                terminal: &self.terminal,
                config_path: &self.loaded.config_path,
                display_path,
            };
            closure(&ctx)?
        };

        let terminal = &self.terminal;
        let json = self.json;
        crate::sink::with_stdout(|w| output::render_eval(w, terminal, json, &body));
        self.emit_audit(AuditMode::Eval, None, command, &body.audit);
        Ok(())
    }

    /// `may-i check` entry point. Drives the prelude and trust warning
    /// (Check never consults the gate), invokes the closure, and dispatches
    /// its `CheckOutcomeBody` to the text-or-JSON renderer.
    pub fn run_check<F>(&mut self, closure: F) -> miette::Result<()>
    where
        F: FnOnce(&EvalContext<'_>) -> miette::Result<CheckOutcomeBody>,
    {
        // `consult = false` routes through the warning-only branch; the
        // `trust_mode` argument is unused on that branch.
        let _ = self.prelude_and_trust("", TrustMode::Text, true, false, false);

        let display_path = output::shorten_home(&self.loaded.config_path);
        let body = {
            let ctx = EvalContext {
                config: &self.loaded.config,
                loaded: &self.loaded,
                terminal: &self.terminal,
                config_path: &self.loaded.config_path,
                display_path,
            };
            closure(&ctx)?
        };

        let terminal = &self.terminal;
        let json = self.json;
        crate::sink::with_stdout(|w| output::render_check(w, terminal, json, &body));
        Ok(())
    }

    /// PreToolUse hook entry point. Skips the prelude (Hook is JSON-only),
    /// consults trust, invokes the closure on the allow path, and emits
    /// the hook JSON envelope in the shape dictated by `profile`.
    pub fn run_hook<F>(
        &mut self,
        command: &str,
        profile: HarnessProfile,
        closure: F,
    ) -> miette::Result<()>
    where
        F: FnOnce(&EvalContext<'_>) -> miette::Result<HookOutcomeBody>,
    {
        if let Err(block) = self.prelude_and_trust(command, TrustMode::Hook, false, true, false) {
            self.emit_audit(
                AuditMode::Hook,
                Some(profile.name()),
                command,
                &AuditTap::trust_block(block.decision, block.reason.clone()),
            );
            crate::sink::with_stdout(|w| output::render_hook_trust_block(w, profile, &block));
            return Ok(());
        }

        let display_path = output::shorten_home(&self.loaded.config_path);
        let body = {
            let ctx = EvalContext {
                config: &self.loaded.config,
                loaded: &self.loaded,
                terminal: &self.terminal,
                config_path: &self.loaded.config_path,
                display_path,
            };
            closure(&ctx)?
        };

        crate::sink::with_stdout(|w| output::render_hook(w, profile, &body.result));
        self.emit_audit(AuditMode::Hook, Some(profile.name()), command, &body.audit);
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

    use crate::audit::{AuditSource, AuditTap};
    use crate::pipeline::{
        CheckOutcomeBody, CommandPipeline, EvalOutcomeBody, HarnessProfile, HookOutcomeBody,
    };
    use crate::trust::{InvocationTrust, TrustMode, store::TrustStore};

    fn spanned<T>(value: T) -> Spanned<T> {
        Spanned::new(value, Span::new(0, 0))
    }

    fn sample_tap() -> AuditTap {
        AuditTap {
            decision: Decision::Allow,
            reason: None,
            source: AuditSource::Rule,
            parse_ok: true,
            diagnostic: None,
            rules: vec![],
            cwd: None,
        }
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

    /// Spec: `command-pipeline` / `Check handler dispatches through run_check`
    /// — `run_check` invokes the typed closure on the no-filter path.
    #[test]
    fn run_check_invokes_closure() {
        let loaded = loaded_result(vec![]);
        let trust = InvocationTrust::with_loader(true, Box::new(|| None));
        let mut pipeline = CommandPipeline::with_trust(loaded, true, trust);
        let invoked = Cell::new(false);
        pipeline
            .run_check(|_ctx| {
                invoked.set(true);
                Ok(CheckOutcomeBody {
                    results: vec![],
                    verbose: false,
                    passed: 0,
                    failed: 0,
                    display_path: "/tmp/cfg.lisp".into(),
                    untested_scope_rules: vec![],
                })
            })
            .expect("run check");
        assert!(invoked.get(), "Check arm must invoke the closure");
    }

    /// Spec: `trust-gate` / `Hook mode block reason includes file paths` —
    /// `run_hook` short-circuits the closure on a trust block.
    #[test]
    fn run_hook_short_circuits_on_block() {
        let loaded = loaded_result(vec![loaded_rule("echo", "/tmp/rules.lisp")]);
        let trust = InvocationTrust::with_loader(true, Box::new(|| Some(empty_state())));
        let mut pipeline = CommandPipeline::with_trust(loaded, true, trust);
        let invoked = Cell::new(false);
        pipeline
            .run_hook("echo hi", HarnessProfile::ClaudeCode, |_ctx| {
                invoked.set(true);
                Ok(HookOutcomeBody {
                    result: EvalResult::new(Decision::Allow, None),
                    audit: sample_tap(),
                })
            })
            .expect("run hook");
        assert!(
            !invoked.get(),
            "Hook closure must NOT run when trust blocks"
        );
    }

    /// Spec: `audit-log` / `Trust-block outcomes are recorded` — a hook
    /// blocked by the Trust gate emits a record with source `trust-block`,
    /// distinct from a rule denial, when the threshold records denials.
    #[test]
    fn trust_block_emits_record_with_trust_block_source() {
        use may_i_core::ast::{AuditConfig, AuditThreshold};

        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("audit.jsonl");

        let loaded = loaded_result(vec![loaded_rule("echo", "/tmp/rules.lisp")]);
        let trust = InvocationTrust::with_loader(true, Box::new(|| Some(empty_state())));
        let mut pipeline = CommandPipeline::with_trust(loaded, true, trust);
        pipeline.set_audit(AuditConfig {
            threshold: AuditThreshold::Deny,
            file: Some(audit_path.clone()),
        });

        pipeline
            .run_hook("echo hi", HarnessProfile::ClaudeCode, |_ctx| {
                Ok(HookOutcomeBody {
                    result: EvalResult::new(Decision::Allow, None),
                    audit: sample_tap(),
                })
            })
            .expect("run hook");

        let contents = std::fs::read_to_string(&audit_path).expect("audit file written");
        let rec: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(rec["source"], "trust-block");
        assert_eq!(rec["mode"], "hook");
        assert_eq!(rec["harness"], "claude-code");
    }

    /// Spec: `command-pipeline` / `Eval handler dispatches through run_eval`
    /// — `run_eval` invokes the typed closure when trust allows.
    #[test]
    fn run_eval_invokes_closure_when_trust_allows() {
        let loaded = loaded_result(vec![]);
        let trust = InvocationTrust::with_loader(false, Box::new(|| None));
        let mut pipeline = CommandPipeline::with_trust(loaded, false, trust);
        let invoked = Cell::new(false);
        pipeline
            .run_eval("echo hi", |_ctx| {
                invoked.set(true);
                Ok(EvalOutcomeBody {
                    command: "echo hi".into(),
                    colored: "echo hi".into(),
                    result: EvalResult::new(Decision::Allow, None),
                    traces: vec![],
                    display_path: "/tmp/cfg.lisp".into(),
                    audit: sample_tap(),
                })
            })
            .expect("run eval");
        assert!(invoked.get(), "Eval closure must run on trust allow");
    }

    /// Spec: `command-pipeline` / `Single trust-store load is observable` —
    /// `run_eval` drives the prelude path through the same `InvocationTrust`,
    /// preserving the single-load invariant.
    #[test]
    fn store_loads_once_per_invocation() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let loader = Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            Some(empty_state())
        });
        let trust = InvocationTrust::with_loader(false, loader);
        let loaded = loaded_result(vec![loaded_rule("git", "/tmp/rules.lisp")]);
        let mut pipeline = CommandPipeline::with_trust(loaded, false, trust);

        pipeline
            .run_eval("git status", |_ctx| {
                Ok(EvalOutcomeBody {
                    command: "git status".into(),
                    colored: "git status".into(),
                    result: EvalResult::new(Decision::Allow, None),
                    traces: vec![],
                    display_path: "/tmp/cfg.lisp".into(),
                    audit: sample_tap(),
                })
            })
            .expect("run_eval");

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "run_eval must load the trust store at most once per invocation"
        );
    }

    /// Mode-to-body invariant is enforced statically by the closure type
    /// signatures on each `run_*` method:
    ///
    /// - `run_eval` requires `FnOnce(&EvalContext<'_>) -> miette::Result<EvalOutcomeBody>`
    /// - `run_check` requires `FnOnce(&EvalContext<'_>) -> miette::Result<CheckOutcomeBody>`
    /// - `run_hook` requires `FnOnce(&EvalContext<'_>) -> miette::Result<EvalResult>`
    ///
    /// A `run_check` closure that returned an `EvalOutcomeBody` would fail to
    /// type-check at compile time, not misrender at runtime. `trybuild` is
    /// not a dev-dep so we record the invariant here rather than add the
    /// dependency for one compile-fail fixture.
    #[test]
    fn closure_signatures_pin_mode_to_body() {
        fn _eval_takes_eval_body<F>(_: F)
        where
            F: FnOnce(&super::EvalContext<'_>) -> miette::Result<EvalOutcomeBody>,
        {
        }
        fn _check_takes_check_body<F>(_: F)
        where
            F: FnOnce(&super::EvalContext<'_>) -> miette::Result<CheckOutcomeBody>,
        {
        }
        fn _hook_takes_eval_result<F>(_: F)
        where
            F: FnOnce(&super::EvalContext<'_>) -> miette::Result<EvalResult>,
        {
        }
    }
}
