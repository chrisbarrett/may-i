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

use crate::output::{self, Terminal};
use crate::trust::view::build_catalog;
use crate::trust::{self, TrustBlock, TrustCatalogState, TrustMode, TrustStoreState};

type StoreLoader = Box<dyn Fn() -> Option<TrustStoreState>>;

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
    pub fn consult_trust(&mut self, command: &str, mode: TrustMode) -> Result<(), TrustBlock> {
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
}
