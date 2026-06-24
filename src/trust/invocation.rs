// Per-invocation Trust concern: owns the lazily-loaded catalog, idempotency
// flags, and the projection of `TrustMode`-shaped outcomes the pipeline asks
// for. `CommandPipeline` holds one of these and reaches Trust only through
// its public methods.

use std::io::Write;
use std::path::PathBuf;

use may_i_config::LoadResult;
use may_i_core::ast::Config;
use may_i_output::{Advisory, Layout, NoteHeading, NoteLevel, Style, Styled};

use crate::output::{self, Terminal};
use crate::trust::advisory;
use crate::trust::gate;
use crate::trust::store::{SuspectEntry, TrustStore, default_trust_store_path};
use crate::trust::view::{TrustCatalog, build_catalog};
use crate::trust::{TrustBlock, TrustMode, TrustStoreState};

/// Boxed trust-store loader. The documented test seam for the single-load
/// invariant: callers wrap the production loader (or a stub) in a counter
/// and pass it via [`InvocationTrust::with_loader`].
pub type StoreLoader = Box<dyn Fn() -> Option<TrustStoreState>>;

/// Joined per-invocation snapshot: the catalog (config + store), the store's
/// integrity-suspect list, the corrupt flag, and the path the store was loaded
/// from (used by integrity advisories).
struct InvocationCatalog {
    catalog: TrustCatalog,
    suspects: Vec<SuspectEntry>,
    was_corrupt: bool,
    store_path: PathBuf,
}

/// Owns the per-invocation Trust state and exposes the three operations the
/// pipeline drives during an evaluation: prelude advisories, gate
/// consultation, and the warning advisory.
///
/// The single-store-load invariant lives here: the loader runs at most once
/// per `InvocationTrust`, regardless of how many times `consult`,
/// `render_prelude`, or `render_warning` are called.
pub struct InvocationTrust {
    loader: StoreLoader,
    json: bool,
    catalog: Option<InvocationCatalog>,
    attempted: bool,
    prelude_rendered: bool,
    warning_rendered: bool,
}

impl InvocationTrust {
    pub fn new(json: bool) -> Self {
        Self::with_loader(json, Box::new(default_store_loader))
    }

    pub fn with_loader(json: bool, loader: StoreLoader) -> Self {
        Self {
            loader,
            json,
            catalog: None,
            attempted: false,
            prelude_rendered: false,
            warning_rendered: false,
        }
    }

    /// Consult Trust for `command` in `mode`. On `Ok` the loaded config has
    /// untrusted Loaded rules filtered in place; on `Err` the caller
    /// serialises the block in its mode-appropriate response shape.
    pub fn consult(
        &mut self,
        loaded: &mut LoadResult,
        command: &str,
        mode: TrustMode,
    ) -> Result<(), TrustBlock> {
        self.ensure_loaded(&loaded.config);
        if let Some(block) = self.check_block(command, mode) {
            return Err(block);
        }
        self.filter_untrusted(&mut loaded.config);
        Ok(())
    }

    /// Text-mode prelude: migration note (when applicable), then trust-store
    /// integrity advisories. No-op in JSON mode. Idempotent across repeat
    /// calls within one invocation.
    pub fn render_prelude(
        &mut self,
        loaded: &LoadResult,
        term: &Terminal,
        stderr: &mut impl Write,
    ) {
        if self.json || self.prelude_rendered {
            return;
        }
        self.prelude_rendered = true;

        if let Some(note) = self.migration_note(loaded) {
            output::write_layout(stderr, &note, term);
        }

        self.ensure_loaded(&loaded.config);
        self.render_integrity(term, stderr);
    }

    /// Render the untrusted-loaded warning advisory to stderr. No-op in JSON
    /// mode and idempotent across repeat calls within one invocation.
    pub fn render_warning(&mut self, term: &Terminal, stderr: &mut impl Write) {
        if self.json || self.warning_rendered {
            return;
        }
        self.warning_rendered = true;
        if let Some(layout) = self.build_warning() {
            output::write_layout(stderr, &layout, term);
        }
    }

    /// Build the migration-note advisory when the loaded config came from a
    /// transparent migration. Public so it remains testable and reachable
    /// from the migration-note advisory renderer.
    pub fn migration_note(&self, loaded: &LoadResult) -> Option<Layout> {
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
        let heading = NoteHeading::from(
            Styled::span(prefix, Style::Ask)
                .with(" ", Style::Plain)
                .with(display_path, Style::Strong),
        );
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

    fn ensure_loaded(&mut self, config: &Config) {
        if self.attempted {
            return;
        }
        self.attempted = true;
        let Some(state) = (self.loader)() else {
            return;
        };
        let catalog = build_catalog(config, state.store);
        self.catalog = Some(InvocationCatalog {
            catalog,
            suspects: state.suspects,
            was_corrupt: state.was_corrupt,
            store_path: state.store_path,
        });
    }

    fn check_block(&self, command: &str, mode: TrustMode) -> Option<TrustBlock> {
        let catalog = &self.catalog.as_ref()?.catalog;
        match mode {
            TrustMode::Text => None,
            TrustMode::Json => gate::json_block(catalog, command),
            TrustMode::Hook => gate::hook_block(catalog, command),
        }
    }

    fn filter_untrusted(&self, config: &mut Config) {
        if let Some(state) = self.catalog.as_ref() {
            advisory::filter_trusted_rules(config, &state.catalog);
        }
    }

    fn build_warning(&self) -> Option<Layout> {
        let state = self.catalog.as_ref()?;
        advisory::build_warning_layout(&state.catalog)
    }

    fn render_integrity(&self, term: &Terminal, stderr: &mut impl Write) {
        let Some(state) = self.catalog.as_ref() else {
            return;
        };
        if state.catalog.is_empty() {
            return;
        }
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
        output::render_advisory_stack(stderr, term, &stack);
    }
}

/// Production trust-store loader. Returns `None` when the store path cannot
/// be determined; IO failures collapse into a state with `was_corrupt: true`
/// and an empty store so callers can render the integrity advisory.
fn default_store_loader() -> Option<TrustStoreState> {
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

    use crate::output::Terminal;
    use crate::trust::store::TrustStore;
    use crate::trust::{TrustMode, TrustStoreState};

    use super::InvocationTrust;

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

    fn empty_state() -> TrustStoreState {
        TrustStoreState {
            store: TrustStore::default(),
            suspects: Vec::new(),
            was_corrupt: false,
            store_path: PathBuf::from("/tmp/test-trust.json"),
        }
    }

    fn counting_loader() -> (Arc<AtomicUsize>, super::StoreLoader) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let loader = Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            Some(empty_state())
        });
        (calls, loader)
    }

    /// Spec: `trust-gate` / `Store loaded once per invocation`.
    #[test]
    fn invocation_trust_loads_store_once() {
        let (calls, loader) = counting_loader();
        let mut trust = InvocationTrust::with_loader(false, loader);
        let mut loaded = loaded_result(vec![loaded_rule("git", "/tmp/rules.lisp")]);
        let term = Terminal::new(80);
        let mut buf: Vec<u8> = Vec::new();

        trust.render_prelude(&loaded, &term, &mut buf);
        let _ = trust.consult(&mut loaded, "git status", TrustMode::Hook);
        let _ = trust.consult(&mut loaded, "git status", TrustMode::Hook);
        trust.render_warning(&term, &mut buf);

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "store loader must be invoked exactly once per invocation"
        );
    }

    /// Spec: `command-pipeline` / `Idempotent on repeated calls`.
    #[test]
    fn invocation_trust_prelude_is_idempotent() {
        let (calls, loader) = counting_loader();
        let mut trust = InvocationTrust::with_loader(false, loader);
        let loaded = loaded_result(vec![loaded_rule("git", "/tmp/rules.lisp")]);
        let term = Terminal::new(80);

        let mut buf1: Vec<u8> = Vec::new();
        trust.render_prelude(&loaded, &term, &mut buf1);
        let mut buf2: Vec<u8> = Vec::new();
        trust.render_prelude(&loaded, &term, &mut buf2);
        let mut buf3: Vec<u8> = Vec::new();
        trust.render_prelude(&loaded, &term, &mut buf3);

        assert_eq!(calls.load(Ordering::SeqCst), 1, "single load");
        assert!(
            buf2.is_empty() && buf3.is_empty(),
            "subsequent prelude calls render nothing"
        );
    }

    /// Spec: `command-pipeline` / `JSON mode skips prelude advisories`.
    #[test]
    fn invocation_trust_json_mode_skips_prelude() {
        let (calls, loader) = counting_loader();
        let mut trust = InvocationTrust::with_loader(true, loader);
        let loaded = loaded_result(vec![loaded_rule("git", "/tmp/rules.lisp")]);
        let term = Terminal::new(80);
        let mut buf: Vec<u8> = Vec::new();

        trust.render_prelude(&loaded, &term, &mut buf);

        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "JSON-mode prelude must not load the store"
        );
        assert!(buf.is_empty(), "JSON-mode prelude must write nothing");
    }
}
