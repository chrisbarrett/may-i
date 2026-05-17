// Unified per-rule trust view: the join of engine-computed canonical
// metadata with trust-store approval state.
//
// `TrustCatalog` is the cross-cutting consumer surface. CLI handlers (gate,
// advisory, listing, review) take `&TrustCatalog` and never touch the bare
// `TrustStore` or `TrustViewMeta` types directly. Mutations go through
// `set_state` / `set_state_for_each`; persistence is a separate `save` call.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use may_i_core::ast::Config;
use may_i_engine::trust::{TrustViewMeta, compute_trust_views};

use crate::trust::store::{TrustCheck, TrustStore};

/// Approval state for a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustState {
    Approved,
    Blocked,
    Pending,
}

/// Unified per-rule view: canonical metadata + approval state. Constructed by
/// [`build_catalog`]; consumers read via accessor methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustView {
    hash: String,
    canonical_form: String,
    program: String,
    source_file: Option<PathBuf>,
    position: usize,
    state: TrustState,
}

impl TrustView {
    pub(crate) fn from_meta(meta: TrustViewMeta, state: TrustState) -> Self {
        Self {
            hash: meta.hash,
            canonical_form: meta.canonical_form,
            program: meta.program,
            source_file: meta.source_file,
            position: meta.position,
            state,
        }
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }
    pub fn canonical_form(&self) -> &str {
        &self.canonical_form
    }
    pub fn program(&self) -> &str {
        &self.program
    }
    pub fn source_file(&self) -> Option<&Path> {
        self.source_file.as_deref()
    }
    pub fn position(&self) -> usize {
        self.position
    }
    pub fn state(&self) -> TrustState {
        self.state
    }
}

/// Owned collection of `TrustView`s joined with their backing `TrustStore`.
/// Mutating `set_state` updates both the view's state and the underlying
/// store; persistence is a separate `save` call.
pub struct TrustCatalog {
    views: Vec<TrustView>,
    store: TrustStore,
}

impl TrustCatalog {
    pub fn iter(&self) -> impl Iterator<Item = &TrustView> {
        self.views.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.views.is_empty()
    }

    pub fn len(&self) -> usize {
        self.views.len()
    }

    /// Group views by program name in lexical program order, preserving each
    /// program's per-program iteration order (which matches the engine's
    /// position-within-program ordering).
    pub fn group_by_program(&self) -> BTreeMap<&str, Vec<&TrustView>> {
        let mut groups: BTreeMap<&str, Vec<&TrustView>> = BTreeMap::new();
        for v in &self.views {
            groups.entry(v.program.as_str()).or_default().push(v);
        }
        groups
    }

    /// Iterate views whose state is not `Approved`. Drives gate filtering
    /// and advisory body composition.
    pub fn untrusted_loaded(&self) -> impl Iterator<Item = &TrustView> {
        self.views
            .iter()
            .filter(|v| v.state != TrustState::Approved)
    }

    pub fn find_by_hash(&self, hash: &str) -> Option<&TrustView> {
        self.views.iter().find(|v| v.hash == hash)
    }

    /// Set the state of the view with the given hash, mirroring the change
    /// into the underlying store. No-op if no view has that hash.
    pub fn set_state(&mut self, hash: &str, state: TrustState) {
        let Some(view) = self.views.iter_mut().find(|v| v.hash == hash) else {
            return;
        };
        view.state = state;
        match state {
            TrustState::Approved => self.store.approve_rule(
                view.hash.clone(),
                view.program.clone(),
                view.canonical_form.clone(),
            ),
            TrustState::Blocked => self.store.block_rule(
                view.hash.clone(),
                view.program.clone(),
                view.canonical_form.clone(),
            ),
            TrustState::Pending => {
                // No persistence path: the store has no "pending" entry, so a
                // transition to Pending would correspond to removing the
                // entry. No caller exercises this today.
            }
        }
    }

    /// Borrow the underlying store for read-only operations (integrity-check
    /// peers, rehash flows). Mutating callers go through `set_state`.
    pub(crate) fn store(&self) -> &TrustStore {
        &self.store
    }

    /// Persist the catalog by saving the underlying store.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        self.store.save(path)
    }
}

/// Join engine-computed per-rule metadata with trust-store state into the
/// unified catalog. The catalog takes ownership of `store` so subsequent
/// `set_state` calls can update persistence-side state in one place.
pub(crate) fn build_catalog(config: &Config, store: TrustStore) -> TrustCatalog {
    let metas = compute_trust_views(config);
    let views = metas
        .into_iter()
        .map(|meta| {
            let state = match store.check_rule(&meta.hash) {
                TrustCheck::Approved => TrustState::Approved,
                TrustCheck::Blocked => TrustState::Blocked,
                TrustCheck::Pending => TrustState::Pending,
            };
            TrustView::from_meta(meta, state)
        })
        .collect();
    TrustCatalog { views, store }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use may_i_core::Decision;
    use may_i_core::ast::{Config, Effect, Provenance, Rule, Spanned};
    use may_i_core::pattern::CommandPattern;
    use may_i_core::span::Span;
    use may_i_engine::trust::{canonical_rule, hash_rule};
    use proptest::prelude::*;

    use super::*;

    fn spanned<T>(value: T) -> Spanned<T> {
        Spanned::new(value, Span::new(0, 0))
    }

    fn loaded_rule(cmd: &str, decision: Decision, path: &str) -> Rule {
        Rule {
            command_effect: spanned(Effect::CommandPattern(CommandPattern::Literal(cmd.into()))),
            effect: spanned(Effect::Terminal {
                decision,
                reason: None,
            }),
            checks: vec![],
            span: Span::new(0, 0),
            provenance: Provenance::Loaded {
                path: PathBuf::from(path),
            },
        }
    }

    fn config_of(rules: Vec<Rule>) -> Config {
        Config {
            rules,
            ..Config::default()
        }
    }

    #[test]
    fn join_pending_when_store_empty() {
        let cfg = config_of(vec![loaded_rule("git", Decision::Allow, "/r.lisp")]);
        let cat = build_catalog(&cfg, TrustStore::default());
        assert_eq!(cat.len(), 1);
        let view = cat.iter().next().unwrap();
        assert_eq!(view.state(), TrustState::Pending);
        assert_eq!(view.program(), "git");
    }

    #[test]
    fn join_approved_when_store_has_matching_entry() {
        let rule = loaded_rule("git", Decision::Allow, "/r.lisp");
        let form = canonical_rule(&rule);
        let hash = hash_rule(&form);

        let mut store = TrustStore::default();
        store.approve_rule(hash.clone(), "git".into(), form);

        let cat = build_catalog(&config_of(vec![rule]), store);
        assert_eq!(
            cat.find_by_hash(&hash).unwrap().state(),
            TrustState::Approved
        );
    }

    #[test]
    fn join_blocked_when_store_blocks_hash() {
        let rule = loaded_rule("rm", Decision::Allow, "/r.lisp");
        let form = canonical_rule(&rule);
        let hash = hash_rule(&form);

        let mut store = TrustStore::default();
        store.block_rule(hash.clone(), "rm".into(), form);

        let cat = build_catalog(&config_of(vec![rule]), store);
        assert_eq!(
            cat.find_by_hash(&hash).unwrap().state(),
            TrustState::Blocked
        );
    }

    #[test]
    fn set_state_approve_then_save_round_trips() {
        let rule = loaded_rule("git", Decision::Allow, "/r.lisp");
        let form = canonical_rule(&rule);
        let hash = hash_rule(&form);

        let mut cat = build_catalog(&config_of(vec![rule]), TrustStore::default());
        cat.set_state(&hash, TrustState::Approved);
        assert_eq!(
            cat.find_by_hash(&hash).unwrap().state(),
            TrustState::Approved
        );

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");
        cat.save(&path).unwrap();

        let reloaded = TrustStore::load(&path).unwrap().store;
        assert_eq!(reloaded.check_rule(&hash), TrustCheck::Approved);
    }

    #[test]
    fn untrusted_loaded_yields_non_approved_views() {
        let g = loaded_rule("git", Decision::Allow, "/r.lisp");
        let c = loaded_rule("cargo", Decision::Allow, "/r.lisp");
        let g_form = canonical_rule(&g);
        let g_hash = hash_rule(&g_form);

        let mut store = TrustStore::default();
        store.approve_rule(g_hash.clone(), "git".into(), g_form);

        let cat = build_catalog(&config_of(vec![g, c]), store);
        let untrusted: Vec<&str> = cat.untrusted_loaded().map(|v| v.program()).collect();
        assert_eq!(untrusted, vec!["cargo"]);
    }

    proptest! {
        /// Per-rule join is total and ordered: for any `(Config, TrustStore)`
        /// pair, `build_catalog` returns one view per engine-emitted meta in
        /// the same order. Spec: `trust-store` / `Per-rule view carries
        /// approval state`.
        #[test]
        fn prop_join_is_total_and_in_engine_order(
            programs in prop::collection::vec("[a-z]{1,8}", 0..6),
            paths in prop::collection::vec("/r[a-z]{1,4}\\.lisp", 0..6)
        ) {
            // Pair programs and paths up to the shorter length; produce
            // loaded rules. Empty pair = empty config.
            let n = programs.len().min(paths.len());
            let rules: Vec<Rule> = (0..n)
                .map(|i| loaded_rule(&programs[i], Decision::Allow, &paths[i]))
                .collect();
            let cfg = config_of(rules);

            let metas = may_i_engine::trust::compute_trust_views(&cfg);
            let cat = build_catalog(&cfg, TrustStore::default());

            prop_assert_eq!(cat.len(), metas.len());
            for (view, meta) in cat.iter().zip(metas.iter()) {
                prop_assert_eq!(view.hash(), &meta.hash);
                prop_assert_eq!(view.program(), &meta.program);
                prop_assert_eq!(view.state(), TrustState::Pending);
            }
        }

        /// Store entries matching a rule's hash surface as `Approved`;
        /// missing entries surface as `Pending`. Spec scenarios `Per-rule
        /// view carries approval state` and `Loaded rule absent from store
        /// maps to Pending`. Use distinct command names so each rule has a
        /// distinct hash; the hash-collision case is checked separately.
        #[test]
        fn prop_state_mirrors_store_lookup(
            cmd_count in 1usize..6,
            approve_mask in prop::collection::vec(any::<bool>(), 1..6)
        ) {
            let cmds: Vec<String> = (0..cmd_count).map(|i| format!("cmd{i}")).collect();
            let rules: Vec<Rule> = cmds
                .iter()
                .map(|c| loaded_rule(c, Decision::Allow, "/r.lisp"))
                .collect();
            let cfg = config_of(rules.clone());

            let mut store = TrustStore::default();
            let mut expected_states = Vec::with_capacity(cmds.len());
            for (rule, approve) in rules.iter().zip(approve_mask.iter().cycle()) {
                let form = canonical_rule(rule);
                let hash = hash_rule(&form);
                if *approve {
                    let prog = match &rule.command_effect.value {
                        Effect::CommandPattern(CommandPattern::Literal(s)) => s.clone(),
                        _ => unreachable!(),
                    };
                    store.approve_rule(hash, prog, form);
                    expected_states.push(TrustState::Approved);
                } else {
                    expected_states.push(TrustState::Pending);
                }
            }

            let cat = build_catalog(&cfg, store);
            for (view, expected) in cat.iter().zip(expected_states.iter()) {
                prop_assert_eq!(view.state(), *expected);
            }
        }
    }
}
