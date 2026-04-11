// LoadedConfig bundles a parsed Config with source metadata needed for tracing.

use may_i_core::Span;
use may_i_core::ast::Config;
use may_i_core::doc::Doc;

/// A parsed config together with the source metadata needed for trace rendering.
pub struct LoadedConfig {
    pub config: Config,
    pub source_text: Option<String>,
    pub pre_migration_forms: Option<Vec<(Span, Doc<()>)>>,
}

impl From<may_i_config::LoadResult> for LoadedConfig {
    fn from(r: may_i_config::LoadResult) -> Self {
        Self {
            config: r.config,
            source_text: r.source_text,
            pre_migration_forms: r.pre_migration_forms,
        }
    }
}
