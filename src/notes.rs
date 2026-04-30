// Advisory `Layout` builders that are not trace data.
//
// These return `Option<Layout>` / `Layout` and perform no IO; callers route
// the rendered output to their preferred sink (typically stderr).

use colored::Colorize;
use may_i_layout::{Advisory, Layout, NoteHeading, NoteLevel};

use crate::output;

/// Build a migration advisory note if the config was transparently migrated.
pub fn migration_note(
    loaded: &may_i_config::LoadResult,
    config_path: &std::path::Path,
) -> Option<Layout> {
    if loaded.pre_migration_forms.is_some() {
        let prog = std::env::args()
            .next()
            .map(|s| {
                std::path::Path::new(&s)
                    .file_name()
                    .map(|f| f.to_string_lossy().into_owned())
                    .unwrap_or(s)
            })
            .unwrap_or_else(|| "may-i".into());
        let display_path = output::shorten_home(config_path);
        let prefix = "Migrations available:";
        let heading = NoteHeading {
            text: format!("{} {}", prefix.yellow().bold(), display_path.bold(),),
            visible_width: prefix.len() + 1 + display_path.len(),
        };
        Some(
            Advisory {
                level: NoteLevel::Warn,
                heading: String::new(), // unused — overridden below
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
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use may_i_config::LoadResult;
    use may_i_core::ast::{Config, SecurityConfig};
    use std::path::PathBuf;

    fn loaded_with_pre_migration() -> LoadResult {
        LoadResult {
            config: Config {
                rules: vec![],
                defines: vec![],
                security: SecurityConfig::default(),
                checks: vec![],
            },
            config_path: PathBuf::from("/tmp/config.lisp"),
            source_text: None,
            pre_migration_forms: Some(vec![]),
        }
    }

    fn loaded_without_pre_migration() -> LoadResult {
        LoadResult {
            config: Config {
                rules: vec![],
                defines: vec![],
                security: SecurityConfig::default(),
                checks: vec![],
            },
            config_path: PathBuf::from("/tmp/config.lisp"),
            source_text: None,
            pre_migration_forms: None,
        }
    }

    fn render_text(layout: &Layout) -> String {
        let term = output::Terminal::new(60);
        let mut buf = Vec::new();
        output::write_layout(&mut buf, layout, &term);
        let raw = String::from_utf8(buf).unwrap();
        may_i_layout::strip_ansi(&raw)
    }

    #[test]
    fn returns_none_when_no_pre_migration() {
        let loaded = loaded_without_pre_migration();
        assert!(migration_note(&loaded, &PathBuf::from("/tmp/config.lisp")).is_none());
    }

    #[test]
    fn renders_migration_note_when_pre_migration_present() {
        let loaded = loaded_with_pre_migration();
        let path = PathBuf::from("/tmp/config.lisp");
        let layout = migration_note(&loaded, &path).unwrap();
        let output = render_text(&layout);
        assert!(output.contains("Migrations available:"), "{output}");
        assert!(output.contains("/tmp/config.lisp"), "{output}");
        assert!(output.contains("migrate"), "{output}");
    }
}
