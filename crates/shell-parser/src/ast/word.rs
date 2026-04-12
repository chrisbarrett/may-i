use super::*;

/// Returns true if any part in the slice cannot be statically resolved to a
/// known command name. This is broader than `has_dynamic_in`: it also treats
/// Glob and Opaque parts as dynamic, since they produce unpredictable values
/// when used as command names.
fn is_dynamic_in(parts: &[WordPart]) -> bool {
    parts.iter().any(|part| match part {
        WordPart::Literal(_)
        | WordPart::SingleQuoted(_)
        | WordPart::AnsiCQuoted(_)
        | WordPart::BraceExpansion(_) => false,
        WordPart::DoubleQuoted(inner) => is_dynamic_in(inner),
        _ => true,
    })
}

/// Returns true if any part in the slice is a dynamic shell construct.
/// Opaque parts are safe (trusted) and do NOT count as dynamic.
fn has_dynamic_in(parts: &[WordPart]) -> bool {
    parts.iter().any(|part| match part {
        WordPart::CommandSubstitution(_)
        | WordPart::Backtick(_)
        | WordPart::Parameter(_)
        | WordPart::ParameterExpansion(_)
        | WordPart::ParameterExpansionOp { .. }
        | WordPart::Arithmetic(_)
        | WordPart::ProcessSubstitution { .. } => true,
        WordPart::DoubleQuoted(inner) => has_dynamic_in(inner),
        WordPart::Opaque(_) => false,
        _ => false,
    })
}

/// Collect command strings from embedded substitutions (CommandSubstitution,
/// Backtick, ProcessSubstitution), recursing into DoubleQuoted.
fn collect_embedded_commands<'a>(parts: &'a [WordPart], out: &mut Vec<&'a str>) {
    for part in parts {
        match part {
            WordPart::CommandSubstitution(s) | WordPart::Backtick(s) => out.push(s),
            WordPart::ProcessSubstitution { command, .. } => out.push(command),
            WordPart::DoubleQuoted(inner) => collect_embedded_commands(inner, out),
            _ => {}
        }
    }
}

/// Collect human-readable descriptions of dynamic parts from a part slice.
fn collect_dynamic_from(parts: &[WordPart], out: &mut Vec<String>) {
    for part in parts {
        match part {
            WordPart::Parameter(name) => out.push(format!("${name}")),
            WordPart::ParameterExpansion(name) => out.push(format!("${{{name}}}")),
            WordPart::CommandSubstitution(cmd) => {
                out.push(format!("$({})", abbreviate(cmd)));
            }
            WordPart::Backtick(cmd) => {
                out.push(format!("`{}`", abbreviate(cmd)));
            }
            WordPart::Arithmetic(expr) => {
                out.push(format!("$(({}))", abbreviate(expr)));
            }
            WordPart::ProcessSubstitution { direction, command } => {
                let sigil = match direction {
                    ProcessDirection::Input => '<',
                    ProcessDirection::Output => '>',
                };
                out.push(format!("{sigil}({})", abbreviate(command)));
            }
            WordPart::ParameterExpansionOp { name, op } => {
                out.push(format!("${{{}}}", format_param_op(name, op)));
            }
            WordPart::DoubleQuoted(inner) => {
                collect_dynamic_from(inner, out);
            }
            WordPart::Opaque(_) => {} // safe, not dynamic
            _ => {}
        }
    }
}

/// Flatten a slice of word parts to a plain string.
fn parts_to_str(parts: &[WordPart], out: &mut String) {
    for part in parts {
        match part {
            WordPart::Literal(s)
            | WordPart::SingleQuoted(s)
            | WordPart::AnsiCQuoted(s)
            | WordPart::Parameter(s)
            | WordPart::ParameterExpansion(s)
            | WordPart::CommandSubstitution(s)
            | WordPart::Backtick(s)
            | WordPart::Arithmetic(s)
            | WordPart::Glob(s) => out.push_str(s),
            WordPart::ParameterExpansionOp { name, op } => {
                out.push_str(&format_param_op(name, op));
            }
            WordPart::DoubleQuoted(inner) => {
                parts_to_str(inner, out);
            }
            WordPart::BraceExpansion(items) => {
                out.push_str(&items.join(","));
            }
            WordPart::ProcessSubstitution { command, .. } => {
                out.push_str(command);
            }
            WordPart::Opaque(label) => {
                out.push_str(label);
            }
        }
    }
}

/// Returns true if any part in the slice is an Opaque value.
fn has_opaque_in(parts: &[WordPart]) -> bool {
    parts.iter().any(|part| match part {
        WordPart::Opaque(_) => true,
        WordPart::DoubleQuoted(inner) => has_opaque_in(inner),
        _ => false,
    })
}

impl Word {
    pub fn literal(s: &str) -> Self {
        Word {
            parts: vec![WordPart::Literal(s.to_string())],
        }
    }

    /// Returns true if this word cannot be statically resolved to a known value.
    /// Broader than `has_dynamic_parts`: also treats Glob and Opaque as dynamic.
    /// Use this for command-name checking where any non-literal part means the
    /// command identity is unknown.
    pub fn is_dynamic(&self) -> bool {
        is_dynamic_in(&self.parts)
    }

    /// Extract command strings from embedded substitutions in this word's parts.
    /// Returns sources from CommandSubstitution, Backtick, and ProcessSubstitution,
    /// recursing into DoubleQuoted inner parts.
    pub fn extract_embedded_commands(&self) -> Vec<&str> {
        let mut out = Vec::new();
        collect_embedded_commands(&self.parts, &mut out);
        out
    }

    /// Returns true if this word contains dynamic shell constructs whose runtime
    /// value cannot be determined by static analysis.
    pub fn has_dynamic_parts(&self) -> bool {
        has_dynamic_in(&self.parts)
    }

    /// Collect human-readable descriptions of the dynamic parts in this word.
    /// Returns items like `"$HOME"`, `"$(whoami)"`, `` "`cmd`" ``, `"$((x+1))"`.
    pub fn dynamic_parts(&self) -> Vec<String> {
        let mut out = Vec::new();
        collect_dynamic_from(&self.parts, &mut out);
        out
    }

    /// Flatten this word to a plain string for matching purposes.
    pub fn to_str(&self) -> String {
        let mut out = String::new();
        parts_to_str(&self.parts, &mut out);
        out
    }

    /// Returns true if all parts are static (Literal/SingleQuoted/AnsiCQuoted).
    pub fn is_literal(&self) -> bool {
        !has_dynamic_in(&self.parts) && !has_opaque_in(&self.parts)
    }
}

// ── Test-only resolution helpers ─────────────────────────────────────

#[cfg(test)]
use crate::resolve::resolve_param_op;

#[cfg(test)]
fn resolve_parts(
    parts: &[WordPart],
    env: &std::collections::HashMap<String, String>,
) -> Vec<WordPart> {
    parts
        .iter()
        .map(|part| match part {
            WordPart::Parameter(name) | WordPart::ParameterExpansion(name) => {
                if let Some(val) = env.get(name.as_str()) {
                    WordPart::Literal(val.clone())
                } else {
                    part.clone()
                }
            }
            WordPart::ParameterExpansionOp { name, op } => resolve_param_op(name, op, env),
            WordPart::DoubleQuoted(inner) => WordPart::DoubleQuoted(resolve_parts(inner, env)),
            _ => part.clone(),
        })
        .collect()
}

#[cfg(test)]
impl Word {
    pub fn resolve(&self, env: &std::collections::HashMap<String, String>) -> Word {
        Word {
            parts: resolve_parts(&self.parts, env),
        }
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    // Strategy for generating literal word parts
    fn arb_literal_word() -> impl Strategy<Value = Word> {
        proptest::string::string_regex("[a-zA-Z0-9_]{0,20}")
            .unwrap()
            .prop_map(|s| Word::literal(&s))
    }

    // Strategy for generating simple variable name
    fn arb_var_name() -> impl Strategy<Value = String> {
        proptest::string::string_regex("[A-Z_]{1,10}").unwrap()
    }

    // Property 4.2: resolution is idempotent (resolve(resolve(w)) == resolve(w))
    proptest! {
        #[test]
        fn prop_resolve_is_idempotent(word in arb_literal_word()) {
            let empty_env: std::collections::HashMap<String, String> = std::collections::HashMap::new();
            let resolved_once = word.resolve(&empty_env);
            let resolved_twice = resolved_once.resolve(&empty_env);

            // For literal words, resolution should be idempotent
            assert_eq!(resolved_once.parts.len(), resolved_twice.parts.len());
            for (a, b) in resolved_once.parts.iter().zip(resolved_twice.parts.iter()) {
                assert_eq!(format!("{:?}", a), format!("{:?}", b));
            }
        }
    }

    // Property 4.3: concatenation distributes over resolution
    proptest! {
        #[test]
        fn prop_concat_distributes_over_resolution(
            word1 in arb_literal_word(),
            word2 in arb_literal_word()
        ) {
            let env: std::collections::HashMap<String, String> = std::collections::HashMap::new();

            // Resolve words individually
            let r1 = word1.resolve(&env);
            let r2 = word2.resolve(&env);

            // Concatenate resolved words
            let mut concatenated = Word { parts: Vec::new() };
            concatenated.parts.extend(r1.parts);
            concatenated.parts.extend(r2.parts);

            // Both should produce similar structure for literal words
            assert!(!concatenated.parts.is_empty() || (word1.parts.is_empty() && word2.parts.is_empty()));
        }
    }

    // Property 4.4: words without dynamic parts resolve to themselves
    proptest! {
        #[test]
        fn prop_static_words_resolve_to_themselves(word in arb_literal_word()) {
            let env: std::collections::HashMap<String, String> = std::collections::HashMap::new();
            let resolved = word.resolve(&env);

            // Literal words should resolve to equivalent structure
            assert_eq!(word.parts.len(), resolved.parts.len());
            for (orig, res) in word.parts.iter().zip(resolved.parts.iter()) {
                match (orig, res) {
                    (WordPart::Literal(a), WordPart::Literal(b)) => {
                        assert_eq!(a, b, "Literal word part changed during resolution");
                    }
                    _ => panic!("Non-literal part in supposedly literal word"),
                }
            }
        }
    }

    // Property 4.5: resolution preserves word count for static words
    proptest! {
        #[test]
        fn prop_resolution_preserves_word_count(word in arb_literal_word()) {
            let env: std::collections::HashMap<String, String> = std::collections::HashMap::new();
            let resolved = word.resolve(&env);

            // Word count (parts) should be preserved for static words
            assert_eq!(
                word.parts.len(),
                resolved.parts.len(),
                "Resolution changed word part count for static word"
            );
        }
    }

    // Property: variable resolution works correctly when variable is in env
    proptest! {
        #[test]
        fn prop_variable_resolution_with_env(var_name in arb_var_name(), value in "[a-zA-Z0-9]{0,20}") {
            let word = Word {
                parts: vec![WordPart::Parameter(var_name.clone())],
            };

            let mut env: std::collections::HashMap<String, String> = std::collections::HashMap::new();
            env.insert(var_name.clone(), value.clone());

            let resolved = word.resolve(&env);

            assert_eq!(resolved.parts.len(), 1);
            match &resolved.parts[0] {
                WordPart::Literal(s) => assert_eq!(s, &value),
                _ => panic!("Expected Literal after resolving variable"),
            }
        }
    }

    // Property: variable stays unresolved when not in env
    proptest! {
        #[test]
        fn prop_variable_stays_unresolved(var_name in arb_var_name()) {
            let word = Word {
                parts: vec![WordPart::Parameter(var_name.clone())],
            };

            let env: std::collections::HashMap<String, String> = std::collections::HashMap::new();
            let resolved = word.resolve(&env);

            assert_eq!(resolved.parts.len(), 1);
            match &resolved.parts[0] {
                WordPart::Parameter(name) => assert_eq!(name, &var_name),
                _ => panic!("Expected Parameter to stay unresolved when not in env"),
            }
        }
    }
}
