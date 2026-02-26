// Variable safety tracking for AST analysis.

use may_i_shell_parser::{Command, SimpleCommand, Word, WordPart};

/// The safety state of a shell variable during AST analysis.
#[derive(Debug, Clone, PartialEq)]
pub enum VarState {
    /// Resolvable to a known literal value.
    Known(String),
    /// Safe but value unknown at analysis time (e.g. loop variable, read input).
    Opaque,
    /// Assigned from an unknown or untrusted source.
    Unsafe,
}

/// Tracks variable safety state through AST evaluation.
#[derive(Debug, Clone)]
pub struct VarEnv {
    vars: std::collections::HashMap<String, VarState>,
    fns: std::collections::HashMap<String, Command>,
}

impl VarEnv {
    /// Seed from all process environment variables.
    /// Every env var is `Safe(Some(value))` at startup.
    pub fn from_process_env() -> Self {
        let mut vars = std::collections::HashMap::new();
        for (key, val) in std::env::vars() {
            vars.insert(key, VarState::Known(val));
        }
        VarEnv {
            vars,
            fns: std::collections::HashMap::new(),
        }
    }

    #[cfg(test)]
    pub fn empty() -> Self {
        VarEnv {
            vars: std::collections::HashMap::new(),
            fns: std::collections::HashMap::new(),
        }
    }

    pub fn get(&self, name: &str) -> Option<&VarState> {
        self.vars.get(name)
    }

    pub fn set(&mut self, name: String, state: VarState) {
        self.vars.insert(name, state);
    }

    /// Merge a list of branch environments that all forked from `pre`.
    /// For each variable across all branches:
    /// - Same `Safe(Some(v))` in all → keep `Safe(Some(v))`
    /// - `Safe` in all but different values → `Safe(None)` (opaque)
    /// - `Unsafe` in any branch → `Unsafe`
    /// - Absent in some branches → use `pre`'s value for those branches
    pub fn merge_branches(pre: &VarEnv, branches: &[VarEnv]) -> VarEnv {
        if branches.is_empty() {
            return pre.clone();
        }

        let mut all_keys: std::collections::HashSet<&String> = std::collections::HashSet::new();
        for branch in branches {
            all_keys.extend(branch.vars.keys());
        }
        all_keys.extend(pre.vars.keys());

        let mut result = std::collections::HashMap::new();

        for key in all_keys {
            let mut any_absent = false;
            let mut states: Vec<&VarState> = Vec::new();
            for branch in branches {
                if let Some(s) = branch.vars.get(key).or_else(|| pre.vars.get(key)) {
                    states.push(s);
                } else {
                    any_absent = true;
                }
            }

            if states.is_empty() && !any_absent {
                continue;
            }

            if any_absent || states.iter().any(|s| matches!(s, VarState::Unsafe)) {
                result.insert(key.clone(), VarState::Unsafe);
                continue;
            }

            let first = &states[0];
            if states.iter().all(|s| *s == *first) {
                result.insert(key.clone(), (*first).clone());
            } else {
                result.insert(key.clone(), VarState::Opaque);
            }
        }

        let mut fns = pre.fns.clone();
        for branch in branches {
            for (name, body) in &branch.fns {
                fns.insert(name.clone(), body.clone());
            }
        }

        VarEnv { vars: result, fns }
    }

    /// Check if a variable is safe (regardless of whether its value is known).
    pub fn is_safe(&self, name: &str) -> bool {
        matches!(self.get(name), Some(VarState::Known(_) | VarState::Opaque))
    }

    /// Store a function definition.
    pub fn set_fn(&mut self, name: String, body: Command) {
        self.fns.insert(name, body);
    }

    /// Retrieve a function definition.
    pub fn get_fn(&self, name: &str) -> Option<&Command> {
        self.fns.get(name)
    }
}

// ── VarEnv-based resolution helpers ─────────────────────────────────
// These were originally in parser/ast.rs but depend on VarEnv, so they
// live here to avoid a circular dependency.

/// Resolve variables using VarEnv: Safe(Some) → Literal, Safe(None) → Opaque, absent → keep.
pub fn resolve_parts_with_var_env(
    parts: &[WordPart],
    env: &VarEnv,
) -> Vec<WordPart> {
    parts.iter().map(|part| match part {
        WordPart::Parameter(name) | WordPart::ParameterExpansion(name) => {
            match env.get(name) {
                Some(VarState::Known(val)) => WordPart::Literal(val.clone()),
                Some(VarState::Opaque) => WordPart::Opaque(format!("${name}")),
                Some(VarState::Unsafe) | None => part.clone(),
            }
        }
        WordPart::ParameterExpansionOp { name, op } => {
            match env.get(name) {
                Some(VarState::Known(val)) => {
                    let mut map = std::collections::HashMap::new();
                    map.insert(name.clone(), val.clone());
                    may_i_shell_parser::resolve_param_op(name, op, &map)
                }
                Some(VarState::Opaque) => WordPart::Opaque(format!("${{{name}...}}")),
                Some(VarState::Unsafe) | None => part.clone(),
            }
        }
        WordPart::DoubleQuoted(inner) => {
            WordPart::DoubleQuoted(resolve_parts_with_var_env(inner, env))
        }
        _ => part.clone(),
    }).collect()
}

/// Resolve a Word using VarEnv. Safe+resolvable variables become Literal,
/// safe+opaque variables become Opaque, unsafe/unknown variables stay as Parameter.
pub fn resolve_word_with_var_env(word: &Word, env: &VarEnv) -> Word {
    Word {
        parts: resolve_parts_with_var_env(&word.parts, env),
    }
}

/// Resolve a SimpleCommand using VarEnv in all words, assignment values,
/// and redirect file targets.
pub fn resolve_simple_command_with_var_env(
    sc: &SimpleCommand,
    env: &VarEnv,
) -> SimpleCommand {
    sc.map_words(|w| resolve_word_with_var_env(w, env))
}
