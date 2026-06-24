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
        WordPart::CommandSubstitution { .. }
        | WordPart::Backtick { .. }
        | WordPart::Parameter(_)
        | WordPart::ParameterExpansion(_)
        | WordPart::ParameterExpansionOp { .. }
        | WordPart::ArrayExpansion { .. }
        | WordPart::Arithmetic { .. }
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
            WordPart::CommandSubstitution { source, .. } | WordPart::Backtick { source, .. } => {
                out.push(source)
            }
            WordPart::ProcessSubstitution { command, .. } => out.push(command),
            WordPart::DoubleQuoted(inner) => collect_embedded_commands(inner, out),
            // Substitutions captured out of parameter-expansion operands.
            WordPart::ParameterExpansionOp { embedded, .. } => {
                collect_embedded_commands(embedded, out)
            }
            // An `Index` subscript (`${arr[$(cmd)]}`) is arithmetic-evaluated by
            // bash, so a substitution inside it runs and must be gated. `@`/`*`
            // carry no command.
            WordPart::ArrayExpansion {
                subscript: Subscript::Index(w),
                ..
            } => collect_embedded_commands(&w.parts, out),
            _ => {}
        }
    }
}

/// Surface form of an embedded substitution, preserved so downstream
/// consumers (the engine's reason annotator) can name the form the
/// user actually wrote (`` ` ` `` vs `$( … )` vs process substitution).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubstitutionForm {
    Backtick,
    Dollar,
    Process,
}

/// An embedded substitution extracted from a [`Word`], paired with the
/// information a downstream evaluator needs to recurse into it.
///
/// `terminated` answers the only question the engine actually has — *may I
/// recurse into this substitution's source?* — so the byte-span ↔ diagnostic
/// correlation that decides it stays inside this crate, beside the code that
/// produces the spans. An unterminated `$( … )` / `` ` … ` `` swallows the
/// rest of the input as its "body"; that text is not a command, and
/// `terminated` is `false` for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Embedded<'a> {
    pub source: &'a str,
    pub span: crate::diagnostic::Span,
    pub form: SubstitutionForm,
    pub terminated: bool,
}

/// Whether the substitution body at `span` is unterminated, judged from the
/// parser's own diagnostics. The lexer records an unterminated `$( … )` /
/// `` ` … ` `` as an Error-severity diagnostic whose span runs from the
/// opening sigil to where parsing ran off the end, so it *covers* the body
/// span (which starts just after the sigil and shares the same end). The two
/// kinds are the only ones that suppress recursion; a well-formed substitution
/// — or a process substitution, which emits no such diagnostic — is
/// terminated.
fn span_is_unterminated(
    span: crate::diagnostic::Span,
    diagnostics: &[crate::diagnostic::ParseDiagnostic],
) -> bool {
    use crate::diagnostic::{ParseDiagnosticKind, Severity};
    diagnostics.iter().any(|d| {
        d.severity == Severity::Error
            && matches!(
                d.kind,
                ParseDiagnosticKind::UnterminatedCommandSubstitution
                    | ParseDiagnosticKind::UnterminatedBacktick
            )
            && d.span.start <= span.start
            && span.end <= d.span.end
    })
}

/// Like `collect_embedded_commands` but also returns each substitution's
/// source-byte span and surface form. Used by the engine's `decompose`
/// pass to emit `EvalUnit::EmbeddedCommand` units without re-scanning
/// the input.
fn collect_embedded_with_spans<'a>(
    parts: &'a [WordPart],
    out: &mut Vec<(&'a str, crate::diagnostic::Span, SubstitutionForm)>,
) {
    for part in parts {
        match part {
            WordPart::CommandSubstitution { source, span } => {
                out.push((source, *span, SubstitutionForm::Dollar))
            }
            WordPart::Backtick { source, span } => {
                out.push((source, *span, SubstitutionForm::Backtick))
            }
            WordPart::ProcessSubstitution { command, span, .. } => {
                out.push((command, *span, SubstitutionForm::Process))
            }
            WordPart::DoubleQuoted(inner) => collect_embedded_with_spans(inner, out),
            // Substitutions captured out of parameter-expansion operands carry
            // their own spans, so they surface exactly like inline ones.
            WordPart::ParameterExpansionOp { embedded, .. } => {
                collect_embedded_with_spans(embedded, out)
            }
            // A substitution inside an `Index` subscript (`${arr[$(cmd)]}`) is
            // run by bash (the subscript is arithmetic-evaluated); its parts
            // carry absolute spans, so they surface exactly like inline ones.
            WordPart::ArrayExpansion {
                subscript: Subscript::Index(w),
                ..
            } => collect_embedded_with_spans(&w.parts, out),
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
            WordPart::CommandSubstitution { source, .. } => {
                out.push(format!("$({})", abbreviate(source)));
            }
            WordPart::Backtick { source, .. } => {
                out.push(format!("`{}`", abbreviate(source)));
            }
            WordPart::Arithmetic { source, .. } => {
                out.push(format!("$(({}))", abbreviate(source)));
            }
            WordPart::ProcessSubstitution {
                direction, command, ..
            } => {
                let sigil = match direction {
                    ProcessDirection::Input => '<',
                    ProcessDirection::Output => '>',
                };
                out.push(format!("{sigil}({})", abbreviate(command)));
            }
            WordPart::ParameterExpansionOp { name, op, .. } => {
                out.push(format!("${{{}}}", format_param_op(name, op)));
            }
            WordPart::ArrayExpansion {
                name,
                subscript,
                length,
            } => {
                out.push(format!(
                    "${{{}}}",
                    format_array_expansion(name, subscript, *length)
                ));
            }
            WordPart::DoubleQuoted(inner) => {
                collect_dynamic_from(inner, out);
            }
            WordPart::Opaque(_) => {} // safe, not dynamic
            _ => {}
        }
    }
}

/// Render a slice of word parts in source-faithful form: expansions keep
/// their sigils (`$HOME`, `$(cmd)`, `{a,b}`) instead of flattening to the
/// bare inner text. Quote characters themselves are not reproduced — the
/// output names the word in a reason string, it does not round-trip.
fn parts_to_display(parts: &[WordPart], out: &mut String) {
    for part in parts {
        match part {
            WordPart::Literal(s)
            | WordPart::SingleQuoted(s)
            | WordPart::AnsiCQuoted(s)
            | WordPart::Glob(s) => out.push_str(s),
            WordPart::Parameter(name) => {
                out.push('$');
                out.push_str(name);
            }
            WordPart::ParameterExpansion(name) => {
                out.push_str("${");
                out.push_str(name);
                out.push('}');
            }
            WordPart::ParameterExpansionOp { name, op, .. } => {
                out.push_str("${");
                out.push_str(&format_param_op(name, op));
                out.push('}');
            }
            WordPart::ArrayExpansion {
                name,
                subscript,
                length,
            } => {
                out.push_str("${");
                out.push_str(&format_array_expansion(name, subscript, *length));
                out.push('}');
            }
            WordPart::CommandSubstitution { source, .. } => {
                out.push_str("$(");
                out.push_str(source);
                out.push(')');
            }
            WordPart::Backtick { source, .. } => {
                out.push('`');
                out.push_str(source);
                out.push('`');
            }
            WordPart::Arithmetic { source, .. } => {
                out.push_str("$((");
                out.push_str(source);
                out.push_str("))");
            }
            WordPart::BraceExpansion(items) => {
                out.push('{');
                out.push_str(&items.join(","));
                out.push('}');
            }
            WordPart::ProcessSubstitution {
                direction, command, ..
            } => {
                out.push(match direction {
                    ProcessDirection::Input => '<',
                    ProcessDirection::Output => '>',
                });
                out.push('(');
                out.push_str(command);
                out.push(')');
            }
            WordPart::DoubleQuoted(inner) => parts_to_display(inner, out),
            WordPart::Opaque(label) => out.push_str(label),
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
            | WordPart::Glob(s) => out.push_str(s),
            WordPart::CommandSubstitution { source, .. }
            | WordPart::Backtick { source, .. }
            | WordPart::Arithmetic { source, .. } => out.push_str(source),
            WordPart::ParameterExpansionOp { name, op, .. } => {
                out.push_str(&format_param_op(name, op));
            }
            WordPart::ArrayExpansion {
                name,
                subscript,
                length,
            } => {
                out.push_str(&format_array_expansion(name, subscript, *length));
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

/// Returns true if any part in the slice has a runtime value that is not
/// provable from its source bytes: a dynamic shell construct (parameter,
/// command, arithmetic, or process substitution — recursing into
/// double-quoted regions, where bash still expands), or an unquoted glob
/// or brace expansion (which the lexer only emits outside quotes).
/// Quoted text and plain literals are excluded; `Opaque` is a trusted
/// value by construction and is excluded too.
fn is_expansion_bearing_in(parts: &[WordPart]) -> bool {
    parts.iter().any(|part| match part {
        WordPart::CommandSubstitution { .. }
        | WordPart::Backtick { .. }
        | WordPart::Parameter(_)
        | WordPart::ParameterExpansion(_)
        | WordPart::ParameterExpansionOp { .. }
        | WordPart::ArrayExpansion { .. }
        | WordPart::Arithmetic { .. }
        | WordPart::ProcessSubstitution { .. }
        | WordPart::Glob(_)
        | WordPart::BraceExpansion(_) => true,
        WordPart::DoubleQuoted(inner) => is_expansion_bearing_in(inner),
        WordPart::Literal(_)
        | WordPart::SingleQuoted(_)
        | WordPart::AnsiCQuoted(_)
        | WordPart::Opaque(_) => false,
    })
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

    /// Extract each embedded substitution as an [`Embedded`], pairing its
    /// source, source-byte `Span` (inner-span semantics: excludes sigils),
    /// surface form, and whether it is terminated. `diagnostics` are the
    /// parser's own diagnostics for the same input; they are consulted only
    /// to set `terminated`, never exposed.
    pub fn extract_embedded<'a>(
        &'a self,
        diagnostics: &[crate::diagnostic::ParseDiagnostic],
    ) -> Vec<Embedded<'a>> {
        let mut raw = Vec::new();
        collect_embedded_with_spans(&self.parts, &mut raw);
        raw.into_iter()
            .map(|(source, span, form)| Embedded {
                source,
                span,
                form,
                terminated: !span_is_unterminated(span, diagnostics),
            })
            .collect()
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

    /// Render this word in source-faithful form for naming it in reason
    /// strings: expansions keep their sigils (`/tmp/$HOME`, `$(cmd)`,
    /// `{a,b}`) instead of flattening to the inner text the way
    /// [`Word::to_str`] does.
    pub fn display_source(&self) -> String {
        let mut out = String::new();
        parts_to_display(&self.parts, &mut out);
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

    /// Returns true when this word's runtime value is not provable from its
    /// source bytes — it carries a shell expansion (parameter, command,
    /// arithmetic, or process substitution), an unquoted glob or brace
    /// expansion, or an unquoted leading tilde. The security model forbids
    /// such a word from satisfying a non-wildcard matcher toward `:allow`
    /// (see the expansion-bearing-word requirement).
    ///
    /// A backslash-escaped `~` (`\~/x`) is indistinguishable from a live
    /// leading tilde after lexing and is conservatively reported as
    /// expansion-bearing — over-reporting only tightens decisions.
    pub fn is_expansion_bearing(&self) -> bool {
        if is_expansion_bearing_in(&self.parts) {
            return true;
        }
        matches!(self.parts.first(), Some(WordPart::Literal(s)) if s.starts_with('~'))
    }
}

// ── Resolution helpers ───────────────────────────────────────────────

use crate::const_env::ConstLookup;
use crate::resolve::resolve_param_op;

fn resolve_parts<L: ConstLookup>(parts: &[WordPart], env: &L) -> Vec<WordPart> {
    parts
        .iter()
        .map(|part| match part {
            WordPart::Parameter(name) | WordPart::ParameterExpansion(name) => {
                if let Some(val) = env.lookup_scalar(name.as_str()) {
                    WordPart::Literal(val.to_string())
                } else {
                    part.clone()
                }
            }
            WordPart::ParameterExpansionOp {
                name, op, embedded, ..
            } => resolve_param_op(name, op, embedded, env),
            WordPart::ArrayExpansion {
                name,
                subscript,
                length,
            } => resolve_array_expansion(name, subscript, *length, env),
            WordPart::DoubleQuoted(inner) => WordPart::DoubleQuoted(resolve_parts(inner, env)),
            _ => part.clone(),
        })
        .collect()
}

/// Resolve a subscripted array reference against `env`. Only the single-value
/// forms reduce to a literal here: `${arr[i]}` with a statically-known index in
/// range, and the length forms `${#arr[@]}` / `${#arr[*]}` (element count) and
/// `${#arr[i]}` (element char-length). The word-count-changing `"${arr[@]}"`
/// splice is handled by the caller in argv construction (it is not a single
/// `WordPart`), and `${arr[@]}` / `${arr[*]}` value joins are IFS-dependent, so
/// they stay unresolved. An unknown array, out-of-range or dynamic index, or a
/// scalar name all leave the part unchanged (expansion-bearing).
fn resolve_array_expansion<L: ConstLookup>(
    name: &str,
    subscript: &Subscript,
    length: bool,
    env: &L,
) -> WordPart {
    let unresolved = || WordPart::ArrayExpansion {
        name: name.to_string(),
        subscript: subscript.clone(),
        length,
    };
    let Some(elements) = env.lookup_array(name) else {
        return unresolved();
    };
    if length {
        return match subscript {
            // `${#arr[@]}` / `${#arr[*]}` → element count (order-independent).
            Subscript::All | Subscript::Star => WordPart::Literal(elements.len().to_string()),
            // `${#arr[i]}` → character length of element `i`.
            Subscript::Index(index_word) => match resolve_index(index_word, elements.len(), env) {
                Some(i) => WordPart::Literal(elements[i].chars().count().to_string()),
                None => unresolved(),
            },
        };
    }
    match subscript {
        Subscript::Index(index_word) => match resolve_index(index_word, elements.len(), env) {
            Some(i) => WordPart::Literal(elements[i].clone()),
            None => unresolved(),
        },
        // `@`/`*` are the word-count / IFS-join forms — never a lone literal.
        Subscript::All | Subscript::Star => unresolved(),
    }
}

/// Resolve an array subscript word to an in-range element index. The subscript
/// must resolve (against `env`) to a plain decimal integer — a bash arithmetic
/// expression, a dynamic index (`${arr[$RANDOM]}`), or an unset variable yields
/// `None`, leaving the expansion unresolved. A negative index counts from the
/// end (`${arr[-1]}`), matching bash. Out-of-range indices yield `None`.
fn resolve_index<L: ConstLookup>(index_word: &Word, len: usize, env: &L) -> Option<usize> {
    let resolved = index_word.resolve(env);
    if !resolved.is_literal() {
        return None;
    }
    let n: isize = resolved.to_str().trim().parse().ok()?;
    let idx = if n < 0 { len as isize + n } else { n };
    (idx >= 0 && (idx as usize) < len).then_some(idx as usize)
}

/// Whether an *unquoted* expansion's resolved value would be passed to the
/// program verbatim — no glob metachar (`*?[`) to trigger pathname expansion
/// and no whitespace to trigger word-splitting under a default IFS. Brace and
/// tilde expansion run *before* parameter expansion in bash, so they never
/// apply to a value and are not part of this test.
fn value_is_shell_inert(s: &str) -> bool {
    !s.bytes()
        .any(|b| matches!(b, b'*' | b'?' | b'[' | b' ' | b'\t' | b'\n'))
}

/// Whether every expansion in `parts` resolves against `env` to a value the
/// shell passes through verbatim, given the surrounding quoting. An *unquoted*
/// expansion whose value carries a glob metachar or splitting whitespace is
/// **not** verbatim: bash would pathname-expand or word-split it at runtime, so
/// treating the resolved literal as proven could satisfy an `:allow` on a value
/// the program never receives. A quoted expansion undergoes neither and is safe.
/// Returns `false` for any part that does not resolve (an unset variable, a
/// command/process substitution, a glob/brace) so the word stays floored.
fn resolves_to_safe_literal_in<L: ConstLookup>(parts: &[WordPart], env: &L, quoted: bool) -> bool {
    parts.iter().all(|part| match part {
        WordPart::Literal(_) | WordPart::SingleQuoted(_) | WordPart::AnsiCQuoted(_) => true,
        WordPart::Parameter(name) | WordPart::ParameterExpansion(name) => env
            .lookup_scalar(name.as_str())
            .is_some_and(|val| quoted || value_is_shell_inert(val)),
        WordPart::ParameterExpansionOp {
            name, op, embedded, ..
        } => match resolve_param_op(name, op, embedded, env) {
            WordPart::Literal(val) => quoted || value_is_shell_inert(&val),
            // Stayed an operator form (unset head, or expandable operand held
            // back by `op_operands_are_inert`): not resolved → not safe.
            _ => false,
        },
        // A subscripted array reference is verbatim only when it resolves to a
        // single literal and that literal is shell-inert in unquoted position
        // (an unquoted `${arr[i]}` whose element holds a glob/space would be
        // re-expanded by bash). Mirrors the operator-form arm above.
        WordPart::ArrayExpansion {
            name,
            subscript,
            length,
        } => match resolve_array_expansion(name, subscript, *length, env) {
            WordPart::Literal(val) => quoted || value_is_shell_inert(&val),
            _ => false,
        },
        WordPart::DoubleQuoted(inner) => resolves_to_safe_literal_in(inner, env, true),
        // `Opaque` is a trusted variable whose *runtime value is unknown* (it
        // flattens to a diagnostic label, not a value), so it can never be
        // proven verbatim — consistent with `is_literal`/`is_dynamic`. Globs,
        // braces, command/arithmetic/process substitutions, and backticks are
        // likewise never provably verbatim.
        _ => false,
    })
}

impl Word {
    /// Resolve this word's parameter expansions against `env`, replacing any
    /// part whose variable is present with its literal value and leaving the
    /// rest untouched. A word all of whose dynamic parts resolve becomes a
    /// literal; partially-resolved words stay dynamic.
    pub fn resolve<L: ConstLookup>(&self, env: &L) -> Word {
        Word {
            parts: resolve_parts(&self.parts, env),
        }
    }

    /// Whether this word resolves against `env` to a value the shell passes to
    /// the program **verbatim** — every expansion resolves to a literal, and no
    /// *unquoted* expansion's value carries a glob metachar or splitting
    /// whitespace that bash would pathname-expand or word-split at runtime.
    ///
    /// This is the soundness gate for treating a resolved argument word as
    /// proven: [`Word::resolve`] computes the value, but an unquoted `$VAR`
    /// holding `/etc/passw?` resolves to a literal that is *not*
    /// expansion-bearing yet expands to a different path at runtime. A word that
    /// fails this test must keep its expansion-bearing flag and floor an
    /// `:allow`. Top-level parts are treated as unquoted; `DoubleQuoted` regions
    /// as quoted.
    pub fn resolves_to_verbatim_literal<L: ConstLookup>(&self, env: &L) -> bool {
        resolves_to_safe_literal_in(&self.parts, env, false)
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

    // Property (D1 refactor guard): generalising the constant env from
    // `HashMap<String, String>` to a `ConstLookup` that also carries arrays must
    // not change scalar resolution. A scalar value resolved against the
    // array-carrying `HashMap<String, ConstValue>` is byte-for-byte identical to
    // the same value in the scalar-only map — and the verbatim gate agrees too.
    proptest! {
        #[test]
        fn prop_scalar_resolution_unchanged_across_env_kinds(
            var_name in arb_var_name(),
            value in "[a-zA-Z0-9/_.*? -]{0,20}",
        ) {
            use crate::const_env::ConstValue;
            let word = Word {
                parts: vec![
                    WordPart::Literal("x".into()),
                    WordPart::Parameter(var_name.clone()),
                ],
            };

            let mut scalar_env: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();
            scalar_env.insert(var_name.clone(), value.clone());

            let mut const_env: std::collections::HashMap<String, ConstValue> =
                std::collections::HashMap::new();
            const_env.insert(var_name.clone(), ConstValue::Scalar(value.clone()));

            prop_assert_eq!(
                word.resolve(&scalar_env).to_str(),
                word.resolve(&const_env).to_str()
            );
            prop_assert_eq!(
                word.resolves_to_verbatim_literal(&scalar_env),
                word.resolves_to_verbatim_literal(&const_env)
            );
        }
    }
}
