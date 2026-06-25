use super::Lexer;
use crate::ast::*;

impl Lexer {
    /// Parse the content of `${...}` after the opening `{` has been consumed.
    /// Produces either a simple `ParameterExpansion(name)` for `${VAR}` or a
    /// structured `ParameterExpansionOp { name, op }` for operator forms.
    pub(super) fn read_parameter_expansion(&mut self) -> Option<WordPart> {
        // Special case: ${#VAR} (length operator) and ${#arr[sub]} (array
        // element count).
        if self.peek() == Some('#') {
            // Look ahead: if what follows '#' is a valid identifier and then
            // either `}` (scalar length) or `[sub]}` (array length), this is
            // the length form.
            let saved = self.save_state();
            self.advance(); // skip #
            let name = self.read_identifier();
            if !name.is_empty() {
                if self.peek() == Some('}') {
                    self.advance(); // skip }
                    return Some(WordPart::ParameterExpansionOp {
                        name,
                        op: ParameterOperator::Length,
                        embedded: Vec::new(),
                    });
                }
                if self.peek() == Some('[') {
                    let sub_saved = self.save_state();
                    if let Some(subscript) = self.read_subscript()
                        && self.peek() == Some('}')
                    {
                        self.advance(); // skip }
                        return Some(WordPart::ArrayExpansion {
                            name,
                            subscript,
                            length: true,
                        });
                    }
                    self.restore_state(sub_saved);
                }
            }
            // Not a length operator; restore and fall through to flat parsing
            self.restore_state(saved);
        }

        // Indirect / nameref `${!name}`, `${!prefix*}`, `${!arr[@]}`. The `!`
        // makes the expansion read the variable *named by* the operand, so the
        // operand is not itself the variable read — it stays unresolved. Read
        // the operand via `read_operand` so an embedded `$( … )` / backtick is
        // captured and gated, and classify the listing shape for display.
        // Placed before `read_identifier` because `!` is not an identifier
        // start, so the name read would otherwise be empty and the form would
        // collapse to an opaque flat string.
        if self.peek() == Some('!') {
            self.advance(); // skip !
            let (operand, embedded) = self.read_operand(&['}']);
            self.advance(); // skip }
            let listing = classify_name_listing(&operand);
            return Some(WordPart::ParameterExpansionOp {
                name: String::new(),
                op: ParameterOperator::Indirect { operand, listing },
                embedded,
            });
        }

        // Read the variable name
        let mut name = self.read_identifier();
        if name.is_empty() {
            // Not a valid identifier; fall back to flat string
            let s = self.read_until_char('}');
            self.advance(); // skip }
            return Some(WordPart::ParameterExpansion(s));
        }

        // Command/backtick/process substitutions harvested out of a subscript
        // that is folded into the name below (`${arr[$(cmd)]:-x}`). They are
        // merged into the resulting operator op's `embedded` so the engine gates
        // them — bash arithmetic-evaluates the subscript regardless of the
        // operator, so a `$(…)` there runs and must not be lost.
        let mut subscript_embedded: Vec<WordPart> = Vec::new();

        // A subscript `[sub]` immediately after the name is an array reference
        // (`${arr[0]}`, `${arr[@]}`, `${arr[*]}`). Keep the name and subscript
        // distinct rather than folding `arr[@]` into the name (design D2).
        if self.peek() == Some('[') {
            let sub_saved = self.save_state();
            if let Some(subscript) = self.read_subscript() {
                if self.peek() == Some('}') {
                    self.advance(); // skip }
                    return Some(WordPart::ArrayExpansion {
                        name,
                        subscript,
                        length: false,
                    });
                }
                // Subscript followed by an operator (`${arr[0]:-x}`): fold the
                // raw `[sub]` text back into the name and fall through to the
                // operator dispatch, so the operator's operands — and any
                // embedded command substitution in them — are captured
                // structurally. Leaving it to the unstructured flat fallback
                // would bury an embedded `$(…)` and leave it ungated. The
                // subscript stays folded into the name for this combined form;
                // only the pure `${arr[sub]}` reference separates them (the
                // follow-on resolver needs only those separated). Harvest the
                // subscript's own substitutions so they are gated too.
                let sub_text: String = self.input[sub_saved.0..self.pos].iter().collect();
                name.push_str(&sub_text);
                if let Subscript::Index(w) = &subscript {
                    collect_substitution_parts(&w.parts, &mut subscript_embedded);
                }
            } else {
                // Malformed subscript (no `]` before `}`/EOF): restore and let
                // the flat path below handle it without dropping tokens.
                self.restore_state(sub_saved);
            }
        }

        // Check what follows the name
        let mut expansion = match self.peek() {
            Some('}') => {
                self.advance(); // skip }
                Some(WordPart::ParameterExpansion(name))
            }
            Some('#') => {
                self.advance(); // skip #
                let longest = if self.peek() == Some('#') {
                    self.advance();
                    true
                } else {
                    false
                };
                let (pattern, embedded) = self.read_operand(&['}']);
                self.advance(); // skip }
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::StripPrefix { longest, pattern },
                    embedded,
                })
            }
            Some('%') => {
                self.advance(); // skip %
                let longest = if self.peek() == Some('%') {
                    self.advance();
                    true
                } else {
                    false
                };
                let (pattern, embedded) = self.read_operand(&['}']);
                self.advance(); // skip }
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::StripSuffix { longest, pattern },
                    embedded,
                })
            }
            Some('/') => {
                self.advance(); // skip /
                let all = if self.peek() == Some('/') {
                    self.advance();
                    true
                } else {
                    false
                };
                let (pattern, mut embedded) = self.read_operand(&['/', '}']);
                let replacement = if self.peek() == Some('/') {
                    self.advance(); // skip separator /
                    let (replacement, more) = self.read_operand(&['}']);
                    embedded.extend(more);
                    replacement
                } else {
                    String::new()
                };
                self.advance(); // skip }
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::Replace {
                        all,
                        pattern,
                        replacement,
                    },
                    embedded,
                })
            }
            Some(':') => {
                self.advance(); // skip :
                match self.peek() {
                    Some('-') => {
                        self.advance();
                        let (value, embedded) = self.read_operand(&['}']);
                        self.advance();
                        Some(WordPart::ParameterExpansionOp {
                            name,
                            op: ParameterOperator::Default { colon: true, value },
                            embedded,
                        })
                    }
                    Some('+') => {
                        self.advance();
                        let (value, embedded) = self.read_operand(&['}']);
                        self.advance();
                        Some(WordPart::ParameterExpansionOp {
                            name,
                            op: ParameterOperator::Alternative { colon: true, value },
                            embedded,
                        })
                    }
                    Some('?') => {
                        self.advance();
                        let (message, embedded) = self.read_operand(&['}']);
                        self.advance();
                        Some(WordPart::ParameterExpansionOp {
                            name,
                            op: ParameterOperator::Error {
                                colon: true,
                                message,
                            },
                            embedded,
                        })
                    }
                    Some('=') => {
                        self.advance();
                        let (value, embedded) = self.read_operand(&['}']);
                        self.advance();
                        Some(WordPart::ParameterExpansionOp {
                            name,
                            op: ParameterOperator::Assign { colon: true, value },
                            embedded,
                        })
                    }
                    _ => {
                        // Substring: ${VAR:offset} or ${VAR:offset:length}
                        let (offset, mut embedded) = self.read_operand(&[':', '}']);
                        let length = if self.peek() == Some(':') {
                            self.advance();
                            let (length, more) = self.read_operand(&['}']);
                            embedded.extend(more);
                            Some(length)
                        } else {
                            None
                        };
                        self.advance(); // skip }
                        Some(WordPart::ParameterExpansionOp {
                            name,
                            op: ParameterOperator::Substring { offset, length },
                            embedded,
                        })
                    }
                }
            }
            Some('-') => {
                self.advance();
                let (value, embedded) = self.read_operand(&['}']);
                self.advance();
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::Default {
                        colon: false,
                        value,
                    },
                    embedded,
                })
            }
            Some('+') => {
                self.advance();
                let (value, embedded) = self.read_operand(&['}']);
                self.advance();
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::Alternative {
                        colon: false,
                        value,
                    },
                    embedded,
                })
            }
            Some('?') => {
                self.advance();
                let (message, embedded) = self.read_operand(&['}']);
                self.advance();
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::Error {
                        colon: false,
                        message,
                    },
                    embedded,
                })
            }
            Some('=') => {
                self.advance();
                let (value, embedded) = self.read_operand(&['}']);
                self.advance();
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::Assign {
                        colon: false,
                        value,
                    },
                    embedded,
                })
            }
            Some('^') => {
                self.advance();
                let all = if self.peek() == Some('^') {
                    self.advance();
                    true
                } else {
                    false
                };
                let (pattern, embedded) = self.read_operand(&['}']);
                self.advance();
                // bash `${VAR^^pat}` converts only chars matching `pat`. The
                // `Uppercase` op carries no pattern, so a non-empty operand would
                // be silently dropped and resolution would diverge (full-case vs
                // patterned). Emit the structured `CaseConvert` (never resolved,
                // so the word stays expansion-bearing and floors) which carries
                // the operand's `embedded` substitutions for gating.
                // `${VAR^^}`/`${VAR^}` (no pattern) resolves as before.
                if pattern.is_empty() {
                    Some(WordPart::ParameterExpansionOp {
                        name,
                        op: ParameterOperator::Uppercase { all },
                        embedded,
                    })
                } else {
                    Some(WordPart::ParameterExpansionOp {
                        name,
                        op: ParameterOperator::CaseConvert {
                            upper: true,
                            all,
                            pattern,
                        },
                        embedded,
                    })
                }
            }
            Some(',') => {
                self.advance();
                let all = if self.peek() == Some(',') {
                    self.advance();
                    true
                } else {
                    false
                };
                let (pattern, embedded) = self.read_operand(&['}']);
                self.advance();
                // See the `^` arm: a non-empty `${VAR,,pat}` pattern is dropped by
                // the `Lowercase` op, so emit the structured `CaseConvert`
                // (unresolved, expansion-bearing) carrying its `embedded`.
                if pattern.is_empty() {
                    Some(WordPart::ParameterExpansionOp {
                        name,
                        op: ParameterOperator::Lowercase { all },
                        embedded,
                    })
                } else {
                    Some(WordPart::ParameterExpansionOp {
                        name,
                        op: ParameterOperator::CaseConvert {
                            upper: false,
                            all,
                            pattern,
                        },
                        embedded,
                    })
                }
            }
            _ => {
                // Operator the lexer does not structure. Read via `read_operand`
                // (not `read_until_char`) so an embedded `$( … )` / backtick is
                // captured and gated. A leading `@` is a transform (`${VAR@Q}`);
                // anything else is an unrecognised operator kept verbatim. Both
                // stay unresolved (expansion-bearing) — only the substitution
                // becomes visible.
                let (rest, embedded) = self.read_operand(&['}']);
                self.advance(); // skip }
                let op = match rest.strip_prefix('@') {
                    Some(spec) => ParameterOperator::Transform {
                        spec: spec.to_string(),
                    },
                    None => ParameterOperator::Unknown { source: rest },
                };
                Some(WordPart::ParameterExpansionOp { name, op, embedded })
            }
        };

        // Merge any substitutions harvested from a folded subscript into the
        // operator op's `embedded`, so `${arr[$(cmd)]:-x}` (and every operator
        // whose operand is read via `read_operand`) gates the subscript command.
        // Every operator arm above now yields a `ParameterExpansionOp` that can
        // carry `embedded` — the patterned case-conversion, transform/unknown,
        // and indirect forms included — so a folded subscript's substitutions
        // are never lost.
        if !subscript_embedded.is_empty()
            && let Some(WordPart::ParameterExpansionOp { embedded, .. }) = &mut expansion
        {
            embedded.splice(0..0, subscript_embedded);
        }
        expansion
    }

    /// Read a parameter-expansion operator operand up to (not including) one of
    /// `stops` or EOF, capturing the command (`$( … )`) and backtick
    /// substitutions inside it as structured parts with absolute source-byte
    /// spans. The returned `String` is byte-identical to what `read_until_char`
    /// would have produced, so resolution and display are unaffected; the
    /// captured parts let the engine gate the substitutions the operand runs.
    ///
    /// Arithmetic `$(( … ))` runs no command, so it is copied verbatim like
    /// ordinary text and produces no part — matching the rest of the lexer.
    pub(super) fn read_operand(&mut self, stops: &[char]) -> (String, Vec<WordPart>) {
        let mut text = String::new();
        let mut embedded = Vec::new();
        while let Some(ch) = self.peek() {
            if stops.contains(&ch) {
                break;
            }
            // `$(` is a command substitution (arithmetic `$((` runs nothing and
            // is left to the verbatim copy below). Delegate to the shared
            // readers so spans and balanced-paren / closing handling match every
            // other path, then append the exact source consumed so `text` stays
            // identical to a flat read.
            if ch == '$' && self.peek_at(1) == Some('(') && self.peek_at(2) != Some('(') {
                let before = self.pos;
                if let Some(part) = self.read_dollar() {
                    text.extend(self.input[before..self.pos].iter());
                    // `read_dollar` may fold a static `$(cat <<heredoc)` to a
                    // Literal; only a real substitution is gateable.
                    if matches!(part, WordPart::CommandSubstitution { .. }) {
                        embedded.push(part);
                    }
                    continue;
                }
            }
            if ch == '`' {
                let before = self.pos;
                let part = self.read_backtick();
                text.extend(self.input[before..self.pos].iter());
                embedded.push(part);
                continue;
            }
            text.push(ch);
            self.advance();
        }
        (text, embedded)
    }

    /// Read an array subscript `[ … ]`, the cursor on the opening `[`. On
    /// success the cursor is just past the closing `]` and the subscript is
    /// returned: `@` → [`Subscript::All`], `*` → [`Subscript::Star`], any other
    /// content → [`Subscript::Index`] holding the inner text lexed as a word
    /// (so `${arr[$i]}` keeps its dynamic subscript). Returns `None` (cursor
    /// left at the `[`, since callers save/restore) when there is no closing
    /// `]` before `}` or EOF — a malformed subscript the caller falls back on
    /// rather than dropping.
    pub(super) fn read_subscript(&mut self) -> Option<Subscript> {
        debug_assert_eq!(self.peek(), Some('['));
        self.advance(); // skip [
        // Absolute byte offset where the inner subscript text begins. `inner` is
        // built up as a verbatim contiguous copy of the input from here, so this
        // is the base offset to re-absolutise sub-lexer spans below.
        let inner_start = self.byte_pos;
        // Capture the inner text up to the matching `]`. Nested `[` (rare, e.g.
        // arithmetic index `arr[a[0]]`) increases depth so the right `]`
        // closes. A `}` or EOF before any closing `]` is malformed.
        let mut depth = 1usize;
        let mut inner = String::new();
        loop {
            match self.peek() {
                None => return None,
                Some('}') if depth == 1 => return None,
                Some('[') => {
                    depth += 1;
                    inner.push('[');
                    self.advance();
                }
                Some(']') => {
                    depth -= 1;
                    self.advance();
                    if depth == 0 {
                        break;
                    }
                    inner.push(']');
                }
                Some(ch) => {
                    inner.push(ch);
                    self.advance();
                }
            }
        }
        Some(match inner.as_str() {
            "@" => Subscript::All,
            "*" => Subscript::Star,
            _ => {
                // Lex the inner text as a word so a dynamic subscript
                // (`$i`, `$((i))`, `${j}`) is modelled, not flattened. Seed the
                // sub-lexer's byte position with `inner_start` so any embedded
                // substitution (`${arr[$(cmd)]}`) carries an *absolute* span
                // into the original input — the engine slices the input by that
                // span to gate the command, so a relative span would mislocate
                // (or escape) it.
                let mut sub_lexer = Lexer::new(&inner);
                sub_lexer.byte_pos = inner_start;
                let parts = sub_lexer.read_word_parts();
                let word = if parts.is_empty() {
                    Word::literal(&inner)
                } else {
                    Word { parts }
                };
                Subscript::Index(word)
            }
        })
    }

    /// Read a shell identifier (alphanumeric + underscore).
    pub(super) fn read_identifier(&mut self) -> String {
        let mut name = String::new();
        while let Some(ch) = self.peek() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                name.push(ch);
                self.advance();
            } else {
                break;
            }
        }
        name
    }
}

/// Classify an indirect-expansion operand (the text after `!`) into its
/// [`NameListing`] shape. An array-key form `${!arr[@]}` carries a `[`; a
/// prefix-listing `${!prefix*}` / `${!prefix@}` ends with `*` or `@`; anything
/// else is a plain indirect `${!name}`. All stay unresolved — the distinction
/// is for display fidelity only.
fn classify_name_listing(operand: &str) -> NameListing {
    if operand.contains('[') {
        NameListing::Keys
    } else if operand.ends_with('*') || operand.ends_with('@') {
        NameListing::Prefix
    } else {
        NameListing::Indirect
    }
}

/// Clone the command/backtick/process-substitution word parts out of `parts`
/// (recursing through double-quoted regions and nested operator/subscript
/// parts), preserving their absolute source spans. Used to lift the
/// substitutions of a subscript that is folded into a parameter-expansion
/// name (`${arr[$(cmd)]:-x}`) into the operator op's `embedded` list, so the
/// engine gates them like any other substitution.
fn collect_substitution_parts(parts: &[WordPart], out: &mut Vec<WordPart>) {
    for part in parts {
        match part {
            WordPart::CommandSubstitution { .. }
            | WordPart::Backtick { .. }
            | WordPart::ProcessSubstitution { .. } => out.push(part.clone()),
            WordPart::DoubleQuoted(inner) => collect_substitution_parts(inner, out),
            WordPart::ParameterExpansionOp { embedded, .. } => {
                collect_substitution_parts(embedded, out)
            }
            WordPart::ArrayExpansion {
                subscript: Subscript::Index(w),
                ..
            } => collect_substitution_parts(&w.parts, out),
            // `ArrayExpansion` with an `@`/`*` subscript carries no nested word,
            // so it falls here alongside every leaf part.
            WordPart::ArrayExpansion { .. }
            | WordPart::Literal(_)
            | WordPart::SingleQuoted(_)
            | WordPart::AnsiCQuoted(_)
            | WordPart::Parameter(_)
            | WordPart::ParameterExpansion(_)
            | WordPart::Arithmetic { .. }
            | WordPart::BraceExpansion(_)
            | WordPart::Glob(_)
            | WordPart::Opaque(_) => {}
        }
    }
}
