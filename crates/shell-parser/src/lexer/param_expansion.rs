use super::Lexer;
use crate::ast::*;

impl Lexer {
    /// Parse the content of `${...}` after the opening `{` has been consumed.
    /// Produces either a simple `ParameterExpansion(name)` for `${VAR}` or a
    /// structured `ParameterExpansionOp { name, op }` for operator forms.
    pub(super) fn read_parameter_expansion(&mut self) -> Option<WordPart> {
        // Special case: ${#VAR} (length operator)
        if self.peek() == Some('#') {
            // Look ahead: if what follows '#' is a valid identifier and then '}',
            // this is the length operator.
            let saved = self.save_state();
            self.advance(); // skip #
            let name = self.read_identifier();
            if !name.is_empty() && self.peek() == Some('}') {
                self.advance(); // skip }
                return Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::Length,
                    embedded: Vec::new(),
                });
            }
            // Not a length operator; restore and fall through to flat parsing
            self.restore_state(saved);
        }

        // Read the variable name
        let name = self.read_identifier();
        if name.is_empty() {
            // Not a valid identifier; fall back to flat string
            let s = self.read_until_char('}');
            self.advance(); // skip }
            return Some(WordPart::ParameterExpansion(s));
        }

        // Check what follows the name
        match self.peek() {
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
                // patterned). Emit the unresolvable flat form instead so the word
                // stays expansion-bearing and floors. `${VAR^^}`/`${VAR^}` (no
                // pattern) resolves as before.
                if pattern.is_empty() {
                    Some(WordPart::ParameterExpansionOp {
                        name,
                        op: ParameterOperator::Uppercase { all },
                        embedded,
                    })
                } else {
                    let sigil = if all { "^^" } else { "^" };
                    Some(WordPart::ParameterExpansion(format!(
                        "{name}{sigil}{pattern}"
                    )))
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
                // the `Lowercase` op, so floor it via the unresolvable flat form.
                if pattern.is_empty() {
                    Some(WordPart::ParameterExpansionOp {
                        name,
                        op: ParameterOperator::Lowercase { all },
                        embedded,
                    })
                } else {
                    let sigil = if all { ",," } else { "," };
                    Some(WordPart::ParameterExpansion(format!(
                        "{name}{sigil}{pattern}"
                    )))
                }
            }
            _ => {
                // Unknown operator; fall back to flat string
                let rest = self.read_until_char('}');
                self.advance(); // skip }
                Some(WordPart::ParameterExpansion(format!("{name}{rest}")))
            }
        }
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
