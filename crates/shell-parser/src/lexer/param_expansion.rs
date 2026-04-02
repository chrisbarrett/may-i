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
                let pattern = self.read_until_char('}');
                self.advance(); // skip }
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::StripPrefix { longest, pattern },
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
                let pattern = self.read_until_char('}');
                self.advance(); // skip }
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::StripSuffix { longest, pattern },
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
                let pattern = self.read_until_either('/', '}');
                let replacement = if self.peek() == Some('/') {
                    self.advance(); // skip separator /
                    self.read_until_char('}')
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
                })
            }
            Some(':') => {
                self.advance(); // skip :
                match self.peek() {
                    Some('-') => {
                        self.advance();
                        let value = self.read_until_char('}');
                        self.advance();
                        Some(WordPart::ParameterExpansionOp {
                            name,
                            op: ParameterOperator::Default { colon: true, value },
                        })
                    }
                    Some('+') => {
                        self.advance();
                        let value = self.read_until_char('}');
                        self.advance();
                        Some(WordPart::ParameterExpansionOp {
                            name,
                            op: ParameterOperator::Alternative { colon: true, value },
                        })
                    }
                    Some('?') => {
                        self.advance();
                        let message = self.read_until_char('}');
                        self.advance();
                        Some(WordPart::ParameterExpansionOp {
                            name,
                            op: ParameterOperator::Error {
                                colon: true,
                                message,
                            },
                        })
                    }
                    Some('=') => {
                        self.advance();
                        let value = self.read_until_char('}');
                        self.advance();
                        Some(WordPart::ParameterExpansionOp {
                            name,
                            op: ParameterOperator::Assign { colon: true, value },
                        })
                    }
                    _ => {
                        // Substring: ${VAR:offset} or ${VAR:offset:length}
                        let offset = self.read_until_either(':', '}');
                        let length = if self.peek() == Some(':') {
                            self.advance();
                            Some(self.read_until_char('}'))
                        } else {
                            None
                        };
                        self.advance(); // skip }
                        Some(WordPart::ParameterExpansionOp {
                            name,
                            op: ParameterOperator::Substring { offset, length },
                        })
                    }
                }
            }
            Some('-') => {
                self.advance();
                let value = self.read_until_char('}');
                self.advance();
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::Default {
                        colon: false,
                        value,
                    },
                })
            }
            Some('+') => {
                self.advance();
                let value = self.read_until_char('}');
                self.advance();
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::Alternative {
                        colon: false,
                        value,
                    },
                })
            }
            Some('?') => {
                self.advance();
                let message = self.read_until_char('}');
                self.advance();
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::Error {
                        colon: false,
                        message,
                    },
                })
            }
            Some('=') => {
                self.advance();
                let value = self.read_until_char('}');
                self.advance();
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::Assign {
                        colon: false,
                        value,
                    },
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
                // Skip to closing }
                self.read_until_char('}');
                self.advance();
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::Uppercase { all },
                })
            }
            Some(',') => {
                self.advance();
                let all = if self.peek() == Some(',') {
                    self.advance();
                    true
                } else {
                    false
                };
                // Skip to closing }
                self.read_until_char('}');
                self.advance();
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::Lowercase { all },
                })
            }
            _ => {
                // Unknown operator; fall back to flat string
                let rest = self.read_until_char('}');
                self.advance(); // skip }
                Some(WordPart::ParameterExpansion(format!("{name}{rest}")))
            }
        }
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

    /// Read until either `a` or `b` is found (or EOF). Does not consume the delimiter.
    pub(super) fn read_until_either(&mut self, a: char, b: char) -> String {
        let mut s = String::new();
        while let Some(ch) = self.peek() {
            if ch == a || ch == b {
                break;
            }
            s.push(ch);
            self.advance();
        }
        s
    }
}
