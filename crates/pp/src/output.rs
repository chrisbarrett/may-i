use may_i_core::Trivia;

/// Trait for receiving structured events from the pretty-printer.
pub trait PrettyOutput<A> {
    fn begin_line(&mut self, indent: usize);
    fn emit_space(&mut self);
    fn emit_delim(&mut self, ch: char, dimmed: bool);
    fn emit_atom(&mut self, text: &str, ann: &A, dimmed: bool);
    /// Called when entering a list/vector node that carries an annotation.
    /// Default implementation is a no-op.
    fn emit_node_ann(&mut self, _ann: &A) {}

    /// Emit leading trivia (comments and preserved blank lines) before a node.
    /// Comments are placed on their own line at the given indent level.
    fn emit_leading_trivia(&mut self, trivia: &[Trivia], indent: usize) {
        let mut emitted_comment_with_newline = false;
        for (i, item) in trivia.iter().enumerate() {
            match item {
                Trivia::Comment { text, has_newline } => {
                    // Preserve blank lines from preceding whitespace
                    let prev_ws = if i > 0 {
                        if let Trivia::Whitespace(ws) = &trivia[i - 1] {
                            Some(ws.as_str())
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    if i == 0 && prev_ws.is_none() {
                        // Very first trivia item: emit indent without a
                        // leading newline.
                        for _ in 0..indent {
                            self.emit_raw(" ");
                        }
                    } else if let Some(ws) = prev_ws {
                        let newline_count = ws.matches('\n').count();
                        // The previous comment's has_newline consumed a \n that
                        // we didn't emit, so account for it in the total.
                        let total = if emitted_comment_with_newline {
                            1 + newline_count
                        } else {
                            newline_count.max(1)
                        };
                        for _ in 0..total.saturating_sub(1) {
                            self.begin_line(0);
                        }
                        self.begin_line(indent);
                    } else {
                        self.begin_line(indent);
                    }
                    self.emit_raw(text);
                    emitted_comment_with_newline = *has_newline;
                }
                Trivia::Whitespace(_) => {}
            }
        }
        // Position the cursor for the node content that follows the trivia.
        if emitted_comment_with_newline {
            // Check if there's trailing whitespace after the last comment that
            // represents blank lines between the comments and the form.
            let trailing_newlines = trivia
                .last()
                .and_then(|t| match t {
                    Trivia::Whitespace(ws) => Some(ws.matches('\n').count()),
                    _ => None,
                })
                .unwrap_or(0);
            // 1 begin_line for the comment's un-emitted trailing \n, plus
            // any additional newlines from trailing whitespace.
            for _ in 0..trailing_newlines {
                self.begin_line(0);
            }
            self.begin_line(indent);
        }
    }

    /// Emit trailing trivia (typically trailing comments) after a node.
    fn emit_trailing_trivia(&mut self, trivia: &[Trivia]) {
        for (i, item) in trivia.iter().enumerate() {
            match item {
                Trivia::Comment { text, has_newline } => {
                    let prev_ws = if i > 0 {
                        if let Trivia::Whitespace(ws) = &trivia[i - 1] {
                            Some(ws.as_str())
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    match prev_ws {
                        Some(ws) if ws.contains('\n') => {
                            let extra_newlines = ws.matches('\n').count();
                            for _ in 0..extra_newlines {
                                self.begin_line(0);
                            }
                            self.emit_raw(text);
                        }
                        Some(ws) => {
                            self.emit_raw(ws);
                            self.emit_raw(text);
                        }
                        None => {
                            self.emit_raw(text);
                        }
                    }
                    if *has_newline {
                        self.begin_line(0);
                    }
                }
                Trivia::Whitespace(ws) => {
                    // Emit trailing whitespace that isn't followed by a comment
                    // (whitespace before comments is handled above).
                    let next_is_comment = trivia
                        .get(i + 1)
                        .is_some_and(|t| matches!(t, Trivia::Comment { .. }));
                    if !next_is_comment {
                        self.emit_raw(ws);
                    }
                }
            }
        }
    }

    /// Emit raw text without any formatting. Used for trivia content.
    fn emit_raw(&mut self, text: &str);
}

/// Event emitted during flat-rendering for buffering and replay.
pub enum OutputEvent<A> {
    BeginLine(usize),
    Space,
    Delim(char, bool),
    Atom(String, A, bool),
    NodeAnn(A),
    Raw(String),
}
