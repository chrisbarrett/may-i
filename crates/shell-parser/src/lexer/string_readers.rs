use super::Lexer;

impl Lexer {
    pub(super) fn read_until_char(&mut self, end: char) -> String {
        let mut s = String::new();
        while let Some(ch) = self.peek() {
            if ch == end {
                break;
            }
            s.push(ch);
            self.advance();
        }
        s
    }

    pub(super) fn read_ansi_c_string(&mut self) -> String {
        let mut s = String::new();
        while let Some(ch) = self.peek() {
            if ch == '\'' {
                break;
            }
            self.advance();
            if ch == '\\' {
                match self.peek() {
                    None => s.push('\\'),
                    Some(esc) => {
                        self.advance();
                        match esc {
                            '\\' => s.push('\\'),
                            'n' => s.push('\n'),
                            't' => s.push('\t'),
                            'r' => s.push('\r'),
                            'a' => s.push('\x07'),
                            'b' => s.push('\x08'),
                            'e' | 'E' => s.push('\x1B'),
                            'f' => s.push('\x0C'),
                            'v' => s.push('\x0B'),
                            '\'' => s.push('\''),
                            '"' => s.push('"'),
                            '0' => {
                                // Octal: \0NNN (up to 3 octal digits)
                                let mut oct = String::new();
                                for _ in 0..3 {
                                    match self.peek() {
                                        Some(c) if c.is_ascii_digit() && c < '8' => {
                                            oct.push(c);
                                            self.advance();
                                        }
                                        _ => break,
                                    }
                                }
                                if oct.is_empty() {
                                    s.push('\0');
                                } else if let Ok(val) = u32::from_str_radix(&oct, 8)
                                    && let Some(c) = char::from_u32(val)
                                {
                                    s.push(c);
                                }
                            }
                            'x' => {
                                // Hex: \xHH (up to 2 hex digits)
                                let mut hex = String::new();
                                for _ in 0..2 {
                                    match self.peek() {
                                        Some(c) if c.is_ascii_hexdigit() => {
                                            hex.push(c);
                                            self.advance();
                                        }
                                        _ => break,
                                    }
                                }
                                if let Ok(val) = u32::from_str_radix(&hex, 16)
                                    && let Some(c) = char::from_u32(val)
                                {
                                    s.push(c);
                                }
                            }
                            'u' => {
                                // Unicode: \uHHHH (up to 4 hex digits)
                                let mut hex = String::new();
                                for _ in 0..4 {
                                    match self.peek() {
                                        Some(c) if c.is_ascii_hexdigit() => {
                                            hex.push(c);
                                            self.advance();
                                        }
                                        _ => break,
                                    }
                                }
                                if let Ok(val) = u32::from_str_radix(&hex, 16)
                                    && let Some(c) = char::from_u32(val)
                                {
                                    s.push(c);
                                }
                            }
                            'U' => {
                                // Unicode: \UHHHHHHHH (up to 8 hex digits)
                                let mut hex = String::new();
                                for _ in 0..8 {
                                    match self.peek() {
                                        Some(c) if c.is_ascii_hexdigit() => {
                                            hex.push(c);
                                            self.advance();
                                        }
                                        _ => break,
                                    }
                                }
                                if let Ok(val) = u32::from_str_radix(&hex, 16)
                                    && let Some(c) = char::from_u32(val)
                                {
                                    s.push(c);
                                }
                            }
                            'c' => {
                                // Control character: \cX
                                if let Some(ctrl) = self.peek() {
                                    self.advance();
                                    let ctrl_val = (ctrl as u32) & 0x1F;
                                    if let Some(c) = char::from_u32(ctrl_val) {
                                        s.push(c);
                                    }
                                }
                            }
                            other => {
                                // Unknown escape: literal character (bash behavior)
                                s.push(other);
                            }
                        }
                    }
                }
            } else {
                s.push(ch);
            }
        }
        s
    }

    /// Returns `(content, found_closing)`.
    pub(super) fn read_until_double_paren_checked(&mut self) -> (String, bool) {
        let mut s = String::new();
        loop {
            match self.peek() {
                None => return (s, false),
                Some(')') if self.peek_at(1) == Some(')') => {
                    self.advance();
                    self.advance();
                    return (s, true);
                }
                Some(ch) => {
                    s.push(ch);
                    self.advance();
                }
            }
        }
    }

    pub(super) fn read_balanced_parens(&mut self) -> String {
        self.read_balanced_parens_checked().0
    }

    /// Returns `(content, found_closing)`.
    pub(super) fn read_balanced_parens_checked(&mut self) -> (String, bool) {
        let mut s = String::new();
        let mut depth = 1;
        loop {
            match self.peek() {
                None => return (s, false),
                Some('(') => {
                    depth += 1;
                    s.push('(');
                    self.advance();
                }
                Some(')') => {
                    depth -= 1;
                    if depth == 0 {
                        self.advance();
                        return (s, true);
                    }
                    s.push(')');
                    self.advance();
                }
                Some(ch) => {
                    s.push(ch);
                    self.advance();
                }
            }
        }
    }
}
