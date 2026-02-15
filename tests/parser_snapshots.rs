// Snapshot tests for the shell parser, organized by complexity.
//
// Each test parses a shell snippet and snapshots the Debug AST output.
// Test cases are drawn from the Oils for Unix spec test corpus and other
// known tricky bash constructs.
//
// Run: cargo test --test parser_snapshots
// Review: cargo insta review

use may_i::parser::parse;

// ── Simple commands & basic syntax ──────────────────────────────────

mod simple {
    use super::*;

    #[test]
    fn command_with_args() {
        insta::assert_debug_snapshot!(parse("echo hello world"));
    }

    #[test]
    fn single_quoted_string() {
        insta::assert_debug_snapshot!(parse("echo 'hello world'"));
    }

    #[test]
    fn double_quoted_string() {
        insta::assert_debug_snapshot!(parse("echo \"hello world\""));
    }

    #[test]
    fn variable_reference() {
        insta::assert_debug_snapshot!(parse("echo $HOME"));
    }

    #[test]
    fn redirect_output() {
        insta::assert_debug_snapshot!(parse("echo hello > out.txt"));
    }

    #[test]
    fn redirect_input() {
        insta::assert_debug_snapshot!(parse("cat < input.txt"));
    }

    #[test]
    fn redirect_append() {
        insta::assert_debug_snapshot!(parse("echo hello >> log.txt"));
    }

    #[test]
    fn pipeline() {
        insta::assert_debug_snapshot!(parse("ls -la | grep foo"));
    }

    #[test]
    fn semicolon_sequence() {
        insta::assert_debug_snapshot!(parse("echo a; echo b; echo c"));
    }

    #[test]
    fn background() {
        insta::assert_debug_snapshot!(parse("sleep 10 &"));
    }

    #[test]
    fn comment() {
        insta::assert_debug_snapshot!(parse("echo hello # this is a comment"));
    }

    #[test]
    fn empty_input() {
        insta::assert_debug_snapshot!(parse(""));
    }

    #[test]
    fn whitespace_only() {
        insta::assert_debug_snapshot!(parse("   \t  "));
    }
}

// ── Compound commands ───────────────────────────────────────────────

mod compound {
    use super::*;

    #[test]
    fn and_list() {
        insta::assert_debug_snapshot!(parse("make && make install"));
    }

    #[test]
    fn or_list() {
        insta::assert_debug_snapshot!(parse("test -f file || echo missing"));
    }

    #[test]
    fn and_or_chain() {
        insta::assert_debug_snapshot!(parse("a && b || c && d"));
    }

    #[test]
    fn subshell() {
        insta::assert_debug_snapshot!(parse("(cd /tmp && ls)"));
    }

    #[test]
    fn brace_group() {
        insta::assert_debug_snapshot!(parse("{ echo a; echo b; }"));
    }

    #[test]
    fn if_then_fi() {
        insta::assert_debug_snapshot!(parse("if true; then echo yes; fi"));
    }

    #[test]
    fn if_else() {
        insta::assert_debug_snapshot!(parse("if true; then echo yes; else echo no; fi"));
    }

    #[test]
    fn if_elif_else() {
        insta::assert_debug_snapshot!(parse(
            "if test -f a; then echo a; elif test -f b; then echo b; else echo c; fi"
        ));
    }

    #[test]
    fn for_loop() {
        insta::assert_debug_snapshot!(parse("for x in a b c; do echo $x; done"));
    }

    #[test]
    fn while_loop() {
        insta::assert_debug_snapshot!(parse("while read line; do echo $line; done"));
    }

    #[test]
    fn until_loop() {
        insta::assert_debug_snapshot!(parse("until false; do echo wait; done"));
    }

    #[test]
    fn case_basic() {
        insta::assert_debug_snapshot!(parse(
            "case $x in a) echo a;; b) echo b;; *) echo other;; esac"
        ));
    }

    #[test]
    fn case_multiple_patterns() {
        insta::assert_debug_snapshot!(parse(
            "case $x in a|b|c) echo match;; esac"
        ));
    }

    #[test]
    fn case_fallthrough() {
        insta::assert_debug_snapshot!(parse(
            "case $x in a) echo a;& b) echo b;; esac"
        ));
    }

    #[test]
    fn case_continue() {
        insta::assert_debug_snapshot!(parse(
            "case $x in a) echo a;;& b) echo b;; esac"
        ));
    }

    #[test]
    fn function_definition() {
        insta::assert_debug_snapshot!(parse("greet() { echo hello; }"));
    }

    #[test]
    fn function_no_parens() {
        insta::assert_debug_snapshot!(parse("function greet { echo hello; }"));
    }
}

// ── Assignments ─────────────────────────────────────────────────────

mod assignments {
    use super::*;

    #[test]
    fn standalone() {
        insta::assert_debug_snapshot!(parse("FOO=bar"));
    }

    #[test]
    fn with_command() {
        insta::assert_debug_snapshot!(parse("FOO=bar cmd arg"));
    }

    #[test]
    fn empty_value() {
        insta::assert_debug_snapshot!(parse("FOO="));
    }
}

// ── Redirections ────────────────────────────────────────────────────

mod redirections {
    use super::*;

    #[test]
    fn output_clobber() {
        insta::assert_debug_snapshot!(parse("echo hello >| out.txt"));
    }

    #[test]
    fn fd_redirect() {
        insta::assert_debug_snapshot!(parse("cmd 2>&1"));
    }

    #[test]
    fn multiple_redirections() {
        insta::assert_debug_snapshot!(parse("cmd > out.txt 2>&1"));
    }

    #[test]
    fn fd_prefix() {
        insta::assert_debug_snapshot!(parse("cmd 2> err.txt"));
    }

    #[test]
    fn herestring() {
        insta::assert_debug_snapshot!(parse("cat <<< 'hello'"));
    }

    #[test]
    fn heredoc_basic() {
        insta::assert_debug_snapshot!(parse("cat <<EOF\nhello world\nline two\nEOF"));
    }

    #[test]
    fn heredoc_strip_tabs() {
        insta::assert_debug_snapshot!(parse("cat <<-EOF\n\thello\n\tworld\n\tEOF"));
    }

    #[test]
    fn heredoc_single_quoted_delimiter() {
        insta::assert_debug_snapshot!(parse("cat <<'EOF'\nhello $var\nEOF"));
    }

    #[test]
    fn heredoc_double_quoted_delimiter() {
        insta::assert_debug_snapshot!(parse("cat <<\"EOF\"\nhello $var\nEOF"));
    }

    #[test]
    fn heredoc_backslash_delimiter() {
        insta::assert_debug_snapshot!(parse("cat <<\\EOF\nhello\nEOF"));
    }

    #[test]
    fn heredoc_empty_body() {
        insta::assert_debug_snapshot!(parse("cat <<EOF\nEOF"));
    }

    #[test]
    fn heredoc_unterminated() {
        insta::assert_debug_snapshot!(parse("cat <<EOF\nhello\nworld"));
    }
}

// ── Quoting & expansion ────────────────────────────────────────────

mod quoting {
    use super::*;

    #[test]
    fn single_quotes_preserve_literal() {
        insta::assert_debug_snapshot!(parse("echo '$HOME is not expanded'"));
    }

    #[test]
    fn double_quotes_with_variable() {
        insta::assert_debug_snapshot!(parse("echo \"hello $USER\""));
    }

    #[test]
    fn double_quotes_with_command_sub() {
        insta::assert_debug_snapshot!(parse("echo \"today is $(date)\""));
    }

    #[test]
    fn escaped_quote_in_double_quotes() {
        insta::assert_debug_snapshot!(parse(r#"echo "a \"quoted\" word""#));
    }

    #[test]
    fn mixed_quoting() {
        // Three segments concatenated: single-quoted + double-quoted + single-quoted
        insta::assert_debug_snapshot!(parse("echo 'hello '\"$USER\"' world'"));
    }

    #[test]
    fn ansi_c_quoting() {
        insta::assert_debug_snapshot!(parse("echo $'hello\\nworld'"));
    }

    #[test]
    fn ansi_c_tab() {
        insta::assert_debug_snapshot!(parse("echo $'col1\\tcol2'"));
    }

    #[test]
    fn backslash_escape_outside_quotes() {
        insta::assert_debug_snapshot!(parse("echo hello\\ world"));
    }

    #[test]
    fn bare_dollar_sign() {
        insta::assert_debug_snapshot!(parse("echo $"));
    }
}

// ── Parameter expansion ─────────────────────────────────────────────

mod parameter_expansion {
    use super::*;

    #[test]
    fn simple_variable() {
        insta::assert_debug_snapshot!(parse("echo $var"));
    }

    #[test]
    fn braced_variable() {
        insta::assert_debug_snapshot!(parse("echo ${var}"));
    }

    #[test]
    fn default_value() {
        insta::assert_debug_snapshot!(parse("echo ${var:-default}"));
    }

    #[test]
    fn alternate_value() {
        insta::assert_debug_snapshot!(parse("echo ${var:+alternate}"));
    }

    #[test]
    fn strip_prefix() {
        insta::assert_debug_snapshot!(parse("echo ${var##*.}"));
    }

    #[test]
    fn strip_suffix() {
        insta::assert_debug_snapshot!(parse("echo ${var%%.*}"));
    }

    #[test]
    fn string_length() {
        insta::assert_debug_snapshot!(parse("echo ${#var}"));
    }

    #[test]
    fn special_variables() {
        insta::assert_debug_snapshot!(parse("echo $? $! $$ $# $@ $* $0"));
    }
}

// ── Command & process substitution ──────────────────────────────────

mod substitution {
    use super::*;

    #[test]
    fn command_sub_dollar() {
        insta::assert_debug_snapshot!(parse("echo $(whoami)"));
    }

    #[test]
    fn command_sub_backtick() {
        insta::assert_debug_snapshot!(parse("echo `whoami`"));
    }

    #[test]
    fn nested_command_sub() {
        insta::assert_debug_snapshot!(parse("echo $(echo $(whoami))"));
    }

    #[test]
    fn arithmetic_expansion() {
        insta::assert_debug_snapshot!(parse("echo $((1 + 2))"));
    }

    #[test]
    fn process_sub_input() {
        insta::assert_debug_snapshot!(parse("diff <(sort a) <(sort b)"));
    }

    #[test]
    fn process_sub_output() {
        insta::assert_debug_snapshot!(parse("tee >(grep foo) >(grep bar)"));
    }
}

// ── Globs & brace expansion ────────────────────────────────────────

mod globs {
    use super::*;

    #[test]
    fn star() {
        insta::assert_debug_snapshot!(parse("ls *.rs"));
    }

    #[test]
    fn question_mark() {
        insta::assert_debug_snapshot!(parse("ls file?.txt"));
    }

    #[test]
    fn bracket() {
        insta::assert_debug_snapshot!(parse("ls [abc].txt"));
    }

    #[test]
    fn brace_expansion() {
        insta::assert_debug_snapshot!(parse("echo {a,b,c}"));
    }

    #[test]
    fn brace_no_comma_is_literal() {
        insta::assert_debug_snapshot!(parse("echo {foo}"));
    }
}

// ── Complex / tricky combinations ───────────────────────────────────

mod complex {
    use super::*;

    #[test]
    fn pipeline_in_subshell_with_and() {
        insta::assert_debug_snapshot!(parse("(ls | grep foo) && echo done"));
    }

    #[test]
    fn heredoc_with_pipe() {
        // The pipe is after the heredoc terminator — tricky for parsers
        insta::assert_debug_snapshot!(parse("cat <<EOF\nhello\nEOF"));
    }

    #[test]
    fn while_with_heredoc() {
        insta::assert_debug_snapshot!(parse(
            "while read line; do echo $line; done <<EOF\na\nb\nEOF"
        ));
    }

    #[test]
    fn for_with_command_sub_in_words() {
        insta::assert_debug_snapshot!(parse("for f in $(ls *.txt); do cat $f; done"));
    }

    #[test]
    fn nested_if_in_while() {
        insta::assert_debug_snapshot!(parse(
            "while true; do if test -f done; then break; fi; done"
        ));
    }

    #[test]
    fn multiple_assignments_before_command() {
        insta::assert_debug_snapshot!(parse("A=1 B=2 C=3 cmd arg"));
    }

    #[test]
    fn redirect_with_fd_and_pipe() {
        insta::assert_debug_snapshot!(parse("cmd 2>&1 | grep error"));
    }

    #[test]
    fn semicolon_and_background_mixed() {
        insta::assert_debug_snapshot!(parse("cmd1 & cmd2; cmd3 &"));
    }

    #[test]
    fn case_with_command_sub_word() {
        insta::assert_debug_snapshot!(parse(
            "case $(uname) in Linux) echo linux;; Darwin) echo mac;; esac"
        ));
    }

    #[test]
    fn deeply_nested_subshells() {
        insta::assert_debug_snapshot!(parse("(( (echo deep) ))"));
    }

    #[test]
    fn function_with_local_and_redirect() {
        insta::assert_debug_snapshot!(parse(
            "f() { local x=1; echo $x > /dev/null; }"
        ));
    }

    #[test]
    fn pipeline_of_compound_commands() {
        insta::assert_debug_snapshot!(parse(
            "{ echo a; echo b; } | sort | uniq"
        ));
    }

    #[test]
    fn mixed_word_parts() {
        // Literal + expansion + literal concatenated in one word
        insta::assert_debug_snapshot!(parse("echo prefix${VAR}suffix"));
    }

    #[test]
    fn double_quotes_multiple_expansions() {
        insta::assert_debug_snapshot!(parse(
            r#"echo "user=$USER home=$HOME shell=$SHELL""#
        ));
    }
}
