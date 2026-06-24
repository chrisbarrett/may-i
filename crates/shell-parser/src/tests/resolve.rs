use crate::*;
use std::collections::HashMap;

// -- Resolution of parameter expansion operators --

#[test]
fn resolve_param_length() {
    let env: HashMap<String, String> = [("VAR".into(), "hello".into())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Length,
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "5");
    assert!(!resolved.has_dynamic_parts());
}

#[test]
fn resolve_param_strip_prefix() {
    let env: HashMap<String, String> = [("PATH".into(), "/usr/local/bin".into())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "PATH".into(),
            op: ParameterOperator::StripPrefix {
                longest: true,
                pattern: "*/".into(),
            },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "bin");
    assert!(!resolved.has_dynamic_parts());
}

#[test]
fn resolve_param_strip_suffix() {
    let env: HashMap<String, String> = [("FILE".into(), "archive.tar.gz".into())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "FILE".into(),
            op: ParameterOperator::StripSuffix {
                longest: false,
                pattern: ".*".into(),
            },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "archive.tar");
}

#[test]
fn resolve_param_replace() {
    let env: HashMap<String, String> = [("VAR".into(), "hello world".into())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Replace {
                all: false,
                pattern: "world".into(),
                replacement: "rust".into(),
            },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "hello rust");
}

#[test]
fn resolve_param_default_colon_empty() {
    let env: HashMap<String, String> = [("VAR".into(), String::new())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Default {
                colon: true,
                value: "fallback".into(),
            },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "fallback");
}

#[test]
fn resolve_param_default_colon_set() {
    let env: HashMap<String, String> = [("VAR".into(), "value".into())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Default {
                colon: true,
                value: "fallback".into(),
            },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "value");
}

#[test]
fn resolve_param_alternative_colon_set() {
    let env: HashMap<String, String> = [("VAR".into(), "value".into())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Alternative {
                colon: true,
                value: "alt".into(),
            },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "alt");
}

#[test]
fn resolve_param_alternative_colon_empty() {
    let env: HashMap<String, String> = [("VAR".into(), String::new())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Alternative {
                colon: true,
                value: "alt".into(),
            },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "");
}

#[test]
fn resolve_param_substring() {
    let env: HashMap<String, String> = [("VAR".into(), "hello world".into())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Substring {
                offset: "6".into(),
                length: Some("5".into()),
            },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "world");
}

#[test]
fn resolve_param_substring_no_length() {
    let env: HashMap<String, String> = [("VAR".into(), "hello world".into())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Substring {
                offset: "6".into(),
                length: None,
            },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "world");
}

#[test]
fn resolve_param_uppercase_all() {
    let env: HashMap<String, String> = [("VAR".into(), "hello".into())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Uppercase { all: true },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "HELLO");
}

#[test]
fn resolve_param_uppercase_first() {
    let env: HashMap<String, String> = [("VAR".into(), "hello".into())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Uppercase { all: false },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "Hello");
}

#[test]
fn resolve_param_lowercase_all() {
    let env: HashMap<String, String> = [("VAR".into(), "HELLO".into())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Lowercase { all: true },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "hello");
}

#[test]
fn resolve_param_error_set() {
    let env: HashMap<String, String> = [("VAR".into(), "value".into())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Error {
                colon: true,
                message: "oops".into(),
            },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "value");
}

#[test]
fn resolve_param_assign_set() {
    let env: HashMap<String, String> = [("VAR".into(), "value".into())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Assign {
                colon: true,
                value: "default".into(),
            },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "value");
}

#[test]
fn resolve_param_unresolved_stays_dynamic() {
    let env: HashMap<String, String> = HashMap::new();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "UNKNOWN".into(),
            op: ParameterOperator::StripPrefix {
                longest: true,
                pattern: "*/".into(),
            },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert!(resolved.has_dynamic_parts());
    assert_eq!(resolved.dynamic_parts(), vec!["${UNKNOWN##*/}"]);
}

#[test]
fn resolve_param_op_in_double_quotes() {
    let env: HashMap<String, String> = [("HOME".into(), "/home/user".into())].into();
    let w = Word {
        parts: vec![WordPart::DoubleQuoted(vec![
            WordPart::ParameterExpansionOp {
                name: "HOME".into(),
                op: ParameterOperator::StripPrefix {
                    longest: true,
                    pattern: "*/".into(),
                },
                embedded: Vec::new(),
            },
        ])],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "user");
    assert!(!resolved.has_dynamic_parts());
}

// -- Resolution: non-colon Default (variable is set) --

#[test]
fn resolve_param_default_no_colon_set() {
    let env: HashMap<String, String> = [("VAR".into(), "hello".into())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Default {
                colon: false,
                value: "fallback".into(),
            },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "hello");
}

// -- Resolution: Alternative with colon:false --

#[test]
fn resolve_param_alternative_no_colon_set() {
    let env: HashMap<String, String> = [("VAR".into(), "hello".into())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Alternative {
                colon: false,
                value: "alt".into(),
            },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    // ${VAR+alt}: variable is set, so use alternative
    assert_eq!(resolved.to_str(), "alt");
}

// -- Resolution: Substring with negative offset --

#[test]
fn resolve_param_substring_negative_offset() {
    let env: HashMap<String, String> = [("VAR".into(), "hello world".into())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Substring {
                offset: "-5".into(),
                length: None,
            },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "world");
}

// -- Resolution: Uppercase first character only --

#[test]
fn resolve_param_uppercase_first_char() {
    let env: HashMap<String, String> = [("VAR".into(), "hello".into())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Uppercase { all: false },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "Hello");
}

#[test]
fn resolve_param_uppercase_first_empty() {
    let env: HashMap<String, String> = [("VAR".into(), "".into())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Uppercase { all: false },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "");
}

// -- Resolution: Lowercase first character only --

#[test]
fn resolve_param_lowercase_first() {
    let env: HashMap<String, String> = [("VAR".into(), "HELLO".into())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Lowercase { all: false },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "hELLO");
}

#[test]
fn resolve_param_lowercase_first_empty() {
    let env: HashMap<String, String> = [("VAR".into(), "".into())].into();
    let w = Word {
        parts: vec![WordPart::ParameterExpansionOp {
            name: "VAR".into(),
            op: ParameterOperator::Lowercase { all: false },
            embedded: Vec::new(),
        }],
    };
    let resolved = w.resolve(&env);
    assert_eq!(resolved.to_str(), "");
}
