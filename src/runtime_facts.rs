use may_i_core::ContextFacts;

pub fn parse_cli_facts(raw_facts: &[String]) -> miette::Result<ContextFacts> {
    let mut context = ContextFacts::default();

    for raw in raw_facts {
        let (key, value) = parse_fact(raw)?;
        if context.has(&key) {
            return Err(miette::miette!("duplicate --fact key: {key}"));
        }
        match value {
            Some(value) => context.insert_scalar(key, value),
            None => context.insert_present(key),
        }
    }

    Ok(context)
}

fn parse_fact(raw: &str) -> miette::Result<(String, Option<String>)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(miette::miette!(
            "invalid --fact value: empty string; use :key or :key=value"
        ));
    }

    let (key, value) = match raw.split_once('=') {
        Some((key, value)) => (key, Some(value.to_string())),
        None => (raw, None),
    };

    validate_context_key(key)?;
    Ok((key.to_string(), value))
}

fn validate_context_key(key: &str) -> miette::Result<()> {
    if !key.starts_with(':') {
        return Err(miette::miette!(
            "context fact key must be namespaced: {key}\nhelp: use a namespaced key like :via/ssh or :claude-code/permission-mode"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parse_presence_fact() {
        let facts = parse_cli_facts(&[":via/ssh".to_string()]).unwrap();
        assert!(facts.has(":via/ssh"));
    }

    #[test]
    fn parse_scalar_fact() {
        let facts = parse_cli_facts(&[":env=prod".to_string()]).unwrap();
        assert_eq!(facts.get_scalar(":env"), Some("prod"));
    }

    #[test]
    fn empty_string_is_error() {
        assert!(parse_cli_facts(&["".to_string()]).is_err());
    }

    #[test]
    fn whitespace_only_is_error() {
        assert!(parse_cli_facts(&["   ".to_string()]).is_err());
    }

    #[test]
    fn missing_colon_prefix_is_error() {
        assert!(parse_cli_facts(&["no-colon".to_string()]).is_err());
    }

    #[test]
    fn duplicate_key_is_error() {
        assert!(parse_cli_facts(&[":k".to_string(), ":k".to_string()]).is_err());
    }

    #[test]
    fn scalar_value_with_equals_in_value() {
        let facts = parse_cli_facts(&[":key=a=b".to_string()]).unwrap();
        assert_eq!(facts.get_scalar(":key"), Some("a=b"));
    }

    proptest! {
        #[test]
        fn valid_presence_facts_roundtrip(key in ":[a-z][a-z/]{0,10}") {
            let facts = parse_cli_facts(&[key.clone()]).unwrap();
            prop_assert!(facts.has(&key));
        }

        #[test]
        fn valid_scalar_facts_roundtrip(
            key in ":[a-z][a-z/]{0,10}",
            value in "[a-zA-Z0-9_-]{1,20}",
        ) {
            let input = format!("{key}={value}");
            let facts = parse_cli_facts(&[input]).unwrap();
            prop_assert_eq!(facts.get_scalar(&key), Some(value.as_str()));
        }

        #[test]
        fn unnamespaced_keys_always_fail(key in "[a-z][a-z]{0,10}") {
            prop_assert!(parse_cli_facts(&[key]).is_err());
        }
    }
}
