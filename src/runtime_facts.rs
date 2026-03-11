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
