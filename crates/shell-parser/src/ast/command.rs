use super::*;

impl Command {
    /// Returns all direct child commands of this node.
    pub fn children(&self) -> Vec<&Command> {
        match self {
            Command::Simple(_) | Command::Assignment(_) => vec![],
            Command::Pipeline(cmds) | Command::Sequence(cmds) => cmds.iter().collect(),
            Command::And(a, b) | Command::Or(a, b) => vec![a, b],
            Command::Background(c) | Command::Subshell(c) | Command::BraceGroup(c) => vec![c],
            Command::If {
                condition,
                then_branch,
                elif_branches,
                else_branch,
            } => {
                let mut children = vec![condition.as_ref(), then_branch.as_ref()];
                for (cond, body) in elif_branches {
                    children.push(cond);
                    children.push(body);
                }
                if let Some(eb) = else_branch {
                    children.push(eb);
                }
                children
            }
            Command::For { body, .. } => vec![body],
            Command::Loop {
                condition, body, ..
            } => {
                vec![condition, body]
            }
            Command::Case { arms, .. } => arms.iter().filter_map(|arm| arm.body.as_ref()).collect(),
            Command::FunctionDef { body, .. } => vec![body],
            Command::Redirected { command, .. } => vec![command],
        }
    }
}

impl SimpleCommand {
    pub(crate) fn command_name(&self) -> Option<&str> {
        self.words.first().map(|w| {
            // Return a reference to the first literal part
            if let Some(WordPart::Literal(s)) = w.parts.first() {
                s.as_str()
            } else {
                ""
            }
        })
    }

    #[cfg(test)]
    pub(crate) fn args(&self) -> &[Word] {
        if self.words.len() > 1 {
            &self.words[1..]
        } else {
            &[]
        }
    }
}
