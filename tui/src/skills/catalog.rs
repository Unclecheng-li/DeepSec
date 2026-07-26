#[derive(Clone, Debug)]
pub struct SkillNode {
    pub name: String,
    pub children: Vec<SkillNode>,
}

pub fn skill_tree() -> Vec<SkillNode> {
    vec![
        SkillNode {
            name: "Shield".into(),
            children: vec![
                leaf("patterns"),
                leaf("sast"),
                leaf("ai-audit"),
                leaf("agent-security"),
                leaf("supply-chain"),
            ],
        },
        SkillNode {
            name: "Spear".into(),
            children: vec![leaf("recon"), leaf("verification"), leaf("reporting")],
        },
    ]
}

fn leaf(name: &str) -> SkillNode {
    SkillNode {
        name: name.into(),
        children: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::skill_tree;

    #[test]
    fn exposes_shield_and_spear_as_parent_nodes() {
        let skills = skill_tree();

        assert_eq!(skills.len(), 2);
        assert_eq!(skills[0].name, "Shield");
        assert_eq!(skills[1].name, "Spear");
        assert!(!skills[0].children.is_empty());
        assert!(!skills[1].children.is_empty());
    }
}
