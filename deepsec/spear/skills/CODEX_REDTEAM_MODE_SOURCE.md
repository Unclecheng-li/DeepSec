Source: https://github.com/chAng-L19/codex-redteam-mode/

Imported content:

- `agents/skills/redteam-*-detail-pack/SKILL.md`
- `agents/skills/redteam-cve-lookup/SKILL.md`
- `agents/skills/redteam-cve-validation/SKILL.md`
- `agents/skills/redteam-recon-intake/SKILL.md`

Excluded content:

- `redteam-jailbreak-detail-pack`
- `red-team-command-doctrine`
- Codex prompt patchers, refusal/jailbreak/session-switching material, and any
  non-skill files from the upstream repository.

Rationale:

These imported files are used as opt-in authorized red-team knowledge cards in
VulnClaw's skill/knowledge layer. They are not used as a forced router and do
not constrain the default model-led solve engine.

License:

The upstream repository is MIT licensed. Keep the upstream MIT license notice
with redistributed copies or substantial portions.
