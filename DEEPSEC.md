# DeepSec

DeepSec refactors VibeGuard into a Python-first security platform with two modes:

- `shield`: local L1 pattern detection, L2 SAST, opt-in L3 semantic review, Agent security checks, and supply-chain checks.
- `spear`: the MIT-licensed VulnClaw engine migrated below `deepsec.spear`, protected by an explicit `--authorized` acknowledgement at the new CLI entry point.

## Install

```powershell
py -3 -m pip install -e .
deepsec config init
deepsec shield scan . --format sarif --output deepsec.sarif
```

The configuration file is `~/.deepsec/config.toml`. L3 only calls a remote provider when explicitly selected and credentials are present. `DEEPSEC_LLM_API_KEY` overrides the configured key.

## Commands

```text
deepsec shield scan <path> [--layer l1,l2,l3] [--format json|sarif|markdown|html]
deepsec shield agent-audit <path>
deepsec shield supply-chain check <path> [--private-package NAME]
deepsec spear run <target> --authorized [--mode quick|standard|deep]
deepsec spear recon <target> --authorized
deepsec snapshot create <repo> --mode shield
deepsec snapshot list <repo>
deepsec report <result.json> --format markdown --chain
```

`deepsec spear` is for explicitly authorized targets only. It never runs from the new entry point without `--authorized`.

## IDE Bridge

Set `vibeguard.deepsecPythonPath` to the Python interpreter that has DeepSec installed. JetBrains deployments can set the inherited `DEEPSEC_PYTHON` environment variable instead. The existing LSP invokes `python -m deepsec shield scan ... --format json --output -`, maps the normalized findings back into LSP diagnostics, and falls back to the TypeScript implementation if the interpreter is unset or unavailable.

The extension retains `vibeguard.*` identifiers temporarily to preserve installed user configuration, keybindings, and Marketplace upgrade compatibility. Its visible display name is DeepSec.

## TUI

```powershell
cargo build --release --manifest-path tui/Cargo.toml
deepsec tui
```

When launched from this repository, `deepsec tui` finds the built binary automatically. In `cmd.exe`, run the same `cargo build` command followed by `deepsec tui`; no PowerShell `$env:Path` command is required.

The Ratatui workbench uses a CodeWhale-inspired Composer workflow: the session transcript is central, workspace capabilities are on the left, and the severity-colored findings inspector is on the right. Type `/` for command suggestions, then use `Up`/`Down` and `Enter` to complete one. The Composer supports cursor editing, pasted commands, and `Ctrl+P`/`Ctrl+N` command history. `Tab` cycles `Plan`, `Agent`, and `YOLO`; `Plan` permits read-only Shield scans but blocks Spear. `Shift+Tab` cycles the `Ask`, `Auto-review`, and `Full access` interaction postures; `Ctrl+T` exposes streaming reasoning; and `Ctrl+Left`/`Ctrl+Right` selects the panel that `Up`/`Down` scrolls. `/shield scan <path>` runs the Python Shield CLI with live events and a tracked execution receipt. Spear actions require an existing `--authorized <scope.json>` file, a separate `Y` confirmation in the TUI, and Python-side signature/target validation regardless of the selected posture.

## Migration Layout

`deepsec.spear.*` contains the migrated VulnClaw agent, skills, intel, reports, orchestration, target state, and legacy TUI/CLI support. Common MCP, KB, plugin, traffic, configuration, and i18n modules live under `deepsec.*`. New shared models and reporting live under `deepsec.core`.

`tests/spear` contains the migrated VulnClaw regression suite; `tests/deepsec` covers the new Shield core and CLI.
