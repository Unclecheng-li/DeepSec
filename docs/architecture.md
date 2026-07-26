# DeepSec Architecture

DeepSec has one Python security core and three clients: the `deepsec` CLI, the Rust terminal workbench, and IDE bridges. Shield produces a common finding schema for local pattern checks, AST checks, semantic checks, agent checks, and supply-chain checks. Spear consumes the same schema for authorized assessment evidence and attack-chain reports.

## Components

- `deepsec/core`: typed configuration, findings, LLM routing, authorization, reports, and snapshots.
- `deepsec/shield`: local-first code and dependency auditing. L3 is opt-in when source must be sent to an LLM.
- `deepsec/spear`: the migrated assessment engine. Every command is gated by a signed scope manifest.
- `tui`: Ratatui client. It reads newline-delimited JSON events from the Python CLI on background threads.
- `src/deepsecBridge.ts`: VS Code adapter. The extension uses `deepsec.*` IDs and still reads legacy `vibeguard.*` settings.
- `jetbrains`: IntelliJ distribution with the DeepSec tool window and shared LSP bundle.

## Runtime Artifacts

`~/.deepsec/runs/` stores LLM usage metadata and Spear authorization audit logs. A Spear audit event records the target, command, timestamp, signer, scope file, and authorization hash. Reports can also write SARIF, Markdown, HTML, and attack-chain JSON.

## Local Development

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
cargo build --release --manifest-path tui\Cargo.toml
deepsec shield scan .\src --format sarif --output deepsec.sarif
deepsec tui
```

The Python TUI launcher discovers `tui/target/release/deepsec-tui-native.exe` when run from this checkout. In `cmd.exe`, use `py -3 -m deepsec ...`; PowerShell syntax such as `$env:Path += ...` is not valid in `cmd.exe`.
