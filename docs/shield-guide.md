# Shield Guide

Shield is local-first. L1 and L2 scan source without sending it off the machine; L3 adds semantic heuristics and may call a configured LLM only when explicitly selected.

```powershell
deepsec shield scan .\src
deepsec shield scan .\src --layer l1,l2 --format sarif --output deepsec.sarif
deepsec shield scan .\src --layer l3 --format markdown --output shield.md
deepsec shield agent-audit .\agent-config
deepsec shield supply-chain check .
```

`--layer all` keeps remote L3 disabled. An explicit `--layer l3` uses a configured provider when a key is available; `--remote-l3` is an explicit override. Use `--stream` only for a client that consumes line-delimited JSON events, such as the Rust TUI.

Shield returns exit code `2` when it finds an active high or critical finding. CI should retain SARIF output even for that expected nonzero result.
