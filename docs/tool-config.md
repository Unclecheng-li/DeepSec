# Tool Configuration

DeepSec currently catalogs `nmap`, `nuclei`, `sqlmap`, `dirsearch`, `subfinder`, `httpx`, `ffuf`, and `feroxbuster`. The catalog records installation checks and suggested installation commands; it does not install tools automatically.

```powershell
deepsec tools
deepsec spear tools --role pentester
deepsec spear tools --role ctf_player
```

Tool access is role-filtered through `min_role`. `blueteam` intentionally exposes no active Spear tools. The other roles are `pentester`, `auditor`, `redteam`, and `ctf_player`. Authorization remains independent of a role: choosing `redteam` does not bypass a signed Spear scope, address restrictions, or the audit log.

Keep external binaries on `PATH`, verify their version with the catalog's `install.check` value, and prefer a dedicated test environment. Tool output is evidence, not an automatically verified finding.
