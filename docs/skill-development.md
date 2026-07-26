# Skill Development

DeepSec catalog entries live in `deepsec/roles/*.yaml` and `deepsec/tools/*.yaml`. Catalogs are reloaded on every CLI request, so a valid edit takes effect without restarting the process. Invalid YAML is logged as a warning and skipped rather than taking the catalog down.

A role defines its operating mode, permitted tools, skill namespaces, model preferences, and execution budgets. Tool entries must provide a name, description, category (`recon`, `exploit`, `verify`, or `report`), installation metadata, parameters, output parser metadata, skills, and a non-empty `min_role` list.

```yaml
name: example-tool
description: Example authorized verifier.
category: verify
install:
  check: example-tool --version
  command: pip install example-tool
  method: pip
parameters:
  target: "{target}"
output:
  format: json
  parse: true
skills: [web/verification]
min_role: [pentester, redteam]
```

Validate a catalog change with `deepsec tools` and `deepsec spear tools --role pentester`. Do not put destructive defaults, real credentials, or broad target ranges in a tool definition.
