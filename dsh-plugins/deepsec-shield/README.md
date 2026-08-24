# dsh-deepsec-shield

DeepSec Shield 网络安全审查插件，为 [DeepSeek Harness（dsh）](https://github.com/deepseek-ai/deepseek-harness) 提供代码安全审计工具。防御侧插件：只做本地/授权扫描，不发起任何主动攻击。

English summary: a dsh plugin exposing DeepSec Shield's defensive code-audit capabilities (SAST, secret detection, agent-config audit, supply-chain checks, report rendering) as agent tools.

## 提供的工具

| 工具 | 对应 CLI | 说明 |
|------|----------|------|
| `deepsec_scan` | `deepsec shield scan` | L1 模式/密钥/AI 错误检测 + L2 Tree-sitter AST 分析（注入/XSS/SSRF/路径穿越），可选 L3 语义审查。返回严重度汇总 + Top 发现 |
| `deepsec_agent_audit` | `deepsec shield agent-audit` | AI Agent 配置审计：提示注入、数据外泄、工具滥用 |
| `deepsec_supply_chain` | `deepsec shield supply-chain check` | 拼写抢注（typosquatting）与依赖混淆检测 |
| `deepsec_report` | `deepsec report` | 将保存的 JSON 结果渲染为 markdown / html / sarif，可生成攻击链可视化 |

退出码语义：DeepSec 审计命令在存在活跃 high/critical 发现时退出码为 `2`，插件将其映射为 `ok: true` + `hasActiveHighOrCritical: true`，而不是工具错误。

## 前置条件

- Node.js ≥ 20（dsh 本体要求）
- DeepSec CLI 可执行（二选一）：
  - `pip install -e /path/to/DeepSec`（本仓库）后 `deepsec` 在 PATH 上；
  - 或在插件配置里指定 `command: "py -3 -m deepsec"`。

L1/L2 完全本地执行，源码不出机器。只有显式传 `remoteL3: true`（或显式 `--layer l3` 且配置了密钥）才会调用远程 LLM。

## 安装

```bash
# 从本地仓库安装
dsh plugin --profile <profile> add <repo>/dsh-plugins/deepsec-shield

# 验证插件层已挂载（不启动会话）
dsh --profile <profile> --dump-config
```

发布到 npm 后也可以 `dsh plugin --profile <profile> add dsh-deepsec-shield`。

## 配置

```yaml
# profile 配置中的插件项
- id: deepsec-shield
  config:
    command: deepsec      # 或 "py -3 -m deepsec"
    timeoutMs: 600000     # 单命令超时；0 = 不限时
    maxFindings: 50       # 返回给模型的最大发现条数
    maxOutputChars: 40000 # 捕获 CLI 输出的上限（字符）
```

## 返回结构（deepsec_scan）

```jsonc
{
  "ok": true,
  "exitCode": 2,
  "hasActiveHighOrCritical": true,
  "summary": { "activeFindings": 3, "bySeverity": { "critical": 1, "high": 2 }, "filesScanned": 42, "elapsedMs": 812.5 },
  "findings": [
    { "severity": "critical", "target": "src/auth.py", "line": 12, "rule": "hardcoded_secret", "title": "…", "suggestion": "…", "fixAvailable": true }
  ],
  "findingsTruncated": false
}
```

## Model experience

- 典型工作流：`deepsec_scan` → 按 `summary.bySeverity` 判断风险 → 对需要修复的项引用 `findings[].rule/line` → 需要交付物时用 `deepsec_report` 生成 markdown/sarif。
- 扫描大仓库时先 `layers: "l1,l2"`，确有需要再单独跑 L3。

## Known limitations

- 依赖外部 `deepsec` CLI；未安装时工具返回带安装指引的错误。
- `deepsec_scan` 始终以 `--format json --output -` 采集机器可读结果；需要 sarif/html 文件时用 `deepsec_report` 二次渲染。
- dsh 仍处于 developer preview，`defineTool`/schema 契约变更时本插件带 passthrough 兜底，但输出 shape 可能随 dsh 版本调整。
