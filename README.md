<div align="center">

<img src="https://raw.githubusercontent.com/Unclecheng-li/VibeGuard/main/media/VibeGuardIcon.png" width="120" height="120" alt="DeepSec">

<h1>DeepSec</h1>

<p><strong>AI 安全攻防一体平台 — Shield 代码审计 + Spear 授权渗透测试</strong></p>

<p>Catch what AI missed. Penetrate what others can't.</p>

<p>
  <a href="https://github.com/Unclecheng-li/VibeGuard/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Unclecheng-li/VibeGuard/ci.yml?branch=main&logo=github&label=CI" alt="CI"></a>
  <a href="https://github.com/Unclecheng-li/VibeGuard/releases"><img src="https://img.shields.io/github/v/release/Unclecheng-li/VibeGuard?display_name=tag&logo=github" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Unclecheng-li/VibeGuard?color=blue" alt="License"></a>
  <a href="https://github.com/Unclecheng-li/VibeGuard/stargazers"><img src="https://img.shields.io/github/stars/Unclecheng-li/VibeGuard?style=social" alt="Stars"></a>
</p>

<p>
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript&logoColor=white" alt="TypeScript">
  <img src="https://img.shields.io/badge/Rust-ratatui-CE422B?logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/VSCode-1.92+-007ACC?logo=visualstudiocode&logoColor=white" alt="VSCode">
  <img src="https://img.shields.io/badge/JetBrains-2025.2+-000000?logo=jetbrains&logoColor=white" alt="JetBrains">
</p>

</div>

---

## What is DeepSec?

DeepSec 是从 VibeGuard 演进而来的 AI 安全攻防一体化工具。它将 **Shield**（AI 代码安全审计）与 **Spear**（授权渗透测试引擎）统一在一个 CLI、一个 TUI 终端工作台、一套 IDE 插件之中。

```
┌──────────────────────────────────────────────────────────┐
│                      DeepSec Platform                     │
│                                                          │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│   │ Shield   │  │  Spear   │  │   TUI    │  │   MCP   │ │
│   │ Code     │  │ Pentest  │  │ Terminal │  │ Server  │ │
│   │ Audit    │  │ Engine   │  │ Workbench│  │         │ │
│   └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬────┘ │
│        │             │             │              │       │
│        └─────────────┴─────────────┴──────────────┘       │
│                          │                               │
│              ┌───────────┴───────────┐                   │
│              │   Unified Config      │                   │
│              │   ~/.deepsec/         │                   │
│              │   config.yaml         │                   │
│              └───────────────────────┘                   │
└──────────────────────────────────────────────────────────┘
         │                              │
   ┌─────┴─────┐                  ┌─────┴──────┐
   │  VSCode   │                  │  JetBrains │
   │  Plugin   │                  │   Plugin   │
   │  (TS/LSP) │                  │  (Kotlin)  │
   └───────────┘                  └────────────┘
```

### Shield — 代码安全审计

三层检测架构，从实时正则到 LLM 语义分析：

| Layer | 检测内容 | 速度 | 方法 |
|-------|---------|------|------|
| **L1** | 幻觉包、硬编码密钥、不安全配置、AI 编码模式 | < 50ms | 正则 + 熵分析 + 种子目录 |
| **L2** | SQL 注入、XSS、SSRF、路径穿越、命令注入 | < 2s | Tree-sitter WASM AST 分析 |
| **L3** | 缺失认证/限流/校验、语义漏洞 | < 5s | LLM（DeepSeek/Claude/OpenAI/Ollama）+ 本地启发式回退 |

### Spear — 授权渗透测试

从 VulnClaw 迁移的端到端自动化渗透引擎：

- **Recon → Explore → Fact → Reflect → Report → PoC** 全流程自动化
- 40+ 内置技能包（nmap、dirsearch、subfinder、nuclei、sqlmap、ffuf、httpx、feroxbuster）
- 5 种角色（pentester、redteam、auditor、blueteam、ctf_player）
- 签名授权作用域（Signed Scope），时间限制 + 审计日志
- 攻击链可视化、多格式报告（Markdown / SARIF / JSON / HTML）

### TUI — 终端工作台

Rust + ratatui 构建的安全工作台，借鉴 DeepSeek-TUI 的交互设计：

- 三面板布局：Workspace 侧栏 · Session Transcript · Findings Inspector
- Plan / Agent / YOLO 三模式切换
- 斜杠命令体系 + 命令历史回溯
- Side-Git 快照（随时创建/恢复代码状态）
- 会话持久化（Ctrl+S 保存 / Ctrl+R 恢复）

---

## Quick Start

### 安装

```bash
# Python 核心 + CLI
pip install -e .

# Rust TUI（可选）
cargo build --manifest-path tui/Cargo.toml

# IDE 插件
# VSCode: 在项目根目录按 F5 启动 Extension Development Host
# JetBrains: cd jetbrains && ./gradlew buildPlugin
```

### Shield 扫描

```bash
# 扫描项目（L1 + L2，本地离线）
deepsec shield scan ./src

# 启用 L3 语义分析（需要 LLM API Key）
DEEPSEEK_API_KEY=... deepsec shield scan ./src --layer l3

# 输出 SARIF 报告
deepsec shield scan . --format sarif --output deepsec.sarif

# 流式输出（供 TUI 消费）
deepsec shield scan . --stream

# Agent 配置审计
deepsec shield agent-audit ./agent-config

# 供应链安全检查
deepsec shield supply-chain check .
```

### Spear 渗透测试

```bash
# 1.（可选）维护授权白名单 —— 推荐直接在 TUI 里用 /scope 命令
#    也可手动编辑 ~/.deepsec/targets/scope.json 的 targets 字段
#    若仍需强校验签名：export DEEPSEC_SCOPE_SIGNING_KEY=... && deepsec scope sign ./scope.json

# 2. 运行渗透测试（目标必须已在白名单中）
deepsec spear run https://authorized-target.example --authorized ./scope.json

# 3. 仅侦察阶段
deepsec spear recon https://authorized-target.example --authorized ./scope.json

# 4. 查看角色和工具
deepsec spear roles
deepsec spear tools --role pentester
```

### TUI 终端工作台

```bash
# 启动终端工作台
deepsec tui

# 或直接运行 Rust 原生二进制
./tui/target/debug/deepsec-tui-native
```

TUI 内置斜杠命令：

| 命令 | 说明 |
|------|------|
| `/shield scan` | 运行 Shield 扫描 |
| `/spear run` | 运行 Spear 渗透（需通过白名单授权） |
| `/spear recon` | 运行侦察阶段 |
| `/scope add <目标>` | 将目标加入授权白名单（允许列表） |
| `/scope remove <目标>` | 从白名单移除目标 |
| `/scope list` | 列出当前白名单 |
| `/report` | 生成报告 |
| `/plan` | 切换到 Plan 模式 |
| `/agent` | 切换到 Agent 模式 |
| `/yolo` | 切换到 YOLO 模式（全自动） |
| `/clear` | 清空会话 |
| `/help` | 帮助 |

#### TUI 实战：添加白名单并开启渗透测试

DeepSec TUI 内置了授权白名单管理，无需再手动编辑 `scope.json`，也不再需要 HMAC 签名密钥。

**1. 启动 TUI**

```bash
deepsec tui
```

**2. 把目标加入白名单**

在 TUI 命令行（底部 `> ` 提示符）输入：

```
/scope add https://your-authorized-domain.com
```

- 目标会被规范化（scheme+host 转小写、去掉末尾 `/`）并去重，与后端授权匹配规则一致。
- 不指定 `--file` 时，默认写入**最近一次 `/spear run --authorized <文件>` 解析到的绝对路径**；若还没跑过 spear，则回落到 `~/.deepsec/targets/scope.json`。
- 查看现有白名单：`/scope list`
- 移除某个目标：`/scope remove https://your-authorized-domain.com`

**3. 开启渗透测试**

```
/spear run https://your-authorized-domain.com --authorized ~/.deepsec/targets/scope.json
```

随后：

- 按 `Tab` 在 **Plan / Agent / YOLO** 之间切换执行模式（YOLO 为全自动，无需逐步确认）。
- Plan 模式为只读，不能直接 arm Spear，需切到 Agent 或 YOLO。
- 按 `Y` 确认授权验证并真正启动；按 `Esc` 取消。
- 运行中按 `Ctrl+C` 可**中止当前任务**（TUI 保持打开）；空闲时按 `Ctrl+C` 退出 TUI。

**4. 安全边界**

- 白名单外的目标一律被拒（`target ... is not present in the scope manifest`）。
- 私网 / 回环 / 非公网地址仍被拦截，防止误打内网。
- 白名单仅接受你**确实拥有或已获书面授权**的资产；任意第三方生产域名若不在 `targets` 中，照样打不出去。

### Side-Git 快照

```bash
# 创建快照
deepsec snapshot create . --mode shield --description "before-refactor"

# 列出快照
deepsec snapshot list .

# 恢复快照
deepsec restore <snapshot-id>
```

---

## Screenshots

<div align="center">
<table>
<tr>
<td align="center"><b>Real-time diagnostics</b></td>
<td align="center"><b>Hover for details</b></td>
</tr>
<tr>
<td><img src="https://raw.githubusercontent.com/Unclecheng-li/VibeGuard/main/media/demonstration/realtime-diagnostic.png" alt="Real-time diagnostics" width="400"></td>
<td><img src="https://raw.githubusercontent.com/Unclecheng-li/VibeGuard/main/media/demonstration/hover-tooltip.png" alt="Hover tooltip" width="400"></td>
</tr>
<tr>
<td align="center"><b>Quick Fix menu</b></td>
<td align="center"><b>Problems panel</b></td>
</tr>
<tr>
<td><img src="https://raw.githubusercontent.com/Unclecheng-li/VibeGuard/main/media/demonstration/quick-fix.png" alt="Quick Fix menu" width="400"></td>
<td><img src="https://raw.githubusercontent.com/Unclecheng-li/VibeGuard/main/media/demonstration/problems-panel.png" alt="Problems panel" width="400"></td>
</tr>
</table>
</div>

---

## Architecture

DeepSec 是一个多语言项目：

| 组件 | 语言 | 文件数 | 代码行数 | 用途 |
|------|------|--------|---------|------|
| **Python 核心** | Python 3.10+ | 153 | 43,500+ | Shield 扫描器、Spear 引擎、CLI、MCP Server、角色/工具系统 |
| **IDE 插件** | TypeScript | 53 | 21,000+ | VSCode 扩展、LSP Server、Tree-sitter SAST |
| **TUI** | Rust | 22 | 2,470+ | ratatui 终端工作台 |
| **Rust LSP** | Rust | 5 | 7,800+ | 原生 L1 LSP 预览 |

### 项目结构

```
deepsec/                 # Python 核心
├── cli/                 # Typer CLI 入口 (shield/spear/snapshot/config/scope)
├── config/              # 统一 YAML 配置 + Pydantic schema
├── core/                # 配置适配、LLM 客户端、授权、快照、角色
├── shield/              # L1/L2/L3 扫描器、供应链安全、去重、忽略规则
├── spear/               # 渗透引擎 (agent/intel/skills/report/warstories)
├── roles/               # YAML 角色定义 (pentester/redteam/auditor/blueteam/ctf_player)
├── tools/               # YAML 工具目录 (nmap/dirsearch/nuclei/sqlmap/...)
├── mcp/                 # MCP Server (lifecycle/registry/router/diagnostics)
├── report/              # 报告生成 + 攻击链可视化
├── kb/                  # 知识库
├── plugins/             # 插件系统
└── traffic/             # 流量回放与归一化

src/                     # TypeScript IDE 插件
├── extension.ts         # VSCode 扩展入口
├── lspServer.ts         # LSP Server (Node)
├── scanner.ts           # L1/L2 扫描器
├── deepsecBridge.ts     # Python 核心桥接
└── ...

tui/                     # Rust TUI 终端工作台
├── src/
│   ├── app.rs           # 应用状态 + 命令调度
│   ├── events.rs        # 键盘事件处理
│   ├── ui/              # 三面板布局 (transcript/findings/layout)
│   ├── views/           # Skills Manager 侧栏
│   ├── theme.rs         # CodeWhale 深色主题
│   ├── sessions.rs      # 会话持久化
│   └── skills/          # 技能树目录
└── Cargo.toml

rust-lsp/                # Rust 原生 L1 LSP 预览
jetbrains/               # JetBrains 插件 (Kotlin)
docs/                    # 操作指南
```

---

## Configuration

DeepSec 使用统一的 YAML 配置文件 `~/.deepsec/config.yaml`：

```bash
deepsec config init      # 初始化配置
deepsec config show      # 查看配置
deepsec config set llm.provider deepseek  # 设置配置项
```

### LLM 配置

DeepSec 支持 13+ LLM 提供商：

| 提供商 | Base URL | 默认模型 |
|--------|----------|---------|
| DeepSeek | `api.deepseek.com/v1` | `deepseek-chat` |
| Anthropic Claude | `api.anthropic.com/v1` | `claude-sonnet-5` |
| OpenAI | `api.openai.com/v1` | `gpt-4o` |
| 智谱 GLM | `open.bigmodel.cn/api/paas/v4` | `glm-4.7` |
| Kimi (月之暗面) | `api.moonshot.cn/v1` | `kimi-k2.6` |
| 通义千问 | `dashscope.aliyuncs.com/compatible-mode/v1` | `qwen3-max` |
| SiliconFlow | `api.siliconflow.cn/v1` | `deepseek-ai/DeepSeek-V4-Flash` |
| 豆包 (字节跳动) | `ark.cn-beijing.volces.com/api/v3` | `Doubao-Seed-2.0-Pro` |
| 百川 | `api.baichuan-ai.com/v1` | `Baichuan4-Turbo` |
| MiniMax | `api.minimaxi.com/v1` | `MiniMax-M3` |
| 阶跃星辰 | `api.stepfun.com/v1` | `step-3.5-flash` |
| 商汤 (日日新) | `api.sensenova.cn/v1` | `SenseNova-6.7-Flash-Lite` |
| 零一万物 (Yi) | `api.lingyiwanwu.com/v1` | `yi-lightning` |
| Custom | 自定义 | 自定义 |

```bash
# 设置 API Key
deepsec config set llm.provider deepseek
deepsec config set llm.api_key "sk-xxx"

# 或通过环境变量
export DEEPSEC_LLM_API_KEY="sk-xxx"
```

### Spear 授权

Spear 以**授权白名单（allow-list）**为核心闸门：只有 `scope.json` 的 `targets` 中明确列出的目标才能被渗透，白名单外的目标一律拒绝。

> **签名已改为可选**：早期版本要求对 `scope.json` 做 HMAC-SHA256 签名并配置 `DEEPSEC_SCOPE_SIGNING_KEY`。现已移除强制签名——`signature` / `signer` 字段保留但被忽略，授权只看 `targets` 白名单（可选的时间窗仍会校验）。这意味着你不再需要 `export` 密钥、重签、重开 TUI，直接在 TUI 里用 `/scope` 命令维护白名单即可（见上文「TUI 实战」）。

作用域文件格式（`~/.deepsec/targets/scope.json`）：

```json
{
  "version": 1,
  "targets": ["https://your-authorized-domain.com"],
  "valid_from": "2026-07-26T00:00:00Z",
  "valid_until": "2026-08-25T00:00:00Z",
  "prohibited_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"],
  "signer": "UncleC",
  "signature": "0000000000000000000000000000000000000000000000000000000000000000",
  "signature_algorithm": "hmac-sha256"
}
```

- `targets`：允许被渗透的目标列表，支持 `https://域名`、`域名`、`*.域名` 通配、纯 IP/CIDR。匹配时自动去尾 `/`、转小写，scheme 需对齐。
- `prohibited_cidrs`：默认拦截私网 / 回环 / 链路本地地址，防止误打内网。
- 若仍想保留强校验，可手动 `deepsec scope sign ./scope.json`（需 `DEEPSEC_SCOPE_SIGNING_KEY`）；不签也不影响使用。

```bash
# （可选）手动签名
export DEEPSEC_SCOPE_SIGNING_KEY="your-secret"
deepsec scope sign ./scope.json

# 校验作用域结构 / 时间窗 / 可选签名
deepsec scope verify ./scope.json
```

---

## IDE Integration

### VSCode

VSCode 扩展提供实时诊断、Quick Fix、Findings 侧边栏：

| 设置 | 默认值 | 说明 |
|------|--------|------|
| `deepsec.enabled` | `true` | 启用/禁用扫描 |
| `deepsec.scanOnChange` | `true` | 编辑时扫描 |
| `deepsec.scanOnSave` | `true` | 保存时扫描 |
| `deepsec.enableL2` | `true` | 启用 L2 SAST |
| `deepsec.l2DebounceMs` | `500` | L2 防抖 |
| `deepsec.enableL3` | `false` | 启用 L3 语义分析 |
| `deepsec.l3DebounceMs` | `2000` | L3 防抖 |
| `deepsec.llmProvider` | — | LLM 提供商 |
| `deepsec.deepsecPythonPath` | — | DeepSec Python 路径 |
| `deepsec.dedupWithExistingTools` | `true` | 与 SonarQube/Snyk/Semgrep/CodeQL 去重 |

**Quick Fixes：**
- 幻觉包 → 推荐替代包名
- 硬编码密钥 → 环境变量读取
- `yaml.load()` → `yaml.safe_load()`
- SQL f-string → 参数化查询
- `innerHTML` → `textContent`
- 调试/CORS/主机检查 → 机械修复

### JetBrains

JetBrains 插件通过 LSP 协议复用 DeepSec 诊断能力，支持 JetBrains 2025.2+：

```bash
cd jetbrains
./gradlew buildPlugin
# 产物: build/distributions/deepsec-*.zip
```

### Rust LSP 预览

独立的 Rust 原生 L1 LSP Server，提供更低延迟的基础检测：

```bash
cargo run --manifest-path rust-lsp/Cargo.toml -- --stdio
```

---

## CLI Reference

```bash
# Shield 命令
deepsec shield scan <path> [--layer all|l1|l2|l3] [--format text|json|sarif|markdown|html] [--stream]
deepsec shield agent-audit <path>
deepsec shield watch <path> [--interval 1.0]
deepsec shield supply-chain check <path> [--private-package pkg]

# Spear 命令
deepsec spear run <target> --authorized <scope.json> [--scope full|web|api|mobile] [--mode quick|standard|deep]
deepsec spear recon <target> --authorized <scope.json>
deepsec spear roles
deepsec spear tools [--role pentester]

# 快照命令
deepsec snapshot create <path> [--mode shield|spear] [--description "..."]
deepsec snapshot list <path>

# 配置命令
deepsec config init
deepsec config set <key> <value>
deepsec config show

# 授权命令
deepsec scope sign <scope.json>      # （可选）对作用域签名，需 DEEPSEC_SCOPE_SIGNING_KEY
deepsec scope verify <scope.json>    # 校验作用域结构 / 时间窗 / 可选签名

# 其他
deepsec tui                          # 启动 TUI
deepsec chat                         # 交互式 Spear 工作台
deepsec tools                        # 列出所有工具
deepsec report <result.json> [--format markdown|json|sarif|html] [--chain]
deepsec restore <snapshot-id>
```

---

## Roles & Tools

### 内置角色

| 角色 | 模式 | 说明 |
|------|------|------|
| `pentester` | standard | 标准渗透测试 |
| `redteam` | deep | 红队深度攻击 |
| `auditor` | standard | 安全审计（只读） |
| `blueteam` | quick | 蓝队快速验证 |
| `ctf_player` | quick | CTF 竞赛模式 |

### 内置工具

| 工具 | 类别 | 安装检查 |
|------|------|---------|
| nmap | network | `nmap --version` |
| dirsearch | web | `dirsearch --version` |
| subfinder | recon | `subfinder -version` |
| httpx | web | `httpx -version` |
| feroxbuster | web | `feroxbuster --version` |
| ffuf | web | `ffuf -V` |
| nuclei | web | `nuclei -version` |
| sqlmap | web | `sqlmap --version` |

通过 `deepsec/tools/*.yaml` 添加自定义工具，通过 `deepsec/roles/*.yaml` 添加自定义角色。

---

## MCP Server

DeepSec 内置 MCP（Model Context Protocol）Server，可被 Claude Desktop、Cursor 等 MCP 客户端调用：

```python
from deepsec.mcp import MCPServer

server = MCPServer()
server.run()
```

支持的工具包括 Shield 扫描、Spear 侦察、报告生成等。

---

## Testing

```bash
# Python 测试
python -m pytest tests/deepsec/ -v

# TypeScript 测试
npm test

# Rust TUI 测试
cargo test --manifest-path tui/Cargo.toml

# Rust LSP 测试
cargo test --manifest-path rust-lsp/Cargo.toml
```

当前状态：**30 Python tests passed · 32 Rust TUI tests passed · TypeScript clean**

---

## Docker

```bash
docker build -t deepsec:local .
docker run --rm -v "$PWD:/workspace" deepsec:local shield scan /workspace
```

---

## Contributing

```bash
git clone https://github.com/Unclecheng-li/VibeGuard.git
cd VibeGuard

# Python 开发环境
pip install -e .[dev]

# Node.js IDE 插件开发
nvm use  # Node.js 22 LTS
npm install
npm run build

# Rust TUI 开发
cargo build --manifest-path tui/Cargo.toml
```

- **Report bugs** — [Open an issue](https://github.com/Unclecheng-li/VibeGuard/issues)
- **Request features** — [Start a discussion](https://github.com/Unclecheng-li/VibeGuard/discussions)
- **Submit PRs** — Fork, feature branch, pull request

---

## Documentation

- [Architecture](docs/architecture.md) — 系统架构详解
- [Shield Guide](docs/shield-guide.md) — 代码审计指南
- [Spear Guide](docs/spear-guide.md) — 渗透测试指南
- [Skill Development](docs/skill-development.md) — 技能包开发
- [Tool Config](docs/tool-config.md) — 工具配置
- [DeepSeek Optimization](docs/deepseek-optimization.md) — DeepSeek 模型优化
- [Migration Design](doc/DeepSec-改造设计文档.md) — 从 VibeGuard 到 DeepSec 的改造设计
- [TUI Dev Guide](doc/DeepSec-TUI开发文档.md) — TUI 开发文档

---

## License

[MIT](LICENSE) © 2026 DeepSec contributors

---

<div align="center">

<sub>Built for developers who ship AI-generated code — and need to break it before attackers do.</sub>

<sub>If DeepSec helps you, consider [starring the repo](https://github.com/Unclecheng-li/VibeGuard/stargazers) or [sponsoring](https://github.com/sponsors/Unclecheng-li).</sub>

</div>
