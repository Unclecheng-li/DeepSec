# DeepSec 3 分钟快速上手

> 给 AI 写的代码做安全体检，30 秒看到第一个漏洞。
> 本指南全程中文，跟着做就能跑起来。

---

## 0. 我该用哪个？（先选一条路）

| 你是什么情况 | 推荐方式 | 耗时 |
|---|---|---|
| 不写代码，只想体验效果 | **下载 Windows/Linux 版 TUI** | 1 分钟 |
| 开发者，用 VS Code | **安装 VS Code 插件** | 2 分钟 |
| 开发者，用命令行 | **pip 安装 CLI** | 2 分钟 |
| 想扫自己的项目 | **pip 安装 CLI**（推荐） | 2 分钟 |

> **最快体验路径**：**下载 TUI 版 → 双击 → 输入 `/shield scan 你的项目文件夹`**，2 秒出结果。

---

## 1. 安装（三选一）

### 方式 A：下载即用（最快，推荐新手）

1. 打开 [Releases 页面](https://github.com/Unclecheng-li/DeepSec/releases)
2. 下载最新版里的：
   - **Windows** → `deepsec-tui-windows.exe`
   - **Linux** → `deepsec-tui-linux`
3. 双击运行（Windows 可能需要允许未知发布者）

### 方式 B：pip 安装 CLI（开发者推荐）

```bash
# 要求 Python 3.10+
pip install deepsec
```

> 如果 PyPI 还没同步，可以下载 Release 里的 `deepsec-0.2.0-py3-none-any.whl` 直接安装：
>
> ```bash
> pip install deepsec-0.2.0-py3-none-any.whl
> ```

### 方式 C：VS Code 插件（IDE 实时提示）

1. 下载 Release 里的 `deepsec-0.2.0.vsix`
2. VS Code 扩展面板 → 右上角 `...` → **Install from VSIX** → 选中该文件
3. 打开项目，AI 写代码时实时标红

---

## 2. 第一次扫描：2 秒看到漏洞

仓库里自带一个**故意写满漏洞的示例文件** `demo/unsafe-ai-sample.ts`，用来演示。

### 用命令行

```bash
cd <DeepSec 项目目录>
deepsec shield scan demo
```

你会看到类似输出（真实运行结果）：

```
+-----------------------------------------------------------------------------+
| Severity | Location            | Rule                | Finding              |
|----------+---------------------+---------------------+----------------------|
| critical | ...\unsafe-ai-sample.ts:4 | hardcoded_secret_o… | OpenAI API key       |
|          |                     |                     | appears to be        |
|          |                     |                     | hardcoded.           |
| high     | ...\unsafe-ai-sample.ts:11 | sast_xss_inner_html | HTML is assigned     |
|          |                     |                     | directly to the DOM. |
+-----------------------------------------------------------------------------+
Scanned 1 file(s) in 10.8 ms; 2 finding(s).
```
一个 `critical`（硬编码 OpenAI API Key）+ 一个 `high`（XSS，`.innerHTML` 直接渲染用户输入）——这正是 AI 最爱犯的两种错。

### 用 TUI（终端工作台）

```bash
deepsec tui
```

在底部命令行输入：

```
/shield scan demo
```

TUI 会流式显示扫描过程和结果，三面板布局（工作区 / 会话记录 / 漏洞面板）。

---

## 3. 扫你自己的项目

```bash
# 扫整个项目（L1 即时检测 + L2 SAST，全程本地离线）
deepsec shield scan <你的项目路径>

# 扫指定目录
deepsec shield scan ./src

# 生成 SARIF 报告（CI 用）
deepsec shield scan . --format sarif --output deepsec.sarif

# 生成 Markdown 报告
deepsec shield scan . --format markdown --output shield.md
```

**三层检测各管什么：**

| 层 | 检测内容 | 速度 | 原理 |
|---|---|---|---|
| **L1** | 幻觉包、硬编码密钥、不安全配置、AI 错误模式 | < 50ms | 正则 + 熵分析 + 种子目录 |
| **L2** | SQL 注入、XSS、SSRF、路径穿越、命令注入 | < 2s | Tree-sitter AST 污点追踪 |
| **L3** | 缺失认证/限流/校验等语义漏洞 | < 5s | LLM（DeepSeek/Claude/OpenAI/Ollama） |

> L1 + L2 默认开启、完全离线，**不需要任何 API Key**。
> L3 需要配置 LLM Key（见下），不开也不影响基本使用。

---

## 4.（可选）开启 L3 语义分析

```bash
# 配置 LLM（支持 13+ 家，DeepSeek 为例）
deepsec config set llm.provider deepseek
deepsec config set llm.api_key "sk-xxx"

# 或直接用环境变量
export DEEPSEC_LLM_API_KEY="sk-xxx"

# 带 L3 扫描
deepsec shield scan ./src --layer l3
```

---

## 5.（进阶）Spear 授权渗透测试

> 注意：只能测**你拥有或已书面授权**的目标，白名单外的一律拒绝。

```bash
# 1. 把目标加进白名单（TUI 里直接 /scope add）
/scope add https://your-authorized-domain.com

# 2. 开始渗透（Recon → 漏洞发现 → 报告 → PoC 全流程）
deepsec spear run https://your-authorized-domain.com --authorized ~/.deepsec/targets/scope.json

# 3. 只看侦察阶段
deepsec spear recon https://your-authorized-domain.com --authorized ~/.deepsec/targets/scope.json
```

---

## 常见问题

**Q：Windows 双击 exe 没反应？**
试试在终端里运行：`.\deepsec-tui-windows.exe`，看报错信息。

**Q：`deepsec` 命令找不到？**
确认 Python 3.10+ 已装，且 pip 的 Scripts 目录在 PATH 里（Windows 常见）。重开终端再试。

**Q：扫描会不会把我的代码传出去？**
不会。L1/L2 完全本地离线。只有显式 `--layer l3` 才会调用你配置的 LLM，且发送前会先把密钥脱敏成 `DEEPSEC_REDACTED_SECRET`。

**Q：扫描太慢 / 误报多？**
先扫单个目录 `deepsec shield scan ./src`，用 `--format json` 看完整规则名；规则文件在 `deepsec/shield/` 下，欢迎提 issue 或 PR 一起完善。

---

## 下一步

- 完整文档：[Architecture](architecture.md) · [Shield Guide](shield-guide.md) · [Spear Guide](spear-guide.md)
- 报 Bug / 提需求：[Issues](https://github.com/Unclecheng-li/DeepSec/issues)
- 觉得有用？给仓库点个 Star，安全圈的朋友欢迎一起贡献检测规则

---

<div align="center">

**3 分钟，让 AI 写的每一行代码都有人把关。**

</div>
