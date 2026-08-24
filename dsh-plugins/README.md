# DeepSec 的 DeepSeek Harness（dsh）插件

把 DeepSec 平台的两大能力包装成 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（`dsh`）的 Agent 工具：防御侧的安全审查，与授权侧的渗透测试。两个插件都是独立的 npm 包（声明 `dsh.bundle`），通过 `dsh plugin add` 安装到 profile。

English summary: two standalone dsh plugin packages wrapping DeepSec's Shield (defensive code audit) and Spear (authorized penetration testing) CLIs as agent tools, preserving Spear's signed-scope authorization gate.

## 插件一览

| 包 | 目录 | 定位 | 工具 |
|----|------|------|------|
| `dsh-deepsec-shield` | [`deepsec-shield/`](./deepsec-shield/) | 网络安全审查（防御侧，本地优先） | `deepsec_scan`、`deepsec_agent_audit`、`deepsec_supply_chain`、`deepsec_report` |
| `dsh-deepsec-spear` | [`deepsec-spear/`](./deepsec-spear/) | 授权渗透测试（攻击侧，签名作用域强制） | `deepsec_scope_sign`、`deepsec_scope_verify`、`deepsec_spear_recon`、`deepsec_spear_run`、`deepsec_spear_catalog` |

## 设计要点

- **薄封装，不重写引擎**：插件以子进程调用 `deepsec` CLI（`--format json --output -` 采集机器可读结果），检测逻辑、授权逻辑、审计日志全部复用 DeepSec 本体，行为与 CLI 完全一致。
- **授权门禁不可绕过**：Spear 工具把已签名 scope manifest 作为必填参数传给 CLI；签名校验、时间窗口、目标成员关系、私网地址拒绝、审计日志均由 Python 侧强制执行，插件层没有任何旁路。
- **契约合规**：遵循 dsh 插件规范——命名导出 `name` / `inject` / `Config` / `apply(ctx, config)`；每次注册返回 disposer；`execute` 返回单一规范 JSON 值（领域失败放返回值，不抛异常）；遵守 `exec.signal` 取消信号；object 输出 schema 声明 `additionalProperties: true`。
- **优雅降级**：`@deepseek-ai/dsh-tools` / `@deepseek-ai/schemastery` 以可选 peer 依赖 + 动态导入兜底的方式使用，预览期契约变动时插件仍可加载。
- **退出码语义**：审计命令在存在活跃 high/critical 发现时退出码为 `2`，插件映射为 `ok: true` + `hasActiveHighOrCritical: true`。

## 安装与使用

前置：Node.js ≥ 20、DeepSec CLI（`pip install -e /path/to/DeepSec`，或配置 `command: "py -3 -m deepsec"`）。

```bash
# 从本仓库安装（pnpm 会读取 dsh.bundle 自动并入 profile bundle 层）
dsh plugin --profile <profile> add /path/to/DeepSec/dsh-plugins/deepsec-shield
dsh plugin --profile <profile> add /path/to/DeepSec/dsh-plugins/deepsec-spear

# 验证
dsh --profile <profile> --dump-config
```

安装后，在 dsh 会话里直接下自然语言指令即可，例如：

- “扫描 ./src 找硬编码密钥和注入风险，生成 markdown 报告”（Shield）
- “审计我的 Agent 配置有没有提示注入风险”（Shield）
- “这是授权方给的 scope.json，验证后对 https://target.example 做侦察”（Spear）

## 本地开发与测试

```bash
node --check dsh-plugins/deepsec-shield/index.js
node --check dsh-plugins/deepsec-spear/index.js
node dsh-plugins/test/smoke.mjs     # 需要本机 deepsec CLI；含授权门禁负向测试
```

冒烟测试用假 ctx 驱动两个插件的 `apply()`，并真实调用本机 `deepsec` CLI 验证：L1 扫描、供应链检查、scope 签名/验签往返，以及“目标不在授权范围内时 spear run 被拒绝”的安全负向用例。

## 发布

```bash
cd dsh-plugins/deepsec-shield && npm publish
cd dsh-plugins/deepsec-spear  && npm publish
```

发布后用户即可 `dsh plugin --profile <profile> add dsh-deepsec-shield`。建议同时给 GitHub 仓库打 `dsh-plugin` topic（生态的事实发现索引），并关注 dsh 仓库 `docs/` 的契约演进——本插件当前基于 developer preview 规范开发。

## 安全说明

- Shield 插件只做防御性扫描；L1/L2 本地执行，源码不出机器，L3 需显式 opt-in。
- Spear 插件仅用于**已获授权**的测试场景（渗透委托、CTF、自有系统）。签名密钥必须来自授权方，插件与模型不得自行生成。
