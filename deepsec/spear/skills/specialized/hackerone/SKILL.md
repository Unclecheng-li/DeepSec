---
name: hackerone
description: HackerOne 赏金项目 scope-guard 流程 — 读取 program scope，强制 scope 与 program rules，再逐个把 in-scope asset 交给 pentest-flow
requires_target: false
---

# HackerOne 赏金 scope-guard Skill

你当前正在执行 HackerOne bug bounty 流程。本 Skill 是一层 **scope-guard wrapper**：
先解析并强制 program scope 与 program rules，再把每个 **in-scope asset** 交给
`pentest-flow` Skill 执行真正的渗透。**严禁在任何阶段触碰 out-of-scope asset。**

启动参数是一个 HackerOne program 链接（`<SCOPE LINK>`），例如
`hackerone.com/<handle>` 或 `.../policy_scopes`。本 Skill 无预设 target
（frontmatter `requires_target: false`）——target 从 scope 中发现。

## 阶段一：读取 scope（Read scope）

1. **优先 fetch 链接**
   - 用 fetch 工具访问传入的 `<SCOPE LINK>`。
   - HackerOne 是 JavaScript SPA：`hackerone.com/*` 的 fetch 通常只返回
     **空 app shell**，没有渲染出的 scope 行（scope 数据来自 `hackerone.com/graphql`
     或 authenticated `api.hackerone.com`，naive fetch 拿不到）。
   - **检测空壳**：若响应中没有可识别的 scope 表格 / asset 列表（只有
     `<div id="app">` 之类的骨架），判定为 fetch 失败。

2. **fallback：请用户粘贴 scope**
   - fetch 为空 / 被 login-wall / 仅 JS 渲染时，**这是常态而非例外**。
   - 请用户从 program 页面的 **Scope** 标签把 in-scope 与 out-of-scope 两张表
     直接粘贴过来。给出一个可参照的粘贴格式示例：

     ```
     In scope:
     https://api.example.com        | URL       | Eligible for bounty
     *.example.com                  | WILDCARD  | Eligible for bounty
     app.example.com                | URL       | In scope, NOT bounty-eligible
     com.example.android            | GOOGLE_PLAY_APP_ID | Eligible for bounty

     Out of scope:
     blog.example.com               | URL
     *.corp.example.com             | WILDCARD
     ```

3. **宽松解析（lenient parse）**
   - 从粘贴或 fetch 结果中提取两个列表：**in-scope** 与 **out-of-scope**。
   - 识别 asset type（human label 或 API enum 均可）：
     `URL`、`WILDCARD`（`*.x.com`）、`CIDR`/IP、`SOURCE_CODE`、
     `GOOGLE_PLAY_APP_ID`/`APPLE_STORE_APP_ID`/`TESTFLIGHT`/`OTHER_APK`/`OTHER_IPA`、
     `HARDWARE`、`AI_MODEL`、`SMART_CONTRACT`、`OTHER` 等。
   - 识别 **eligibility 三态**（submission 与 bounty 是两个独立布尔）：
     - `submission=true, bounty=true` → in scope，可测，有赏金。
     - `submission=true, bounty=false` → **in scope，可测，无赏金**（勿与 out-of-scope 混淆）。
     - `submission=false` → **out of scope，绝不测试**。
   - 解析不确定时，向用户确认，**绝不把 asset 默认当作 in-scope**。

4. **输出**
   - in-scope asset 列表（含 type + eligibility）。
   - out-of-scope **deny-list**（用于全程强制）。

## 阶段二：强制边界（Enforce boundaries）

在进入任何测试前，明确写下并全程遵守以下 **硬性规则**：

1. **Scope 硬边界**
   - 只测试 in-scope 列表中的 asset。
   - out-of-scope deny-list 中的 asset **绝不触碰**——不 fetch、不扫描、不发任何 payload。
   - `pentest-flow` 只能直接作用于 `URL` 与 `WILDCARD` 类型；其它类型
     （mobile app / source / CIDR / hardware 等）暂不自动化，需先与用户确认处理方式。

2. **Program rules（层叠在 VulnClaw 既有 `BLOCKED_PATTERNS` / `RESERVED_IP_RANGES` 之上）**
   - **no DoS / 无可用性影响**：禁止压力测试、资源耗尽、批量并发（自动化扫描器的首要红线）。
   - **尊重 rate limit / automation limit**：低速、串行；遵守 program 声明的 "no automated scanning" 条款。
   - **no social engineering**：不针对人员，不钓鱼。
   - **minimal impact / no PII exfil**：验证漏洞即止，不导出真实用户数据、不做破坏性操作。

3. **异常处理**
   - 任何一步若可能越过 scope 或触发上述规则，**停止并询问用户**。

## 阶段三：枚举与确认（Enumerate & confirm）

1. 向用户列出全部已解析的 in-scope asset（编号、type、eligibility）。
2. 询问从哪个 asset 开始（或全部）。
3. **一次只处理一个 asset**，逐个确认，避免并发导致越界或触发 rate limit。

## 阶段四：委派 pentest-flow（Delegate）

对用户选定的 **单个 in-scope asset**：

1. 将该 asset 作为 target 交给 `pentest-flow` Skill，执行
   recon → vuln-discovery → exploitation 全流程。
2. 全程保持在 scope 内：`pentest-flow` 发现的新子域 / 端点若超出
   in-scope 定义（尤其不匹配任何 in-scope `WILDCARD`），**排除**并提示用户。
3. 持续对照阶段二的 program rules。

## 阶段五：报告（Report — HackerOne submission format）

对每个确认的 finding，按 **HackerOne 提交格式** 输出一份报告：

1. **Title** — 简洁描述漏洞（type + 受影响 asset）。
2. **Asset** — 受影响的 in-scope asset（URL / 标识）。
3. **Severity (CVSS)** — CVSS 向量与分数（Critical/High/Medium/Low）。
4. **Steps to Reproduce** — 可复现的分步操作（含请求 / 响应 / payload）。
5. **Impact** — 可利用性与业务影响。
6. **Remediation** — 修复建议。

多个 finding 时，每个独立成节；附可参数化的 Python PoC（requests 库）。
提醒用户：报告仅供其在 HackerOne 上 **人工提交**，本 Skill 不自动上报。

## 参考文档

- `references/hackerone-report-and-scope.md` — scope 解析参考（asset type ↔ API enum、
  eligibility 三态、粘贴表形状）、program rules 强制清单、HackerOne 提交格式报告模板。
