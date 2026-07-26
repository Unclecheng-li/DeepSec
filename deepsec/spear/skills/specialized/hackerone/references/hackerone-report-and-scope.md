# HackerOne 报告模板与 scope 解析参考

本参考供 `hackerone` Skill 使用：右侧是 **scope 解析** 的目标形状，左侧是
**HackerOne 提交格式** 的报告模板。技术术语保留英文原文。

## 1. Scope 解析参考

### 1.1 asset type（human label ↔ API enum）

| Human label            | API enum                                   | pentest-flow 可直接处理 |
| ---------------------- | ------------------------------------------ | ----------------------- |
| Domain / URL           | `URL`                                      | ✅                      |
| Wildcard `*.x.com`     | `WILDCARD`                                 | ✅                      |
| IP range / CIDR        | `CIDR`                                     | ⚠️ 需确认（可能受限）   |
| Source code            | `SOURCE_CODE`                              | ❌ 人工                 |
| Android app            | `GOOGLE_PLAY_APP_ID` / `OTHER_APK`         | ❌ 需专用流程           |
| iOS app                | `APPLE_STORE_APP_ID` / `TESTFLIGHT` / `OTHER_IPA` | ❌ 需专用流程    |
| Hardware               | `HARDWARE`                                 | ❌ 人工                 |
| AI Model               | `AI_MODEL`                                 | ❌ 人工                 |
| Smart Contract         | `SMART_CONTRACT`                           | ❌ 人工                 |
| Other / ASN            | `OTHER`                                    | ⚠️ 需确认               |

### 1.2 eligibility 三态（submission × bounty 两个独立布尔）

| submission | bounty | 含义                                    | 行为             |
| ---------- | ------ | --------------------------------------- | ---------------- |
| true       | true   | in scope，可测，有赏金                  | 正常测试         |
| true       | false  | in scope，可测，**无赏金**              | 正常测试（勿跳过）|
| false      | —      | **out of scope**                        | **绝不触碰**     |

### 1.3 粘贴 scope 表的目标形状（lenient parse）

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

解析要点：
- 每行至少提取 **asset 标识** 与 **in/out 归属**；type 与 eligibility 尽量识别。
- 列顺序、分隔符（`|`、tab、多空格）都可能变化——按 token 宽松匹配。
- 任何无法确定归属的行，**向用户确认，绝不默认 in-scope**。

## 2. Program rules 强制清单

在测试任一 asset 前逐条对照：

- **no DoS / 无可用性影响** —— 禁止压力测试、资源耗尽、批量并发。
- **rate limit / automation limit** —— 低速串行；遵守 "no automated scanning" 条款。
- **no social engineering** —— 不针对人员、不钓鱼。
- **minimal impact / no PII exfil** —— 验证即止，不导出真实用户数据。
- 叠加于 VulnClaw 既有 `BLOCKED_PATTERNS` / `RESERVED_IP_RANGES` 之上。

## 3. HackerOne 提交格式报告模板

每个 finding 用如下结构：

```markdown
### [Title] <漏洞类型> on <asset>

**Asset:** <受影响的 in-scope asset（URL / 标识）>

**Severity (CVSS):** <Critical | High | Medium | Low> —
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (score: X.X)

**Steps to Reproduce:**
1. <步骤，含请求 / 响应 / payload>
2. ...

**Impact:**
<可利用性与业务影响>

**Remediation:**
<修复建议>

**Proof of Concept:**
（附可参数化的 Python PoC，requests 库；仅用于验证，无破坏性）
```

提醒：报告仅供用户在 HackerOne 上 **人工提交**，Skill 不自动上报。
