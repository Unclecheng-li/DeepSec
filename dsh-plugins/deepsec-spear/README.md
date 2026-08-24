# dsh-deepsec-spear

DeepSec Spear 授权渗透测试插件，为 [DeepSeek Harness（dsh）](https://github.com/deepseek-ai/deepseek-harness) 提供签名授权作用域下的渗透测试工具。

English summary: a dsh plugin exposing DeepSec Spear's *authorized* penetration-testing workflow (scope signing/verification, reconnaissance, agent-driven assessments) as agent tools. The signed-scope authorization gate is enforced by the underlying CLI and deliberately not bypassable from the plugin.

## ⚠️ 授权边界（先读这个）

- 本插件**只用于已获书面/签名授权的测试**（渗透测试委托、CTF、自有系统安全评估）。
- `deepsec_spear_run` / `deepsec_spear_recon` 强制要求 `authorized` 参数指向**已签名**的 scope manifest；DeepSec CLI 会校验签名、时间窗口、目标成员关系，拒绝私网/保留地址，并把每次运行写入 `~/.deepsec/runs/` 审计日志。插件层不提供任何绕过手段。
- 签名密钥 `DEEPSEC_SCOPE_SIGNING_KEY` 必须由授权方通过安全渠道提供，**模型/插件不得自行生成或猜测**。
- 角色选择（pentester / redteam / ctf_player…）只影响工具目录和预算，不会放宽授权校验。

## 提供的工具

| 工具 | 对应 CLI | 说明 |
|------|----------|------|
| `deepsec_scope_sign` | `deepsec scope sign` | 用 `DEEPSEC_SCOPE_SIGNING_KEY` 原地签名 scope manifest |
| `deepsec_scope_verify` | `deepsec scope verify` | 校验结构、时间窗口状态、签名匹配（发命令前先验证授权可用性） |
| `deepsec_spear_recon` | `deepsec spear recon` | 仅侦察（不利用），需已签名作用域 |
| `deepsec_spear_run` | `deepsec spear run` | 完整评估：侦察→发现→带 Agent 推理的验证利用；`scope`（full/web/api/mobile）与 `mode`（quick/standard/deep）可调 |
| `deepsec_spear_catalog` | `deepsec spear roles` + `spear tools` | 只读查看角色与外部工具目录（nmap、nuclei、httpx…） |

## scope manifest 示例

```json
{
  "version": 1,
  "targets": ["https://assessment.example.com/api"],
  "valid_from": "2026-08-24T09:00:00+08:00",
  "valid_until": "2026-08-24T18:00:00+08:00",
  "prohibited_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"],
  "signer": "security-team",
  "signature_algorithm": "hmac-sha256"
}
```

典型流程：授权方提供 `scope.json` 与签名密钥 → `deepsec_scope_sign` → `deepsec_scope_verify` → `deepsec_spear_recon` → `deepsec_spear_run` → 检查 `~/.deepsec/runs/<id>/audit.log`。

## 前置条件

- Node.js ≥ 20、DeepSec CLI 可执行（同 [dsh-deepsec-shield](../deepsec-shield/README.md)）。
- `DEEPSEC_SCOPE_SIGNING_KEY` 环境变量（签名/验签时）。
- Spear 的 LLM 推理使用 `~/.deepsec/config.toml` 中 `[llm.spear]` 配置的模型（默认 DeepSeek）。

## 安装

```bash
dsh plugin --profile <profile> add <repo>/dsh-plugins/deepsec-spear
dsh --profile <profile> --dump-config   # 验证插件层
```

## 配置

```yaml
- id: deepsec-spear
  config:
    command: deepsec
    timeoutMs: 3600000    # 完整评估可能耗时很长；0 = 不限时
    maxOutputChars: 60000 # 捕获输出上限，完整工件在 ~/.deepsec/runs/
```

## Model experience

- 先 `deepsec_scope_verify` 确认授权有效，再发起 recon/run；授权失败会以 `ok: false` + stderr 中的 scope 错误返回，应如实上报而不是重试绕过。
- 长任务遵守取消信号；被取消时返回 `cancelled` 结果。

## Known limitations

- 依赖外部 `deepsec` CLI 与其 LLM 配置；CLI 缺失时返回带安装指引的错误。
- 交互式工作台（`deepsec chat` / TUI）不适合子进程封装，未纳入工具。
- dsh 处于 developer preview，工具契约可能随版本演进。
