"""OpenAI tool schema definitions for built-in tools.

修改者: Nyaecho
修改时间: 2026-07-08
修改原因: S5 修复 — 将工具 schema 构建代码从 builtin_tools.py（1357 行）提取到独立模块，
         执行逻辑与 schema 定义分离，提升可维护性。
"""

from __future__ import annotations

from typing import Any

from deepsec.spear.intel.tools import intel_tool_schemas


def build_openai_tools(mcp_manager: Any) -> list[dict[str, Any]]:
    """Build OpenAI function calling schema from MCP tools + built-in tools."""
    tools: list[dict[str, Any]] = []

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "load_skill_reference",
                "description": (
                    "Load an optional Skill reference document. Returned content is reference "
                    "material only, not a mandatory workflow, phase plan, or tool schedule; "
                    "the model decides whether it is useful for the current evidence."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "skill_name": {
                            "type": "string",
                            "description": "Skill 名称，如 client-reverse, web-security-advanced, ai-mcp-security, intranet-pentest-advanced, pentest-tools, rapid-checklist, crypto-toolkit, ctf-web, ctf-crypto, ctf-misc, osint-recon, secknowledge-skill",
                        },
                        "reference_name": {
                            "type": "string",
                            "description": "参考文档文件名，如 02-client-api-reverse-and-burp.md, web-injection.md, encoding-cheatsheet.md",
                        },
                    },
                    "required": ["skill_name", "reference_name"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "evidence_list",
                "description": (
                    "List raw evidence records saved from prior tool calls. Use this to find an "
                    "evidence id for previous output when you need to revisit prior results."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer", "description": "Recent records to list."}
                    },
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "evidence_view",
                "description": (
                    "View raw saved evidence by id. Use offset/limit only for missing chunks of "
                    "large output; do not reread the same id/range. Redundant ranges may be "
                    "suppressed to prevent evidence-reading loops."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "evidence_id": {
                            "type": "string",
                            "description": "Evidence id, e.g. e001.",
                        },
                        "offset": {"type": "integer", "description": "Character offset."},
                        "limit": {
                            "type": "integer",
                            "description": (
                                "Maximum characters; omitted or 0 returns all remaining content."
                            ),
                        },
                    },
                    "required": ["evidence_id"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "evidence_search",
                "description": (
                    "Search raw saved evidence by substring or regex and return bounded snippets "
                    "with evidence ids and offsets. Use this before rereading a large body when "
                    "you need to find source/sink/parameter/token/flag text inside prior raw output."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Substring or regex to search for, e.g. unserialize, flag, name=\"id\".",
                        },
                        "evidence_id": {
                            "type": "string",
                            "description": "Optional evidence id to search inside, e.g. e004.",
                        },
                        "regex": {
                            "type": "boolean",
                            "description": "Interpret query as a regex. Default false.",
                        },
                        "context_chars": {
                            "type": "integer",
                            "description": "Characters of raw context around each match. Default 180.",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum matches to return. Default 12, capped internally.",
                        },
                    },
                    "required": ["query"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "source_extract",
                "description": (
                    "Normalize messy HTML/highlight_file/source evidence into readable text and "
                    "extract high-signal PHP/web surfaces such as forms, endpoints, unserialize, "
                    "magic methods, eval sinks, taint sources and filters. Use it when raw body "
                    "contains highlighted or noisy source code."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "evidence_id": {
                            "type": "string",
                            "description": "Evidence id to normalize, e.g. e004.",
                        },
                        "text": {
                            "type": "string",
                            "description": "Inline raw HTML/source text to normalize when no evidence id exists.",
                        },
                    },
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "runtime_diff_probe",
                "description": (
                    "Run a compact local parser/filter differential table. Use when evidence shows "
                    "a regex/string filter before a runtime parser/interpreter and you need to find "
                    "inputs accepted by the parser but missed by the filter. Supports generic regex "
                    "checks and PHP serialize/unserialize checks; this is local verification only."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "mode": {
                            "type": "string",
                            "description": "regex or php_serialize. Default regex.",
                        },
                        "filter_regex": {
                            "type": "string",
                            "description": "Observed filter regex, e.g. /[oc]:\\d+:/i.",
                        },
                        "payload": {
                            "type": "string",
                            "description": "Canonical payload to mutate and compare against the filter/parser.",
                        },
                        "candidates": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "label": {"type": "string"},
                                    "payload": {"type": "string"},
                                },
                            },
                            "description": "Optional explicit candidate payloads to test.",
                        },
                        "mutations": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "Optional mutation names. For php_serialize: signed_lengths, "
                                "leading_zero_lengths, lowercase_type, uppercase_string_type."
                            ),
                        },
                        "class_defs": {
                            "type": "string",
                            "description": (
                                "PHP class definitions for php_serialize mode, without <?php tags. "
                                "Use minimal local definitions needed to validate unserialize behavior."
                            ),
                        },
                        "target_runtime": {
                            "type": "string",
                            "description": (
                                "Optional target runtime/version observed from headers/source, e.g. "
                                "PHP/5.6.40. If omitted, VulnClaw tries to infer it from evidence."
                            ),
                        },
                        "timeout_ms": {
                            "type": "integer",
                            "description": "Local runtime timeout in milliseconds, default 10000.",
                        },
                        "max_output_chars": {
                            "type": "integer",
                            "description": (
                                "Optional command-level output cap before evidence storage; omitted "
                                "or 0 keeps raw output intact, while large active-context observations "
                                "may still be represented by a high-signal preview."
                            ),
                        },
                    },
                    "required": ["filter_regex"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "shell_command",
                "description": (
                    "Run a local shell command when local verification or exact request fidelity is "
                    "useful. Good uses include php -r serialization checks, curl requests with raw "
                    "cookies/headers, rg/Select-String over saved files, and small one-off scripts. "
                    "Set workdir when the command depends on files. Raw stdout/stderr are saved as "
                    "evidence; large active-context observations are bounded high-signal previews."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "Shell command to run."},
                        "workdir": {
                            "type": "string",
                            "description": "Working directory. Defaults to the VulnClaw process cwd.",
                        },
                        "timeout_ms": {
                            "type": "integer",
                            "description": "Command timeout in milliseconds, default 10000, capped at 120000.",
                        },
                        "shell": {
                            "type": "string",
                            "description": "Windows: powershell (default), pwsh, or cmd. Other OSes use the default shell.",
                        },
                        "max_output_chars": {
                            "type": "integer",
                            "description": (
                                "Optional command-level output cap before evidence storage; omitted "
                                "or 0 keeps raw output intact, while large active-context observations "
                                "may still be represented by a high-signal preview."
                            ),
                        },
                    },
                    "required": ["command"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "http_probe_batch",
                "description": (
                    "Batch HTTP probe tool for comparing URL/parameter/header/body variants "
                    "in one call. Returns status/length/hash/title/response headers/body signals, "
                    "audited request surfaces and raw response bodies saved as evidence. Large "
                    "active-context observations are high-signal previews. Supports "
                    "GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "base_url": {"type": "string"},
                        "requests": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "method": {
                                        "type": "string",
                                        "description": "GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS; default GET.",
                                    },
                                    "url": {"type": "string"},
                                    "raw_url": {"type": "string"},
                                    "params": {"type": "object"},
                                    "headers": {
                                        "type": "object",
                                        "description": (
                                            "Per-request headers. For exact Cookie payloads or values "
                                            "containing semicolons/quotes/braces, prefer headers.Cookie "
                                            "with the already-encoded raw value."
                                        ),
                                    },
                                    "cookies": {
                                        "type": "object",
                                        "description": (
                                            "Simple per-request cookies. Use headers.Cookie instead "
                                            "when cookie serialization/encoding must be exact."
                                        ),
                                    },
                                    "data": {},
                                    "json": {},
                                    "label": {"type": "string"},
                                },
                            },
                        },
                        "timeout": {"type": "number"},
                        "follow_redirects": {"type": "boolean"},
                        "verify_tls": {
                            "type": "boolean",
                            "description": "Verify TLS certificates; default false for CTF/lab compatibility.",
                        },
                        "max_body_chars": {"type": "integer"},
                    },
                    "required": ["requests"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "python_execute",
                "description": (
                    "执行 Python 代码片段。用于：构造复杂 HTTP 请求并解析响应、"
                    "做编码转换和数据处理、批量测试不同 payload、比较响应差异、"
                    "执行数学计算等。代码在受限环境中执行，超时 30 秒。"
                    "预装库：requests, beautifulsoup4, pycryptodome, base64, json, re 等。"
                    "普通 HTTP/HTTPS 请求优先使用 fetch 或 http_probe_batch，避免用 Python 手写请求浪费上下文；"
                    "只有需要复杂解析、生成 payload 或批量逻辑时再使用此工具。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "要执行的 Python 代码。支持多行，可 import 标准库和 requests/bs4 等。",
                        },
                        "purpose": {
                            "type": "string",
                            "description": "简要说明执行目的（用于审计日志），如'构造HTTP请求测试弱比较绕过'",
                        },
                    },
                    "required": ["code"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "crypto_decode",
                "description": (
                    "编码解码与加解密工具。遇到 base64/hex/URL/HTML/Unicode 编码字符串、"
                    "需要计算哈希、解密 AES/DES、解析 JWT 等场景时调用此工具。"
                    "重要：不要自行脑补解码结果，始终使用此工具确保准确性。"
                    "支持操作：base64_encode/decode, base32_encode/decode, base58_encode/decode, "
                    "hex_encode/decode, url_encode/decode, html_encode/decode, unicode_encode/decode, "
                    "rot13_encode/decode, caesar_encode/decode, morse_encode/decode, "
                    "md5_hash, sha1_hash, sha256_hash, sha512_hash, "
                    "aes_encrypt/decrypt, jwt_decode/encode, auto_decode"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "operation": {"type": "string", "description": "操作名称"},
                        "input": {
                            "type": "string",
                            "description": "待处理的输入字符串（待编码/解码/哈希/加密的文本）",
                        },
                        "key": {
                            "type": "string",
                            "description": "加密/解密密钥（AES/DES 需要，16/24/32字节）",
                        },
                        "iv": {"type": "string", "description": "AES 初始化向量（16字节，可选）"},
                        "shift": {
                            "type": "integer",
                            "description": "Caesar 密码位移量（默认3，解码时不提供则暴力所有位移）",
                        },
                        "secret": {"type": "string", "description": "JWT 签名密钥"},
                    },
                    "required": ["operation", "input"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "nmap_scan",
                "description": (
                    "nmap 网络端口扫描工具。适合在端口、服务版本或网络暴露面会影响下一步判断时使用。\n"
                    "用法示例：\n"
                    "  扫描常见端口: scan_type=top_ports, target=1.2.3.4\n"
                    "  SYN扫描: scan_type=syn, target=1.2.3.4（需要管理员权限）\n"
                    "  服务版本检测: scan_type=service, target=1.2.3.4\n"
                    "  漏洞扫描: scan_type=vuln, target=1.2.3.4\n"
                    "  全量扫描: scan_type=full, target=1.2.3.4\n"
                    "如果只需验证一个具体 HTTP/Web 行为，可以选择其他更轻量工具。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "目标 IP 地址或域名（必填），如 192.168.1.1 或 scanme.nmap.org",
                        },
                        "scan_type": {
                            "type": "string",
                            "description": "扫描类型：top_ports/syn/tcp/service/os/vuln/full",
                        },
                        "ports": {
                            "type": "string",
                            "description": "指定端口或范围（可选），如 80,443,8080 或 1-1000",
                        },
                        "timing": {
                            "type": "integer",
                            "description": "扫描速度模板 0-5（默认4），数字越大越快但越容易被检测",
                        },
                        "profile": {
                            "type": "string",
                            "description": "可选网络扫描画像：adaptive/fast/thorough/stealth。画像会联动调整端口、速度、服务探测与安全脚本。",
                        },
                    },
                    "required": ["target"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "brute_force_login",
                "description": (
                    "对登录表单进行密码爆破。自动管理 Session Cookie、"
                    "自动提取和更新 CSRF Token、判断登录成功/失败。"
                    "单次调用内完成所有密码尝试，返回每个密码的结果。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "登录页面 URL",
                        },
                        "username_field": {
                            "type": "string",
                            "description": "用户名字段名，如 'username'",
                        },
                        "password_field": {
                            "type": "string",
                            "description": "密码字段名，如 'password'",
                        },
                        "csrf_field": {
                            "type": "string",
                            "description": "CSRF token 字段名，如 'user_token'",
                        },
                        "username": {
                            "type": "string",
                            "description": "要爆破的用户名",
                        },
                        "passwords": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "要尝试的密码列表（最多 20 个）",
                        },
                        "success_keyword": {
                            "type": "string",
                            "description": "登录成功后页面出现的特征词，如 'Welcome'、'Dashboard'",
                        },
                        "failure_keyword": {
                            "type": "string",
                            "description": "登录失败后页面出现的特征词，如 'Login failed'",
                        },
                        "submit_action": {
                            "type": "string",
                            "description": "表单提交的目标 URL（可选，不指定则从表单 action 属性提取）",
                        },
                        "extra_data": {
                            "type": "object",
                            "description": "额外表单字段，如 {\"Login\": \"Login\"}",
                        },
                    },
                    "required": ["url", "password_field", "passwords"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "space_search",
                "description": (
                    "空间测绘资产搜索（FOFA/Hunter/Quake/Shodan/ZoomEye/0.zone 零零信安）。"
                    "可在需要被动发现目标资产、IP、端口、子域、标题或组件指纹时使用，不直接接触目标。"
                    "给 domain 自动按各引擎语法构造 domain 查询；也可传完整 query 语法。"
                    "engine=all 时并发查询所有已配置 key 的引擎。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "engine": {
                            "type": "string",
                            "description": "fofa/hunter/quake/shodan/zoomeye/zerozone/all，默认 fofa",
                        },
                        "query": {
                            "type": "string",
                            "description": "引擎原生查询语法，如 'domain=\"x.com\"'、'app=\"Struts2\"'（可选）",
                        },
                        "domain": {
                            "type": "string",
                            "description": "目标主域名，自动构造各引擎 domain 查询（query 未给时使用）",
                        },
                        "size": {"type": "integer", "description": "返回条数，默认 100"},
                    },
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "subdomain_enum",
                "description": (
                    "子域名枚举。先用已配置的空间测绘引擎被动聚合，再用内置小字典做 DNS 解析爆破，"
                    "返回去重后的存活子域名列表；是否需要枚举由模型根据当前任务判断。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "主域名，如 nju.edu.cn"},
                        "brute": {
                            "type": "boolean",
                            "description": "是否启用内置字典 DNS 爆破（默认 true）",
                        },
                    },
                    "required": ["domain"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "js_recon",
                "description": (
                    "JS 信息收集（参考 URLFinder）。抓取目标页面及其引用的全部 .js 文件，"
                    "提取 API 接口/路径、关联域名、绝对 URL，以及疑似硬编码密钥（AK/SK、token、JWT、私钥等）。"
                    "默认 auto_probe=true：自动对收集到的同源接口逐个做未授权访问探测（仅安全 GET，跳过破坏性接口）。"
                    "适合在页面脚本可能包含端点、路径或硬编码线索时按需调用。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "目标页面 URL"},
                        "max_js": {
                            "type": "integer",
                            "description": "最多抓取的 JS 文件数（默认 30）",
                        },
                        "auto_probe": {
                            "type": "boolean",
                            "description": "是否自动对收集到的接口做未授权探测（默认 true）",
                        },
                        "auth_header": {
                            "type": "string",
                            "description": "可选鉴权头做差分对比，如 'Authorization: Bearer xxx'，验证无 token 是否也能拿到数据",
                        },
                    },
                    "required": ["url"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "unauth_test",
                "description": (
                    "未授权访问探测。对一批接口（通常来自 js_recon 收集的端点）逐个无凭据请求，"
                    "按状态码/响应体/内容类型判定：⚠疑似未授权(返回数据) / ✓已鉴权拦截 / ↪跳转登录 / —不存在。"
                    "提供 auth_header 时做有/无 token 差分对比，无 token 也能拿到同样数据则判定 🔴未授权确认。"
                    "严守读写分离：仅发安全 GET，自动跳过 delete/update/sms 等破坏性接口，不批量遍历 ID。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "base_url": {"type": "string", "description": "目标基础 URL（确定同源范围）"},
                        "endpoints": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "待测接口路径/URL 列表（来自 js_recon 的接口/路径）",
                        },
                        "auth_header": {
                            "type": "string",
                            "description": "可选鉴权头做差分，如 'Authorization: Bearer xxx' 或 'Cookie: session=...'",
                        },
                        "max_endpoints": {
                            "type": "integer",
                            "description": "最多探测的接口数（默认 60）",
                        },
                    },
                    "required": ["base_url", "endpoints"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "dir_enum",
                "description": (
                    "目录/文件枚举（参考 dirsearch）。并发字典爆破，自带 404 基线与全局伪装响应识别"
                    "（随机路径返回 200 即判定伪装并停止）、状态码与响应长度过滤。"
                    "仅做安全的 GET 探测，不碰 delete/update 等破坏性路径。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "目标基础 URL，如 https://x.com/"},
                        "extensions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "扩展名展开，如 ['php','jsp','bak','zip']（可选）",
                        },
                        "wordlist": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "追加的自定义路径（基于命名规律的启发式字典，可选）",
                        },
                    },
                    "required": ["url"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "vault_status",
                "description": (
                    "Show the conversation vault status: active archive blocks, restored blocks, "
                    "messages archived and approximate chars saved. Use before archiving so you "
                    "know which ranges are already covered."
                ),
                "parameters": {"type": "object", "properties": {}},
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "vault_archive",
                "description": (
                    "Archive an older message range (by vault refs like <v#00042>..<v#00057>) into a "
                    "compact pointer (tier 1), a distilled summary (tier 2, default), or the global "
                    "digest (tier 3). The full original text is persisted to disk and can be restored "
                    "with vault_restore or searched with vault_search. The recent tail and the last "
                    "user message are protected and require force=true to override."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "start": {"type": "string", "description": "Start vault ref, e.g. <v#00042>"},
                        "end": {"type": "string", "description": "End vault ref, e.g. <v#00057>"},
                        "tier": {
                            "type": "integer",
                            "description": "1 = pointer, 2 = distilled summary (default), 3 = digest",
                        },
                        "topic": {"type": "string", "description": "Short label for the range"},
                        "summary": {
                            "type": "string",
                            "description": "Optional distilled summary text (tier 2)",
                        },
                        "force": {
                            "type": "boolean",
                            "description": "Override protected-tail / phantom-range guards",
                        },
                    },
                    "required": ["start", "end"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "vault_restore",
                "description": (
                    "Mark an archived range as restored so its messages become archivable again "
                    "(the original text lives on disk / in the hot ring)."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "start": {"type": "string", "description": "Start vault ref"},
                        "end": {"type": "string", "description": "End vault ref"},
                    },
                    "required": ["start", "end"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "vault_search",
                "description": (
                    "Search archived vault blocks by keyword. Returns bounded snippets from block "
                    "topics/summaries without decompressing anything into the model window."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Keyword to search"},
                        "limit": {"type": "integer", "description": "Max hits (default 8)"},
                    },
                    "required": ["query"],
                },
            },
        }
    )

    tools.extend(intel_tool_schemas())

    if mcp_manager:
        for schema in mcp_manager.get_tool_schemas():
            tools.append(
                {
                    "type": "function",
                    "function": {
                        "name": schema.get("name", ""),
                        "description": schema.get("description", ""),
                        "parameters": schema.get(
                            "inputSchema", {"type": "object", "properties": {}}
                        ),
                    },
                }
            )

    return tools
