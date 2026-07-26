"""VulnClaw Knowledge Updater — update and seed the knowledge base."""

from __future__ import annotations

from deepsec.kb.store import KnowledgeStore


def seed_knowledge_base(store: KnowledgeStore) -> None:
    """Seed the knowledge base with initial data.

    This populates the KB with essential security knowledge for MVP.
    """
    # ── CVE Entries ──────────────────────────────────────────────

    cves = [
        {
            "id": "CVE-2026-21858",
            "title": "n8n Arbitrary File Read via Public Form",
            "description": "n8n versions >= 1.65.0 and < 1.121.0 allow unauthenticated "
            "arbitrary file read through public form submission endpoints when "
            "a workflow contains a Form Ending node returning a binary file.",
            "severity": "Critical",
            "affected": "n8n >= 1.65.0, < 1.121.0",
            "tags": ["n8n", "file-read", "rce", "critical"],
            "exploitation_steps": [
                "Identify a public form path on the n8n instance",
                "Send POST request with forged files object containing filepath",
                "Read server files including /etc/passwd, config, database",
                "Extract encryption key from config",
                "Use extracted credentials to login",
                "Create malicious workflow with expression injection for RCE",
            ],
            "remediation": "Upgrade to n8n >= 1.121.0",
        },
        {
            "id": "CVE-2025-68613",
            "title": "n8n Authenticated Expression Injection RCE",
            "description": "Authenticated expression injection in n8n allows RCE via "
            "malicious workflow expressions.",
            "severity": "Critical",
            "affected": "n8n >= 0.211.0, < 1.120.4",
            "tags": ["n8n", "rce", "expression-injection", "critical"],
            "exploitation_steps": [
                "Login with valid credentials",
                "Create a workflow with manualTrigger + set node",
                "Insert expression payload: ={{ (function(){...execSync(cmd)...})() }}",
                "Run the workflow",
                "Read execution result for command output",
            ],
            "remediation": "Upgrade to n8n >= 1.120.4 or 1.121.1",
        },
    ]

    for cve in cves:
        existing = store.get_entry("cve", cve["id"])
        if not existing:
            store.add_entry("cve", cve["id"], cve)

    # ── Technique Entries ────────────────────────────────────────

    techniques = [
        {
            "id": "sqli-bypass",
            "title": "SQL 注入绕过技巧",
            "description": "绕过 WAF 的 SQL 注入 payload 构造方法",
            "tags": ["sqli", "waf-bypass", "web"],
            "bypass_methods": [
                "大小写混合: SeLeCt",
                "内联注释: S/*!ELECT*/",
                "双重编码: %2565",
                "等价函数: GROUP_CONCAT 替代 concat_ws",
            ],
        },
        {
            "id": "sqli-one-pass-playbook",
            "title": "SQL 注入一命通关实战速查",
            "description": "基于 fushuling 公开文章二次整理的 SQL 注入手工验证、sqlmap 加速、tamper/WAF 绕过与证据记录流程。",
            "source": {
                "title": "SQL注入一命通关!",
                "url": "https://fushuling.com/index.php/2023/04/07/sql%E6%B3%A8%E5%85%A5%E4%B8%80%E5%91%BD%E9%80%9A%E5%85%B3/",
                "published": "2023-04-07",
            },
            "tags": [
                "sqli",
                "sqlmap",
                "tamper",
                "waf-bypass",
                "ctf-web",
                "evidence",
            ],
            "workflow": [
                "先定位真实输入面：HTML 表单、GET/POST 参数、XHR/API、Cookie 或 HTTP 头。",
                "建立 baseline，再用 true/false、报错、延迟或 union 回显验证是否进入 SQL 语义层。",
                "联合查询按列数、回显位、库名、表名、列名、数据推进；无回显时切换布尔/时间盲注。",
                "过滤明显时按被拦截 token 选择最小绕过：空白、注释、编码、比较符、关键字形态或自定义 tamper。",
                "手工确认参数和响应差异后，再使用 sqlmap 加速枚举或数据提取。",
            ],
            "tool_guidance": [
                "单次请求用 fetch。",
                "payload 批量对比用 http_probe_batch。",
                "盲注循环、复杂编码或响应解析再用 python_execute。",
                "发现明确表单或 id 参数时优先测试该入口，不要先做无意义目录扫描。",
            ],
            "evidence_required": [
                "URL、HTTP 方法、参数名、baseline 响应摘要。",
                "true/false、error/time 或 union 回显差异。",
                "状态码、长度、hash、关键 body 片段或响应时间。",
                "最终 flag/敏感数据必须逐字来自工具输出。",
            ],
            "reference_file": "vulnclaw/skills/specialized/secknowledge-skill/references/web-sqli-fushuling-one-pass.md",
        },
        {
            "id": "rce-bypass-php",
            "title": "PHP 命令执行绕过技巧",
            "description": "绕过 PHP WAF 的命令执行 payload 构造",
            "tags": ["rce", "waf-bypass", "php", "web"],
            "bypass_methods": [
                "Base64编码函数名: $f=base64_decode('c3lzdGVt');$f('id');",
                "字符串拼接: $f='sys'.'tem';$f('id');",
                "拆分路径: '/va'.'r/ww'.'w/ht'.'ml'",
                "反转字符串: $f=strrev('metsys');$f('id');",
            ],
        },
        {
            "id": "xss-bypass",
            "title": "XSS 绕过技巧",
            "description": "绕过 WAF/XSS 过滤器的 payload 构造",
            "tags": ["xss", "waf-bypass", "web"],
            "bypass_methods": [
                "事件处理器: <img src=x onerror=alert(1)>",
                "SVG 标签: <svg onload=alert(1)>",
                "HTML实体编码",
                "Unicode 编码",
            ],
        },
        {
            "id": "cmd-injection-bypass",
            "title": "命令注入绕过技巧",
            "description": "绕过命令注入过滤的方法",
            "tags": ["command-injection", "waf-bypass", "web"],
            "bypass_methods": [
                "换行符: id\\nwhoami",
                "管道符: id|whoami",
                "变量拼接: a=i;b=d;$a$b",
                "通配符: /bin/ca? /etc/pas?d",
            ],
        },
    ]

    for tech in techniques:
        existing = store.get_entry("techniques", tech["id"])
        if not existing:
            store.add_entry("techniques", tech["id"], tech)

    # ── Tool Guides ──────────────────────────────────────────────

    tools = [
        {
            "id": "nmap",
            "title": "Nmap 端口扫描速查",
            "description": "Nmap 常用扫描命令和参数",
            "tags": ["nmap", "recon", "scanning"],
            "commands": [
                "nmap -sV -sC -p- TARGET    # 全端口扫描+版本探测",
                "nmap -sS -TOP_PORTS 1000 TARGET   # SYN扫描Top1000端口",
                "nmap --script vuln TARGET   # 漏洞扫描脚本",
                "nmap -sU -TOP_PORTS 100 TARGET     # UDP扫描",
            ],
        },
        {
            "id": "burp",
            "title": "Burp Suite 工作流",
            "description": "Burp Suite 渗透测试工作流",
            "tags": ["burp", "proxy", "web"],
            "workflow": [
                "配置浏览器代理 → Burp",
                "浏览目标站点，收集请求",
                "分析请求中的参数和端点",
                "使用 Intruder 进行模糊测试",
                "使用 Repeater 手动验证漏洞",
            ],
        },
    ]

    for tool in tools:
        existing = store.get_entry("tools", tool["id"])
        if not existing:
            store.add_entry("tools", tool["id"], tool)
