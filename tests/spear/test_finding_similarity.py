"""VulnClaw Finding Similarity Tests — semantic deduplication module."""

from __future__ import annotations

from deepsec.spear.agent.context import VulnerabilityFinding
from deepsec.spear.agent.finding_similarity import (
    deduplicate_findings,
    finding_similarity,
    normalize_text,
    normalize_vuln_type,
    text_similarity,
    url_similarity,
)

# ── normalize_text ───────────────────────────────────────────────────


class TestNormalizeText:
    def test_lowercase_and_whitespace(self):
        assert normalize_text("  SQL   Injection  ") == "sql injection"

    def test_empty(self):
        assert normalize_text("") == ""

    def test_url_path_standardized(self):
        # 末尾斜杠去除，scheme/host 归一
        out = normalize_text("Found at https://Example.com/api/user/")
        assert "example.com/api/user" in out
        assert "https://" not in out

    def test_noise_tags_removed(self):
        out = normalize_text("[自动] SQL注入 [已确认]")
        assert "[自动]" not in out
        assert "[已确认]" not in out


# ── text_similarity ──────────────────────────────────────────────────


class TestTextSimilarity:
    def test_identical(self):
        assert text_similarity("sql injection in login", "sql injection in login") == 1.0

    def test_both_empty(self):
        assert text_similarity("", "") == 1.0

    def test_one_empty(self):
        assert text_similarity("", "sql injection") == 0.0

    def test_disjoint(self):
        assert text_similarity("apple banana", "carrot potato") == 0.0

    def test_partial_overlap(self):
        # {sql, injection, login} vs {sql, injection, search}
        # 交集 2 / 并集 4 = 0.5
        sim = text_similarity("sql injection login", "sql injection search")
        assert abs(sim - 0.5) < 1e-9

    def test_case_insensitive(self):
        assert text_similarity("SQL Injection", "sql injection") == 1.0


# ── url_similarity ───────────────────────────────────────────────────


class TestUrlSimilarity:
    def test_identical_url(self):
        u = "https://t.com/api/user?id=1"
        assert url_similarity(u, u) == 1.0

    def test_same_path_different_query_value(self):
        # 相同 host/path/参数名，仅参数值不同 — 应判定为同一接口（=1.0）
        a = "https://t.com/api/user?id=1"
        b = "https://t.com/api/user?id=999"
        assert url_similarity(a, b) == 1.0

    def test_same_path_different_query_keys(self):
        # host 同 + path 同 + 参数名不同(0) => 0.3 + 0.4 + 0 = 0.7
        a = "https://t.com/api/user?id=1"
        b = "https://t.com/api/user?name=bob"
        assert abs(url_similarity(a, b) - 0.7) < 1e-9

    def test_different_host(self):
        # host 不同(0) + path 同 + 无参数(1) => 0 + 0.4 + 0.3 = 0.7
        a = "https://a.com/api/user"
        b = "https://b.com/api/user"
        assert abs(url_similarity(a, b) - 0.7) < 1e-9

    def test_one_empty(self):
        assert url_similarity("", "https://t.com/x") == 0.0

    def test_non_url_fallback_to_text(self):
        # 非 URL 回退到文本相似度
        assert url_similarity("admin panel", "admin panel") == 1.0


# ── normalize_vuln_type ──────────────────────────────────────────────


class TestNormalizeVulnType:
    def test_sqli_aliases(self):
        assert normalize_vuln_type("sqli") == "sql_injection"
        assert normalize_vuln_type("SQL注入") == "sql_injection"
        assert normalize_vuln_type("SQL Injection") == "sql_injection"
        assert normalize_vuln_type("blind sqli") == "sql_injection"

    def test_xss_aliases(self):
        assert normalize_vuln_type("xss") == "cross_site_scripting"
        assert normalize_vuln_type("跨站脚本") == "cross_site_scripting"

    def test_ssrf(self):
        assert normalize_vuln_type("ssrf") == "server_side_request_forgery"
        assert normalize_vuln_type("服务端请求伪造") == "server_side_request_forgery"

    def test_rce(self):
        assert normalize_vuln_type("rce") == "remote_code_execution"
        assert normalize_vuln_type("命令执行") == "remote_code_execution"

    def test_lfi(self):
        assert normalize_vuln_type("lfi") == "local_file_inclusion"
        assert normalize_vuln_type("文件包含") == "local_file_inclusion"

    def test_idor(self):
        assert normalize_vuln_type("idor") == "insecure_direct_object_reference"
        assert normalize_vuln_type("越权") == "insecure_direct_object_reference"

    def test_unknown_falls_back(self):
        assert normalize_vuln_type("Weird Custom Type") == "weird_custom_type"

    def test_empty(self):
        assert normalize_vuln_type("") == ""


# ── finding_similarity ───────────────────────────────────────────────


def _mk(title, vuln_type="", description="", evidence="", **kw):
    return VulnerabilityFinding(
        title=title,
        vuln_type=vuln_type,
        description=description,
        evidence=evidence,
        severity=kw.pop("severity", "Medium"),
        **kw,
    )


class TestFindingSimilarity:
    def test_same_vuln_different_wording(self):
        a = _mk(
            "SQL Injection in login",
            vuln_type="SQLi",
            description="login form vulnerable at https://t.com/api/login?u=1",
        )
        b = _mk(
            "登录处 SQL 注入",
            vuln_type="SQL注入",
            description="https://t.com/api/login?u=2 注入漏洞",
        )
        # 类型归一化匹配 0.8*0.3 + URL 同接口 1.0*0.4 + 描述部分重叠
        assert finding_similarity(a, b) >= 0.6

    def test_different_vuln_types_low(self):
        a = _mk("SQLi", vuln_type="SQLi", description="https://t.com/api/login")
        b = _mk("XSS", vuln_type="XSS", description="https://other.com/search?q=x")
        assert finding_similarity(a, b) < 0.5

    def test_identical_findings(self):
        a = _mk(
            "SQLi at /api/x",
            vuln_type="SQLi",
            description="vuln",
            evidence="https://t.com/api/x?id=1",
        )
        b = _mk(
            "SQLi at /api/x",
            vuln_type="SQLi",
            description="vuln",
            evidence="https://t.com/api/x?id=1",
        )
        assert finding_similarity(a, b) >= 0.95


# ── deduplicate_findings ─────────────────────────────────────────────


class TestDeduplicateFindings:
    def test_merges_same_vuln_different_wording(self):
        findings = [
            _mk(
                "SQL Injection in login",
                vuln_type="SQLi",
                description="https://t.com/api/login?u=1 vulnerable",
            ),
            _mk(
                "登录处 SQL 注入",
                vuln_type="SQL注入",
                description="https://t.com/api/login?u=2 注入",
            ),
        ]
        result = deduplicate_findings(findings, threshold=0.6)
        assert len(result) == 1

    def test_keeps_distinct_vulns(self):
        findings = [
            _mk("SQLi", vuln_type="SQLi", description="https://t.com/api/login"),
            _mk("XSS", vuln_type="XSS", description="https://other.com/search?q=1"),
            _mk("SSRF", vuln_type="SSRF", description="https://t.com/api/fetch?url=x"),
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 3

    def test_keeps_stronger_evidence(self):
        weak = _mk("SQLi candidate", vuln_type="SQLi", description="https://t.com/api/x?id=1")
        weak.lifecycle_status = "candidate"
        weak.evidence_level = "L1"

        strong = _mk(
            "SQLi confirmed",
            vuln_type="sql injection",
            description="https://t.com/api/x?id=2",
            evidence="SLEEP(5) delay confirmed, full PoC",
        )
        strong.verified = True
        strong.verification_status = "verified"
        strong.lifecycle_status = "verified"
        strong.evidence_level = "L4"

        result = deduplicate_findings([weak, strong], threshold=0.6)
        assert len(result) == 1
        assert result[0].verified is True
        assert result[0].evidence_level == "L4"

    def test_empty_list(self):
        assert deduplicate_findings([]) == []


# ── SessionState integration ─────────────────────────────────────────


class TestSessionStateIntegration:
    def test_semantic_dedup_on_add(self):
        from deepsec.spear.agent.context import SessionState

        state = SessionState(target="t.com")
        f1 = _mk(
            "SQL Injection in login",
            vuln_type="SQLi",
            description="https://t.com/api/login?u=1 vulnerable",
        )
        f2 = _mk(
            "登录处 SQL 注入",
            vuln_type="SQL注入",
            description="https://t.com/api/login?u=2 注入",
        )
        state.semantic_dedup_threshold = 0.6
        assert state.add_finding(f1) is True
        # 语义重复，应被拒绝（返回 False），findings 仍只有 1 个
        assert state.add_finding(f2) is False
        assert len(state.findings) == 1

    def test_distinct_findings_both_added(self):
        from deepsec.spear.agent.context import SessionState

        state = SessionState(target="t.com")
        assert state.add_finding(
            _mk("SQLi", vuln_type="SQLi", description="https://t.com/api/login")
        ) is True
        assert state.add_finding(
            _mk("XSS", vuln_type="XSS", description="https://o.com/search?q=1")
        ) is True
        assert len(state.findings) == 2
