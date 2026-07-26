"""Tests for the deterministic skill resolver (PRD #42).

Table-driven, not prompt snapshots: catalog validation, explicit routing,
positive/conflict/negative examples, bundle budget, prompt integration, and
skill-provenance auditability.
"""

import pytest

from deepsec.spear.skills.resolver import (
    SkillProfile,
    SkillQuery,
    SkillResolver,
    build_catalog,
)
from deepsec.spear.skills.routing import SkillRouting, normalize_token


@pytest.fixture(scope="module")
def catalog():
    return build_catalog()


@pytest.fixture(scope="module")
def resolver(catalog):
    return SkillResolver(catalog)


# ── Routing schema ───────────────────────────────────────────────────


class TestSkillRouting:
    def test_normalization_maps_free_text_to_canonical(self):
        assert normalize_token("SQL Injection") == "sqli"
        assert normalize_token("sql注入") == "sqli"
        assert normalize_token("Node.js") == "nodejs"
        assert normalize_token("post-exploitation") == "post_exploitation"

    def test_valid_routing_has_no_warnings(self):
        r = SkillRouting.model_validate(
            {
                "target_types": ["Web", "api"],
                "vulnerability_classes": ["SQL Injection", "xss"],
                "phases": ["vuln-discovery"],
            }
        )
        assert r.warnings == []
        assert "sqli" in r.vulnerability_classes
        assert "web" in r.target_types
        assert "vuln_discovery" in r.phases

    def test_unknown_enum_token_warns_not_raises(self):
        r = SkillRouting.model_validate({"vulnerability_classes": ["not_a_real_class"]})
        assert r.vulnerability_classes == []
        assert any("unknown token" in w for w in r.warnings)

    def test_unknown_role_falls_back_to_primary(self):
        r = SkillRouting.model_validate({"role": "captain"})
        assert r.role == "primary"
        assert any("role" in w for w in r.warnings)

    def test_empty_routing_is_empty(self):
        assert SkillRouting().is_empty()


# ── Catalog validation ───────────────────────────────────────────────


class TestCatalog:
    def test_every_skill_becomes_a_profile(self, catalog):
        assert len(catalog) >= 20
        for name, profile in catalog.items():
            assert isinstance(profile, SkillProfile)
            assert profile.name == name

    def test_no_shipped_skill_has_routing_warnings(self, catalog):
        """Unknown enum tokens in shipped frontmatter fail CI."""
        offenders = {n: p.routing.warnings for n, p in catalog.items() if p.routing.warnings}
        assert offenders == {}, f"routing warnings: {offenders}"

    def test_legacy_skills_without_routing_still_load(self, catalog):
        # A skill with no routing block validates into an empty SkillRouting.
        crypto = catalog.get("crypto-toolkit")
        assert crypto is not None
        assert crypto.routing.is_empty()

    def test_known_skills_have_typed_routing(self, catalog):
        assert "web" in catalog["web-security-advanced"].routing.target_types
        assert "sqli" in catalog["web-security-advanced"].routing.vulnerability_classes
        assert catalog["secknowledge-skill"].routing.broad is True
        assert catalog["pentest-flow"].routing.role == "fallback"


# ── Explicit invocation ──────────────────────────────────────────────


class TestExplicit:
    def test_use_vulnclaw_skill_phrase_wins(self, resolver):
        s = resolver.resolve(SkillQuery.from_input("Use VulnClaw skill ctf-web to solve this"))
        assert s.primary == "ctf-web"
        assert s.confidence == 1.0

    def test_slash_command_wins(self, resolver):
        # /ctf-crypto should win even though the text screams web/sqli.
        s = resolver.resolve(SkillQuery.from_input("/ctf-crypto sql注入 xss rce 测试"))
        assert s.primary == "ctf-crypto"

    def test_explicit_unknown_skill_ignored(self, resolver):
        s = resolver.resolve(SkillQuery.from_input("/not-a-skill sql注入 测试"))
        assert s.primary == "web-security-advanced"


# ── Positive examples (typed metadata) ──────────────────────────────

POSITIVE_CASES = [
    ("web injection", dict(target_type="web", vuln_hints=["sqli", "xss"]), "web-security-advanced"),
    ("ctf web", dict(target_type="ctf", task_types=["ctf"], vuln_hints=["ssti"]), "ctf-web"),
    ("ai/mcp", dict(target_type="ai_agent", vuln_hints=["prompt_injection"]), "ai-mcp-security"),
    ("client reverse", dict(target_type="client", task_types=["reverse"]), "client-reverse"),
    ("android", dict(target_type="android", task_types=["pentest"]), "android-pentest"),
    (
        "intranet",
        dict(target_type="intranet", vuln_hints=["lateral_movement"], phase="post_exploitation"),
        "intranet-pentest-advanced",
    ),
    ("crypto ctf", dict(target_type="crypto", task_types=["crypto"]), "ctf-crypto"),
    ("cve triage", dict(task_types=["triage"], phase="vuln_discovery"), "cve-triage"),
    ("osint", dict(task_types=["osint"], phase="recon"), "osint-recon"),
    ("reporting", dict(task_types=["report"], phase="reporting"), "reporting"),
]


class TestPositive:
    @pytest.mark.parametrize("label,fields,expected", POSITIVE_CASES, ids=[c[0] for c in POSITIVE_CASES])
    def test_expected_primary(self, resolver, label, fields, expected):
        s = resolver.resolve(SkillQuery(text=label, **fields))
        assert s.primary == expected, f"{label}: got {s.primary} ({s.reason})"
        assert s.confidence > 0

    def test_typed_signal_recorded_in_reason(self, resolver):
        s = resolver.resolve(SkillQuery(text="x", target_type="web", vuln_hints=["sqli"]))
        assert any("vuln=sqli" in sig or "target=web" in sig for sig in s.signals)


# ── Conflict resolution ──────────────────────────────────────────────


class TestConflict:
    def test_ctf_web_beats_generic_web_methodology_on_flag(self, resolver):
        s = resolver.resolve(SkillQuery.from_input("flag 弱比较 preg_match绕过 highlight_file"))
        assert s.primary == "ctf-web"

    def test_client_reverse_beats_web_testing_while_replay_blocked(self, resolver):
        s = resolver.resolve(SkillQuery.from_input("客户端签名 无法重放，需要逆向请求链"))
        assert s.primary == "client-reverse"

    def test_web_security_resumes_once_replay_stable(self, resolver):
        s = resolver.resolve(SkillQuery.from_input("重放已稳定，继续 sql注入 xss 测试"))
        assert s.primary == "web-security-advanced"

    def test_broad_kb_never_eclipses_precise_skill_on_tie(self, catalog):
        """A broad KB tied with a precise skill loses the tie-break."""
        resolver = SkillResolver(catalog)
        # Construct a tie via typed signals both share, then confirm the narrow
        # skill (non-broad) is primary and the broad KB rides as support.
        s = resolver.resolve(SkillQuery(text="pentest", target_type="web", task_types=["pentest"]))
        assert s.primary != "secknowledge-skill"
        assert not catalog[s.primary].routing.broad


# ── Negative ─────────────────────────────────────────────────────────


class TestNegative:
    def test_non_security_text_injects_nothing(self, resolver):
        s = resolver.resolve(SkillQuery.from_input("你好今天天气怎么样"))
        assert s.primary is None
        assert s.is_empty()

    def test_generic_pentest_falls_back_to_pentest_flow(self, resolver):
        # Pentest-like signal ("security") but no skill-specific keyword hit.
        s = resolver.resolve(SkillQuery(text="please do a security assessment here"))
        assert s.primary == "pentest-flow"
        assert "fallback" in s.reason


# ── Bundle budget ────────────────────────────────────────────────────


class TestBudget:
    def test_selection_never_exceeds_one_primary_two_support(self, resolver):
        # A signal-rich query that could match many skills.
        s = resolver.resolve(
            SkillQuery(
                text="sql注入 xss rce ssti 逆向 内网 报告",
                target_type="web",
                vuln_hints=["sqli", "xss", "rce"],
            )
        )
        assert s.primary is not None
        assert len(s.supporting) <= 2
        assert len(s.all_skill_ids()) <= 3


# ── Prompt integration ───────────────────────────────────────────────


class TestPromptIntegration:
    def test_context_includes_reference_index_not_skill_body(self):
        from deepsec.spear.agent.skill_context import get_active_skill_context

        ctx = get_active_skill_context("对这个APP做逆向分析")
        assert ctx is not None
        assert "optional reference material only" in ctx.lower()
        assert "primary reference: client-reverse" in ctx
        # resolver reason embedded as reference routing metadata
        assert "reference routing:" in ctx
        # reference hints are on-demand
        assert "load_skill_reference" in ctx
        # not the whole corpus: unrelated markers and primary workflow body are absent
        assert "GAARM" not in ctx
        assert "## 当前 Skill" not in ctx

    def test_non_security_input_yields_no_context(self):
        from deepsec.spear.agent.skill_context import get_active_skill_context

        assert get_active_skill_context("你好今天天气怎么样") is None

    def test_no_input_yields_no_default_playbook(self):
        from deepsec.spear.agent.skill_context import get_active_skill_context

        assert get_active_skill_context(None) is None


# ── Auditability / provenance ────────────────────────────────────────


class TestProvenance:
    def test_selection_to_provenance_is_structured(self, resolver):
        s = resolver.resolve(SkillQuery(text="x", target_type="web", vuln_hints=["sqli"]))
        prov = s.to_provenance(loaded_references=["web-injection.md"])
        assert prov["primary"] == s.primary
        assert prov["references_loaded"] == ["web-injection.md"]
        assert "reason" in prov and "confidence" in prov

    def test_finding_records_active_selection(self, resolver):
        from deepsec.spear.agent.context import SessionState, VulnerabilityFinding

        state = SessionState(target="http://example.com")
        selection = resolver.resolve(SkillQuery(text="x", target_type="web", vuln_hints=["sqli"]))
        changed = state.set_active_skill_selection(selection.to_provenance())
        assert changed is True

        state.add_finding(VulnerabilityFinding(title="SQLi", vuln_type="SQLi", evidence="e"))
        prov = state.findings[0].skill_provenance
        assert prov is not None
        assert prov["primary"] == selection.primary

    def test_selection_change_emits_run_event(self, resolver):
        from deepsec.spear.agent.context import SessionState

        state = SessionState()
        state.set_active_skill_selection({"primary": "web-security-advanced", "supporting": []})
        state.set_active_skill_selection({"primary": "ctf-web", "supporting": []})
        assert len(state.skill_selection_events) == 2
        assert state.skill_selection_events[-1]["primary"] == "ctf-web"

    def test_no_event_when_selection_unchanged(self, resolver):
        from deepsec.spear.agent.context import SessionState

        state = SessionState()
        prov = {"primary": "ctf-web", "supporting": []}
        state.set_active_skill_selection(prov)
        state.set_active_skill_selection(dict(prov))
        assert len(state.skill_selection_events) == 1

    def test_explicit_finding_provenance_not_overwritten(self, resolver):
        from deepsec.spear.agent.context import SessionState, VulnerabilityFinding

        state = SessionState()
        state.set_active_skill_selection({"primary": "web-security-advanced", "supporting": []})
        finding = VulnerabilityFinding(
            title="X", vuln_type="XSS", evidence="e", skill_provenance={"primary": "ctf-web"}
        )
        state.add_finding(finding)
        assert state.findings[0].skill_provenance["primary"] == "ctf-web"


# ── Child-agent task summary ─────────────────────────────────────────


class TestChildAgent:
    def test_task_summary_feeds_routing(self, resolver):
        # No user text, only a child-agent task summary.
        s = resolver.resolve(SkillQuery(text="", task_summary="逆向客户端签名并稳定重放"))
        assert s.primary == "client-reverse"


# ── Runtime wiring (skill_context ↔ session state) ──────────────────


class TestRuntimeWiring:
    def _state(self, **kw):
        from deepsec.spear.agent.context import PentestPhase, SessionState

        state = SessionState(**kw)
        return state, PentestPhase

    def test_apply_derives_typed_signals_from_state(self):
        from deepsec.spear.agent.skill_context import apply_skill_selection

        state, Phase = self._state(target="http://shop.example.com")
        state.phase = Phase.VULN_DISCOVERY
        ctx = apply_skill_selection(state, "测试SQL注入")
        assert ctx is not None
        # Provenance recorded and consistent with a web injection bundle.
        prov = state.active_skill_selection
        assert prov is not None
        assert prov["primary"] == "web-security-advanced"

    def test_apply_records_provenance_matching_context(self):
        from deepsec.spear.agent.skill_context import apply_skill_selection

        state, Phase = self._state()
        ctx = apply_skill_selection(state, "对这个APP做逆向分析")
        assert state.active_skill_selection["primary"] == "client-reverse"
        # The recorded reason is embedded in the very context that was returned.
        assert state.active_skill_selection["reason"].split(" ")[0] in ctx
        assert "optional reference material only" in ctx.lower()

    def test_ascii_vuln_hint_requires_token_boundary(self):
        """`rce` must not fire inside `source` (non-security input stays clean)."""
        from deepsec.spear.agent.skill_context import (
            _extract_vuln_hints,
            get_active_skill_context,
        )

        assert _extract_vuln_hints("show me the source code") == []
        assert _extract_vuln_hints("test for rce here") == ["rce"]
        assert get_active_skill_context("show me the source code") is None

    def test_ascii_tech_keyword_requires_token_boundary(self):
        from deepsec.spear.agent.skill_context import _extract_technologies

        # "java" must not match inside "javascript".
        assert "java" not in _extract_technologies("a javascript app", None)
        assert "java" in _extract_technologies("a java app", None)

    def test_finding_provenance_not_mutated_by_later_reference(self):
        """A reference loaded after a finding must not rewrite its provenance."""
        from deepsec.spear.agent.context import VulnerabilityFinding
        from deepsec.spear.agent.skill_context import apply_skill_selection

        state, _ = self._state()
        apply_skill_selection(state, "对这个APP做逆向分析")
        state.add_finding(VulnerabilityFinding(title="A", vuln_type="Recon", evidence="e"))
        # Reference loaded AFTER the finding was recorded.
        state.record_loaded_reference("client-reverse", "02-client-api-reverse-and-burp.md")
        assert state.findings[0].skill_provenance["references_loaded"] == []

    def test_non_security_input_records_no_selection(self):
        from deepsec.spear.agent.skill_context import apply_skill_selection

        state, _ = self._state()
        ctx = apply_skill_selection(state, "你好今天天气怎么样")
        assert ctx is None
        assert state.active_skill_selection is None

    def test_loaded_reference_recorded_on_provenance(self):
        from deepsec.spear.agent.skill_context import apply_skill_selection

        state, _ = self._state()
        apply_skill_selection(state, "对这个APP做逆向分析")
        state.record_loaded_reference("client-reverse", "02-client-api-reverse-and-burp.md")
        loaded = state.active_skill_selection["references_loaded"]
        assert "client-reverse/02-client-api-reverse-and-burp.md" in loaded

    def test_clearing_selection_emits_clear_event(self):
        from deepsec.spear.agent.context import SessionState

        state = SessionState()
        state.set_active_skill_selection({"primary": "ctf-web", "supporting": []})
        changed = state.set_active_skill_selection(None)
        assert changed is True
        assert state.skill_selection_events[-1]["kind"] == "skill_selection_cleared"

    def test_unchanged_bundle_preserves_loaded_references(self):
        from deepsec.spear.agent.context import SessionState

        state = SessionState()
        state.set_active_skill_selection(
            {"primary": "ctf-web", "supporting": [], "references_loaded": ["ctf-web/a.md"]}
        )
        # Re-resolve to the same bundle (fresh provenance without refs).
        state.set_active_skill_selection({"primary": "ctf-web", "supporting": []})
        assert state.active_skill_selection["references_loaded"] == ["ctf-web/a.md"]
