from deepsec.spear.agent.reflexion import (
    FailureCategory,
    ReflexionEngine,
    classify_failure,
)


def test_classify_failure_categories():
    assert classify_failure("403 forbidden by WAF") == FailureCategory.ENV_CONSTRAINT
    assert classify_failure("target is not vulnerable, no injection found") == FailureCategory.PATH_ERROR
    assert classify_failure("syntax error from invalid payload") == FailureCategory.PARAM_ERROR
    assert classify_failure("need more recon, unknown parameter") == FailureCategory.INFO_NEEDED
    assert classify_failure("unexpected result") == FailureCategory.UNKNOWN
    assert classify_failure("") is None


def test_record_attempt_tracks_failures_and_success_resets_counters():
    engine = ReflexionEngine()

    engine.record_attempt(
        path="sqli_union",
        success=False,
        category=FailureCategory.ENV_CONSTRAINT,
        details="WAF blocked UNION",
        vuln_type="sqli",
    )
    engine.record_attempt(
        path="sqli_boolean",
        success=False,
        category=FailureCategory.PARAM_ERROR,
        details="bad delimiter",
        vuln_type="sqli",
    )

    assert engine.state.consecutive_failures == 2
    assert engine.state.vuln_type_fail_count == 2
    assert engine.should_reflect() is True
    assert engine.get_failed_paths() == ["sqli_union", "sqli_boolean"]
    assert "WAF blocked UNION" in engine.state.constraints

    engine.record_attempt(path="sqli_time", success=True, vuln_type="sqli")

    assert engine.state.consecutive_failures == 0
    assert engine.state.vuln_type_fail_count == 0


def test_should_reflect_on_total_no_progress():
    engine = ReflexionEngine(max_same_vuln_fails=10, max_total_no_progress=3)

    for index in range(3):
        engine.record_attempt(path=f"path_{index}", success=False, vuln_type=f"type_{index}")

    assert engine.should_reflect() is True


def test_reflections_drive_escalation_and_reset_failure_counters():
    engine = ReflexionEngine(max_reflections_before_escalate=2)
    engine.record_attempt(path="xss", success=False, vuln_type="xss")
    engine.record_attempt(path="xss", success=False, vuln_type="xss")

    assert engine.get_escalation_level() == 1

    engine.record_reflection("xss", "ssti", "filters blocked script payloads")

    assert engine.state.consecutive_failures == 0
    assert engine.state.vuln_type_fail_count == 0
    assert engine.get_escalation_level() == 1
    assert engine.should_escalate() is False

    engine.record_reflection("ssti", "file_inclusion", "template path looked unlikely")

    assert engine.should_escalate() is True


def test_escalation_hints_are_level_specific_and_capped():
    engine = ReflexionEngine()

    assert engine.get_escalation_hints() == ["先尝试原始 payload（不编码）。"]

    for index in range(10):
        engine.record_attempt(path=f"path_{index}", success=False, vuln_type="sqli")

    assert engine.get_escalation_level() == 4
    hints = engine.get_escalation_hints()
    assert "组合多层编码混淆。" in hints
    assert "切换到完全不同的漏洞类型/攻击面。" in hints


def test_analyze_failure_patterns_groups_by_category():
    engine = ReflexionEngine()
    engine.record_attempt(
        path="union",
        success=False,
        category=FailureCategory.ENV_CONSTRAINT,
        details="WAF blocked UNION",
    )
    engine.record_attempt(
        path="boolean",
        success=False,
        category=FailureCategory.ENV_CONSTRAINT,
        details="WAF blocked boolean probe",
    )
    engine.record_attempt(
        path="ssti",
        success=False,
        category=FailureCategory.PATH_ERROR,
        details="not vulnerable",
    )

    patterns = engine.analyze_failure_patterns()

    assert patterns[0]["category"] == FailureCategory.ENV_CONSTRAINT.value
    assert patterns[0]["occurrences"] == 2
    assert patterns[0]["affected_paths"] == ["boolean", "union"]
    assert patterns[1]["category"] == FailureCategory.PATH_ERROR.value


def test_prompt_block_is_empty_until_state_exists():
    engine = ReflexionEngine()

    assert engine.to_prompt_block() == ""

    engine.record_attempt(
        path="sqli_union",
        success=False,
        category=FailureCategory.ENV_CONSTRAINT,
        details="WAF blocked UNION",
        vuln_type="sqli",
    )

    block = engine.to_prompt_block()

    # 轻量状态块：仅计数 + 失败路径；详细的失败模式/升级提示已移至 to_reflection_prompt
    assert "🔁 反思状态：" in block
    assert "当前升级级别: L0" in block
    assert "sqli_union" in block
    assert "失败模式" not in block
    assert "绕过提示" not in block


def test_extract_experience_returns_none_or_dict():
    engine = ReflexionEngine()

    assert engine.extract_experience() is None

    engine.record_attempt(path="union", success=False, category=FailureCategory.PARAM_ERROR)
    engine.record_attempt(path="time_based", success=True, vuln_type="sqli")

    experience = engine.extract_experience()

    assert experience is not None
    assert experience["total_attempts"] == 2
    assert experience["successful_paths"] == ["time_based"]
    assert experience["failed_paths"] == ["union"]
    assert experience["last_vuln_type"] == "sqli"
