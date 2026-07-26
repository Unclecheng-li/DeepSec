from types import SimpleNamespace

from deepsec.spear.agent.context import ContextManager
from deepsec.spear.agent.correction_layer import after_tool_call


def _agent():
    return SimpleNamespace(context=ContextManager())


def _record(agent, output: str):
    return agent.context.state.agent_state.remember_tool_result(
        tool="fetch",
        arguments={"url": "https://target/select-waf.php"},
        output=output,
        status=200,
    )


def test_correction_layer_pins_high_signal_web_source_facts():
    agent = _agent()
    raw = """
    <a href="select-waf.php">select</a>
    <script src="js/select.js"></script>
    <form action="select-waf.php" method="get"><input type="text" name="id"></form>
    <script>$.ajax({url:'api/?id='+id, success:function(r){console.log(r)}})</script>
    <?php
    $sql = "select id,username,password from ctfshow_user where username !='flag' and id = '".$_GET['id']."' limit 1;";
    ?>
    """
    record = _record(agent, raw)

    signal = after_tool_call(
        agent,
        tool="fetch",
        arguments={"url": "https://target/select-waf.php"},
        raw_output=raw,
        duration_ms=10,
        evidence=record,
    )

    facts = [item.text for item in agent.context.state.agent_state.pinned_facts]
    hints = agent.context.state.agent_state.correction_hints

    assert any("Source SQL:" in item and "ctfshow_user" in item for item in facts)
    assert any("HTML form:" in item and "action=select-waf.php" in item for item in facts)
    assert any("HTML input:" in item and "name=id" in item for item in facts)
    assert any("JS/API endpoint:" in item and "api/?id=" in item for item in facts)
    assert any("Linked endpoint:" in item and "select-waf.php" in item for item in facts)
    assert any("Diagnostic: SQL source is visible" in item for item in hints)
    assert "server-side SQL/source snippet observed" in signal.model_hint()


def test_correction_layer_suggests_no_comment_payload_delta_after_sql_source():
    agent = _agent()
    sql_source = (
        "$sql = \"select id,username,password from ctfshow_user where username !='flag' "
        "and id = '\".$_GET['id'].\"' limit 1;\";"
    )
    first_record = _record(agent, sql_source)
    after_tool_call(
        agent,
        tool="fetch",
        arguments={"url": "https://target/select-waf.php"},
        raw_output=sql_source,
        duration_ms=10,
        evidence=first_record,
    )

    failed_probe = """
    # http_probe_batch results (1 request)
    [1] raw-url comment status=200 url=https://target/api/?id=0'||username='flag'%23
    body_length=63 body: {"code":0,"msg":"no result"}
    """
    second_record = _record(agent, failed_probe)
    after_tool_call(
        agent,
        tool="http_probe_batch",
        arguments={"requests": [{"raw_url": "/api/?id=0'||username='flag'%23"}]},
        raw_output=failed_probe,
        duration_ms=10,
        evidence=second_record,
    )

    hints = agent.context.state.agent_state.correction_hints
    assert any("closure/operator assumptions unresolved" in item for item in hints)


def test_correction_layer_hints_delivery_check_for_same_body_request_surface():
    agent = _agent()
    raw = """
    # http_probe_batch results (2 request(s))
    [1] GET baseline 200 len=100 hash=abc
        request=GET https://target/api?id=1
        headers={"Cookie":"debug=1"}
        body_length=100
    [2] GET payload 200 len=100 hash=abc
        request=GET https://target/api?id=1%27
        headers={"Cookie":"debug=1"}
        body_length=100
    Same-body groups: 1,2
    """
    record = _record(agent, raw)

    after_tool_call(
        agent,
        tool="http_probe_batch",
        arguments={"requests": [{"url": "/api?id=1"}, {"raw_url": "/api?id=1%27"}]},
        raw_output=raw,
        duration_ms=10,
        evidence=record,
    )

    state = agent.context.state.agent_state
    assert any("Diagnostic: same-body probe results" in item for item in state.correction_hints)
    assert state.progress_signals


def test_correction_layer_ignores_html_tag_pseudo_paths():
    agent = _agent()
    raw = """
    <code><span style="color:#0000BB">&lt;?php<br /></span>
    <span style="color:#007700">highlight_file(__FILE__);<br /></span></code>
    """
    record = _record(agent, raw)

    after_tool_call(
        agent,
        tool="fetch",
        arguments={"url": "https://target/"},
        raw_output=raw,
        duration_ms=10,
        evidence=record,
    )

    combined = "\n".join(item.detail for item in agent.context.state.agent_state.progress_signals)
    assert "/span" not in combined
    assert "/code" not in combined


def test_correction_layer_ignores_dependency_warning_urls():
    agent = _agent()
    raw = (
        "InsecureRequestWarning: Unverified HTTPS request. "
        "See https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings"
    )
    record = _record(agent, raw)

    after_tool_call(
        agent,
        tool="python_execute",
        arguments={"code": "print('warning')"},
        raw_output=raw,
        duration_ms=10,
        evidence=record,
    )

    state = agent.context.state.agent_state
    combined = "\n".join(
        [item.detail for item in state.progress_signals]
        + [item.text for item in state.pinned_facts]
    )
    assert "urllib3.readthedocs.io" not in combined


def test_correction_layer_hints_parser_filter_differential_for_runtime_boundary():
    agent = _agent()
    raw = r"""
    <?php
    if(!preg_match('/[oc]:\d+:/i', $_COOKIE['user'])){
        $user = unserialize($_COOKIE['user']);
    }
    PAYLOAD= O:11:"ctfShowUser":1:{s:5:"class";O:8:"backDoor":1:{s:4:"code";s:11:"echo 12345;";}}
    REGEX_HIT= True
    """
    record = _record(agent, raw)

    signal = after_tool_call(
        agent,
        tool="python_execute",
        arguments={"code": "print('probe')"},
        raw_output=raw,
        duration_ms=10,
        evidence=record,
    )

    state = agent.context.state.agent_state
    assert any("Parser/filter boundary:" in item.text for item in state.pinned_facts)
    assert any("Parser/filter mismatch is an open hypothesis" in item for item in state.correction_hints)
    assert "parser/filter boundary observed" in signal.model_hint()


def test_correction_layer_pins_php_pop_chain_entry_and_sink_hint():
    agent = _agent()
    raw = """
    <?php
    $user = unserialize($_COOKIE['user']);
    class ctfShowUser {
        public $class;
        public function __destruct(){ $this->class->getInfo(); }
    }
    class backDoor {
        public $code;
        public function getInfo(){ eval($this->code); }
    }
    """
    record = _record(agent, raw)

    signal = after_tool_call(
        agent,
        tool="fetch",
        arguments={"url": "https://target/"},
        raw_output=raw,
        duration_ms=10,
        evidence=record,
    )

    state = agent.context.state.agent_state
    assert any(
        "PHP POP chain candidate:" in item.text
        and "entry=ctfShowUser" in item.text
        and "sink=backDoor" in item.text
        for item in state.pinned_facts
    )
    assert any("entry/sink property relationships" in item for item in state.correction_hints)
    assert "PHP POP/deserialization chain observed" in signal.model_hint()
