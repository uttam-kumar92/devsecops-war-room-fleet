import os
import json
import pytest
from unittest.mock import patch, MagicMock

import agents


def test_get_client_missing_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="GEMINI_API_KEY is missing or invalid"):
        agents._get_client(None)


def test_get_client_valid_key():
    client = agents._get_client("test_api_key_12345")
    assert client is not None


def test_clean_and_parse_json():
    # 1. Clean markdown wrapped JSON
    text1 = "```json\n{\"key\": \"val\"}\n```"
    assert agents.clean_and_parse_json(text1) == {"key": "val"}

    # 2. Text before and after JSON with trailing commas
    text2 = "Here is the response: {\"items\": [1, 2, ], \"status\": True, } thank you!"
    res2 = agents.clean_and_parse_json(text2)
    assert res2["items"] == [1, 2]
    assert res2["status"] is True

    # 3. Single-quoted keys
    text3 = "{'overall_security_score': 9, 'passed': True, 'feedback': 'Good patch'}"
    res3 = agents.clean_and_parse_json(text3)
    assert res3["overall_security_score"] == 9
    assert res3["passed"] is True

    # 4. Fallback regex extraction on broken JSON
    text4 = "The result is: {\"passed\": true, \"overall_security_score\": 8, \"feedback\": \"Verified secure\", ... broken text"
    res4 = agents.clean_and_parse_json(text4)
    assert res4["passed"] is True
    assert res4["overall_security_score"] == 8

    # 5. Invalid JSON raises ValueError
    with pytest.raises(ValueError):
        agents.clean_and_parse_json("not a json at all and no fields")


def test_extract_code_patch():
    # 1. Markdown with python tag
    md1 = """
    # Security Report
    ```python
    def secure_func():
        return True
    ```
    """
    assert "def secure_func():" in agents.extract_code_patch(md1)

    # 2. Markdown with diff tag
    md2 = """
    ```diff
    - insecure()
    + hardened()
    ```
    """
    assert "+ hardened()" in agents.extract_code_patch(md2)

    # 3. Empty text
    assert agents.extract_code_patch("") == ""


def test_safe_extract_text():
    assert agents.safe_extract_text(None) == ""
    assert agents.safe_extract_text("plain string") == ""

    # Response with text attribute
    mock_resp = MagicMock()
    mock_resp.text = "Hello Gemini"
    mock_resp.candidates = []
    assert agents.safe_extract_text(mock_resp) == "Hello Gemini"


def test_secops_planner_agent(mock_genai_client):
    planner = agents.SecOpsPlannerAgent(mock_genai_client, model_name="gemini-3.7-flash", thinking_budget=1024)
    code_snippet = "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)"
    plan = planner.run(code_snippet)
    assert isinstance(plan, agents.SecurityAuditPlan)
    assert plan.target_scope == "Test Scope"
    assert len(plan.threat_vectors) >= 1
    assert len(plan.milestones) >= 1


def test_vulnerability_scout_agent(mock_genai_client, monkeypatch):
    monkeypatch.setattr("tools.fetch_news_rss", lambda topic: "Mock Security Feed")
    monkeypatch.setattr("tools.fetch_cve_threat_intel", lambda query: "Mock CVE Data")

    scout = agents.VulnerabilityScoutAgent(mock_genai_client, model_name="gemini-3.7-flash", use_search_grounding=True)
    plan = agents.SecurityAuditPlan(
        target_scope="Flask API",
        threat_vectors=["SQL Injection CWE-89"],
        stride_focus=["Tampering"],
        milestones=[]
    )
    result = scout.run("cursor.execute(f'SELECT {user}')", plan)
    assert "dossier" in result
    assert "citations" in result
    assert len(result["citations"]) >= 1
    assert "nvd.nist.gov" in result["citations"][0]["url"]


def test_rigor_metrics_agent(mock_genai_client):
    metrics_agent = agents.RigorMetricsAgent(mock_genai_client, model_name="gemini-3.7-flash")
    vulnerable_code = """
    import os
    API_KEY = "AKIAIOSFODNN7EXAMPLE987654321"
    os.system("ping " + host)
    """
    result = metrics_agent.run(vulnerable_code)

    assert "heuristics" in result
    assert "analysis_summary" in result
    assert len(result["heuristics"]["vulnerabilities"]) >= 1
    assert result["heuristics"]["static_risk_score"] > 0


def test_threat_model_agent(mock_genai_client):
    threat_modeler = agents.ThreatModelAgent(mock_genai_client, model_name="gemini-3.7-flash", thinking_budget=1024)
    plan = agents.SecurityAuditPlan(
        target_scope="Flask SQLi",
        threat_vectors=["CWE-89"],
        stride_focus=["Tampering"],
        milestones=[]
    )
    metrics_data = {"analysis_summary": "Mock Static Scan"}
    report = threat_modeler.run(
        target_input="cursor.execute('SELECT * FROM users')",
        plan=plan,
        raw_dossier="Raw CVE dossier",
        metrics_data=metrics_data,
        redteam_feedback="Harden parameterization",
        verification_feedback="Verify types"
    )
    assert "Enterprise Threat Model" in report


def test_red_team_exploit_auditor(mock_genai_client):
    red_team = agents.RedTeamExploitAuditor(mock_genai_client, model_name="gemini-3.7-flash")
    critique = red_team.run("cursor.execute()", "Raw CVE", "Draft patch")
    assert isinstance(critique, agents.RedTeamCritique)
    assert critique.bypass_possible is False
    assert isinstance(critique.fluff_detected, bool)


def test_devsecops_verification_gate(mock_genai_client):
    verifier = agents.DevSecOpsVerificationGate(mock_genai_client, model_name="gemini-3.7-flash")
    result = verifier.run("cursor.execute()", "Raw CVE", "Draft patch")
    assert isinstance(result, agents.VerificationResult)
    assert result.passed is True
    assert result.overall_security_score == 10
    assert result.estimated_cvss_score == 8.5


def test_run_fleet_orchestrator(mock_genai_client, monkeypatch):
    monkeypatch.setattr(agents, "_get_client", lambda api_key: mock_genai_client)
    monkeypatch.setattr("tools.fetch_news_rss", lambda topic: "Mock Security Feed")
    monkeypatch.setattr("tools.fetch_cve_threat_intel", lambda query: "Mock CVE Data")

    captured_logs = []

    def status_cb(agent, step_type, message, payload=None):
        captured_logs.append((agent, step_type, message))
        if agent == "SecOpsPlannerAgent":
            # Simulate a status callback exception to verify fleet resilience
            raise RuntimeError("UI telemetry glitch simulated")

    target_code = "import os\nAPI_KEY = 'secret_key_123456789'\nos.system('ls ' + path)"

    fleet_output = agents.run_fleet(
        target_input=target_code,
        api_key="valid_mock_key",
        model_name="gemini-3.7-flash",
        thinking_budget=1024,
        use_search_grounding=True,
        status_callback=status_cb,
        max_revisions=2
    )

    assert "final_report" in fleet_output
    assert "plan" in fleet_output
    assert "verification" in fleet_output
    assert "unified_diff" in fleet_output
    assert "sarif_report" in fleet_output
    assert len(captured_logs) > 0
    assert any(log[0] == "SecOpsPlannerAgent" for log in captured_logs)
    assert any(log[0] == "VulnerabilityScoutAgent" for log in captured_logs)
    assert any(log[0] == "DevSecOpsVerificationGate" for log in captured_logs)


def test_run_fleet_kwargs_compatibility(mock_genai_client, monkeypatch):
    monkeypatch.setattr(agents, "_get_client", lambda api_key: mock_genai_client)
    monkeypatch.setattr("tools.fetch_news_rss", lambda topic: "Mock Security Feed")
    monkeypatch.setattr("tools.fetch_cve_threat_intel", lambda query: "Mock CVE Data")

    # Test calling with target_code and unexpected extra kwargs
    output = agents.run_fleet(
        target_code="import secrets",
        api_key="valid_mock_key",
        unexpected_extra_kwarg="should_not_crash",
    )
    assert "final_report" in output
    assert output["target_input"] == "import secrets"
    assert "sarif_report" in output


def test_run_fleet_large_payload_guarding(mock_genai_client, monkeypatch):
    monkeypatch.setattr(agents, "_get_client", lambda api_key: mock_genai_client)
    monkeypatch.setattr("tools.fetch_news_rss", lambda topic: "Mock Security Feed")
    monkeypatch.setattr("tools.fetch_cve_threat_intel", lambda query: "Mock CVE Data")

    huge_code = "# Insecure code\n" + ("x = 1\n" * 10000)
    output = agents.run_fleet(
        target_input=huge_code,
        api_key="valid_mock_key"
    )
    assert "final_report" in output
    assert len(output["target_input"]) <= 35000
    assert "multi_file_patches" in output


def test_prepare_target_input():
    assert agents._prepare_target_input("") == ""
    assert agents._prepare_target_input("hello", max_chars=10) == "hello"
    long_text = "a" * 20
    bounded = agents._prepare_target_input(long_text, max_chars=10)
    assert "[TRUNCATED" in bounded
    assert bounded.startswith("a" * 10)


def test_extract_multi_file_patches():
    md = """
# Threat Report

```python filename=app.py
def secure_app():
    return "ok"
```

```dockerfile filename=Dockerfile
FROM python:3.11-slim
USER 10001
```
"""
    patches = agents.extract_multi_file_patches(md)
    assert len(patches) == 2
    assert patches[0]["filename"] == "app.py"
    assert "secure_app" in patches[0]["content"]
    assert patches[1]["filename"] == "Dockerfile"
    assert "USER 10001" in patches[1]["content"]


def test_secops_prompt_registry():
    assert agents.SecOpsPromptRegistry.VERSION == "2.4.0"
    planner_p = agents.SecOpsPromptRegistry.planner_prompt("print('hello')")
    assert "SecOpsPlannerAgent" in planner_p
    assert "print('hello')" in planner_p

    scout_p = agents.SecOpsPromptRegistry.scout_grounding_prompt("input", ["SQLi"])
    assert "VulnerabilityScoutAgent" in scout_p
    assert "SQLi" in scout_p

    metrics_p = agents.SecOpsPromptRegistry.metrics_analysis_prompt({"risk": 10}, "input")
    assert "RigorMetricsAgent" in metrics_p

    rt_p = agents.SecOpsPromptRegistry.red_team_prompt("input", "report")
    assert "RedTeamExploitAuditor" in rt_p

    v_p = agents.SecOpsPromptRegistry.verification_prompt("input", "report")
    assert "DevSecOpsVerificationGate" in v_p
