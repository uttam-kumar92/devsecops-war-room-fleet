import threading
from unittest.mock import MagicMock, patch

import tools


def test_calculate_shannon_entropy():
    assert tools.calculate_shannon_entropy("") == 0.0
    low_ent = tools.calculate_shannon_entropy("aaaaaaaaaaaa")
    high_ent = tools.calculate_shannon_entropy("a8F#9xL@2qZ!pW$7")

    assert low_ent == 0.0
    assert high_ent > 3.5


def test_scan_high_entropy_secrets():
    code_with_secret = """
    JWT_SECRET = "super_secret_jwt_key_987654321_production_do_not_leak"
    PLAIN_TEXT = "hello_world"
    URL_PATH = "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"
    ENV AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE987654321
    STRIPE_KEY = "sk_live_51AbCDeFgHiJkLmNoPqRsTuVwXyZ12345"
    GITHUB_PAT = "ghp_123456789012345678901234567890123456"
    """
    secrets = tools.scan_high_entropy_secrets(code_with_secret)
    assert len(secrets) >= 3
    assert any("AKIA" in s["masked_token"] for s in secrets)
    assert any("sk_l" in s["masked_token"] for s in secrets)
    assert any("ghp_" in s["masked_token"] for s in secrets)
    assert not any("nvd.nist.gov" in s["masked_token"] for s in secrets)


def test_run_static_security_heuristics_ast():
    vulnerable_code = """
import os
import sqlite3

JWT_SECRET = "AKIAIOSFODNN7EXAMPLE987654321"

def query_user(username):
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % username)
    os.system("ping " + username)
"""
    heuristics = tools.run_static_security_heuristics(vulnerable_code)

    assert heuristics["total_lines"] > 0
    assert len(heuristics["vulnerabilities"]) >= 2
    assert any(v["rule_id"] == "CWE-89" for v in heuristics["vulnerabilities"])
    assert any(v["rule_id"] == "CWE-78" for v in heuristics["vulnerabilities"])
    assert any("line" in v for v in heuristics["vulnerabilities"])
    assert len(heuristics["secrets_found"]) >= 1
    assert heuristics["static_risk_score"] > 50.0


def test_run_static_security_extended_rules():
    code = """
import pickle
import yaml
import requests
import tempfile
import random
import xml.etree.ElementTree as ET
from flask import Flask, render_template_string

app = Flask(__name__)

def parse(data, user_url, filename, user_xml, template_str):
    obj = pickle.loads(data)
    y = yaml.load(data)
    eval("1+1")
    res = requests.get(user_url, verify=False)
    with open("/tmp/" + filename, "r") as f:
        content = f.read()
    tmp = tempfile.mktemp()
    token = random.randint(1000, 9999)
    doc = ET.fromstring(user_xml)
    html = render_template_string(template_str)

app.run(host="0.0.0.0", debug=True)
"""
    heuristics = tools.run_static_security_heuristics(code)
    vulns = heuristics["vulnerabilities"]
    rule_ids = [v["rule_id"] for v in vulns]

    assert "CWE-502" in rule_ids  # Deserialization
    assert "CWE-95" in rule_ids  # Eval
    assert "CWE-918" in rule_ids  # SSRF
    assert "CWE-22" in rule_ids  # Path Traversal
    assert "CWE-377" in rule_ids  # mktemp
    assert "CWE-338" in rule_ids  # Weak PRNG
    assert "CWE-1327" in rule_ids  # Insecure public debug binding
    assert "CWE-295" in rule_ids  # Disabled SSL verification (verify=False)
    assert "CWE-611" in rule_ids  # XXE
    assert "CWE-79" in rule_ids  # Reflected XSS / SSTI


def test_run_static_security_cloud_and_k8s_rules():
    k8s_manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  hostNetwork: true
  containers:
  - name: root-app
    image: alpine:latest
    securityContext:
      privileged: true
      allowPrivilegeEscalation: true
      runAsUser: 0
---
resource "aws_security_group" "open_ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
    heuristics = tools.run_static_security_heuristics(k8s_manifest)
    vulns = heuristics["vulnerabilities"]
    rule_ids = [v["rule_id"] for v in vulns]

    assert "CWE-269" in rule_ids  # Kubernetes Privilege Escalation
    assert "CWE-284" in rule_ids  # Open Ingress 0.0.0.0/0


def test_generate_unified_diff():
    original = "def foo():\n    return 'insecure'\n"
    patched = "def foo():\n    return 'hardened'\n"
    diff = tools.generate_unified_diff(original, patched, filename="test.py")

    assert "-    return 'insecure'" in diff
    assert "+    return 'hardened'" in diff
    assert "a/test.py" in diff
    assert "b/test.py" in diff


def test_generate_sarif_report():
    heuristics = {
        "vulnerabilities": [
            {
                "rule_id": "CWE-89",
                "name": "SQL Injection",
                "severity": "Critical",
                "description": "SQLi flaw",
                "line": 10,
                "snippet": "cursor.execute(q)",
            },
            {
                "rule_id": "CWE-78",
                "name": "OS Injection",
                "severity": "High",
                "description": "Command injection",
                "line": 15,
                "snippet": "os.system(cmd)",
            },
        ],
        "secrets_found": [{"masked_token": "AKIA****4321", "entropy": 4.5}],
    }
    sarif = tools.generate_sarif_report(heuristics, filename="vulnerable_app.py")

    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) >= 2
    assert len(run["results"]) == 3
    assert run["results"][0]["ruleId"] == "CWE-89"
    assert "helpUri" in run["tool"]["driver"]["rules"][0]


def test_generate_security_dashboard_figures():
    stride_scores = {
        "Spoofing": 8.0,
        "Tampering": 9.0,
        "Repudiation": 7.0,
        "Information Disclosure": 9.5,
        "Denial of Service": 6.0,
        "Elevation of Privilege": 8.5,
    }
    heuristic_metrics = {
        "vulnerabilities": [{"severity": "Critical"}, {"severity": "High"}],
        "secrets_found": [{"token": "test"}],
    }

    figs = tools.generate_security_dashboard_figures(stride_scores, 8.5, heuristic_metrics)

    assert "stride_radar" in figs
    assert "cvss_gauge" in figs
    assert "risk_breakdown" in figs
    assert figs["stride_radar"] is not None
    assert figs["cvss_gauge"] is not None
    assert figs["risk_breakdown"] is not None


def test_get_http_session_thread_safety():
    sessions = []

    def fetch_session():
        s = tools.get_http_session()
        sessions.append(s)

    threads = [threading.Thread(target=fetch_session) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(sessions) == 10
    # All threads received the exact same singleton instance
    assert all(s is sessions[0] for s in sessions)


@patch("requests.Session.get")
def test_fetch_news_rss(mock_session_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = b"""<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
      <channel>
        <item>
          <title>Critical Zero-Day Patch Released</title>
          <link>https://security.google.com/item1</link>
          <pubDate>Mon, 30 Aug 2026 12:00:00 GMT</pubDate>
          <source>Google Security Blog</source>
        </item>
      </channel>
    </rss>
    """
    mock_session_get.return_value = mock_response

    output = tools.fetch_news_rss("Zero Day")
    assert "Critical Zero-Day Patch Released" in output


@patch("requests.Session.get")
def test_fetch_cve_threat_intel(mock_session_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "AbstractText": "SQL injection vulnerability CVE-2026-0001 allows remote code execution.",
        "RelatedTopics": [],
    }
    mock_session_get.return_value = mock_response

    output = tools.fetch_cve_threat_intel("SQL Injection")
    assert "SQL injection vulnerability" in output


@patch("requests.Session.post")
def test_fetch_osv_vulnerabilities(mock_session_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulns": [
            {
                "id": "GHSA-1234-5678",
                "summary": "Critical RCE in Flask",
                "details": "A remote code execution vulnerability exists in Flask session parsing.",
                "aliases": ["CVE-2026-9999"],
                "modified": "2026-08-01T00:00:00Z",
            }
        ]
    }
    mock_session_post.return_value = mock_response

    results = tools.fetch_osv_vulnerabilities("flask")
    assert len(results) == 1
    assert results[0]["id"] == "GHSA-1234-5678"
    assert "Critical RCE" in results[0]["summary"]


def test_constant_literal_tracking_prevents_false_positive():
    static_sql_code = """
import sqlite3

STATIC_QUERY = "SELECT id, name FROM users WHERE active = 1"

def get_active_users(conn):
    cursor = conn.cursor()
    cursor.execute(STATIC_QUERY)
    return cursor.fetchall()
"""
    heuristics = tools.run_static_security_heuristics(static_sql_code)
    vuln_ids = [v["rule_id"] for v in heuristics["vulnerabilities"]]
    # Static constant should NOT trigger CWE-89
    assert "CWE-89" not in vuln_ids


def test_pytorch_and_jwt_rules():
    insecure_code = """
import torch
import jwt

def load_model(path):
    model = torch.load(path)
    return model

def verify_token(raw_token):
    claims = jwt.decode(raw_token, options={"verify_signature": False})
    return claims
"""
    heuristics = tools.run_static_security_heuristics(insecure_code)
    vuln_ids = [v["rule_id"] for v in heuristics["vulnerabilities"]]
    assert "CWE-502" in vuln_ids  # PyTorch model load
    assert "CWE-347" in vuln_ids  # Unverified JWT signature


def test_new_secret_patterns_openai_anthropic_google():
    code = """
OPENAI_KEY = "sk-abcdef1234567890abcdef1234567890"
ANTHROPIC_KEY = "sk-ant-api03-abcdef1234567890abcdef123456"
GOOGLE_KEY = "AIzaSyD-1234567890abcdef1234567890abcde"
"""
    secrets = tools.scan_high_entropy_secrets(code)
    assert any("OpenAI" in s["type"] for s in secrets)
    assert any("Anthropic" in s["type"] for s in secrets)
    assert any("Google" in s["type"] for s in secrets)


@patch("requests.Session.post")
def test_fetch_osv_multi_ecosystem(mock_session_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulns": [
            {
                "id": "GHSA-npm-prototype-pollution",
                "summary": "Prototype Pollution in lodash",
                "details": "Prototype pollution vulnerability",
                "aliases": ["CVE-2020-8203"],
                "modified": "2026-01-01T00:00:00Z",
            }
        ]
    }
    mock_session_post.return_value = mock_response

    # Test automatic ecosystem resolution
    results_npm = tools.fetch_osv_vulnerabilities("lodash")
    assert len(results_npm) == 1
    assert results_npm[0]["ecosystem"] == "npm"
    assert "Prototype Pollution" in results_npm[0]["summary"]

    results_go = tools.fetch_osv_vulnerabilities("gin")
    assert results_go[0]["ecosystem"] == "Go"

    results_rust = tools.fetch_osv_vulnerabilities("tokio")
    assert results_rust[0]["ecosystem"] == "crates.io"

    results_java = tools.fetch_osv_vulnerabilities("log4j")
    assert results_java[0]["ecosystem"] == "Maven"


def test_dataflow_taint_propagation():
    code = """
from flask import Flask, request
import sqlite3
import os

app = Flask(__name__)

@app.route("/user")
def get_user():
    # Multi-hop taint propagation
    raw_user = request.args.get("name")
    sanitized_looking = raw_user
    final_query = f"SELECT * FROM accounts WHERE owner = '{sanitized_looking}'"
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(final_query)

    cmd = "echo " + raw_user
    os.system(cmd)
"""
    heuristics = tools.run_static_security_heuristics(code)
    vuln_ids = [v["rule_id"] for v in heuristics["vulnerabilities"]]

    assert "CWE-89" in vuln_ids
    assert "CWE-78" in vuln_ids


def test_insecure_cookie_rules():
    code = """
from flask import Flask, make_response

app = Flask(__name__)

@app.route("/set")
def set_auth():
    resp = make_response("ok")
    resp.set_cookie("session_id", "123456", secure=False)
    return resp
"""
    heuristics = tools.run_static_security_heuristics(code)
    vuln_ids = [v["rule_id"] for v in heuristics["vulnerabilities"]]

    assert "CWE-614" in vuln_ids


def test_security_rule_registry_loading_and_fallback():
    registry = tools.SecurityRuleRegistry()
    rules = registry.get_non_python_rules()
    patterns = registry.get_known_secret_patterns()

    assert len(rules) >= 6
    assert len(patterns) >= 8
    assert any(r["id"] == "CWE-250" for r in rules)
    assert any("AWS" in p[0] for p in patterns)

    # Custom rule registration
    registry.register_non_python_rule(
        {
            "id": "CWE-CUSTOM",
            "name": "Custom Enterprise Rule",
            "pattern": r"custom_flaw",
            "severity": "Critical",
            "description": "Custom rule test.",
        }
    )
    assert any(r["id"] == "CWE-CUSTOM" for r in registry.get_non_python_rules())


def test_generate_diff_stats():
    orig = "line 1\nline 2\nline 3\n"
    patched = "line 1\nline 2 modified\nline 3\nline 4 added\n"
    stats = tools.generate_diff_stats(orig, patched)

    assert stats["lines_added"] >= 1
    assert stats["lines_unchanged"] >= 1
    assert stats["total_modifications"] >= 1
    assert stats["original_line_count"] == 3
    assert stats["patched_line_count"] == 4


def test_typed_secret_ann_assign_and_aug_assign_taint():
    typed_code = """
import os
import sqlite3

JWT_SECRET: str = "super_secret_jwt_key_987654321_production_do_not_leak"

def run_query(req_input):
    q = "SELECT * FROM items WHERE name = "
    q += req_input
    conn = sqlite3.connect("db.sqlite")
    conn.execute(q)
"""
    heuristics = tools.run_static_security_heuristics(typed_code)
    vulns = heuristics["vulnerabilities"]
    rule_ids = [v["rule_id"] for v in vulns]

    assert "CWE-798" in rule_ids
    assert "CWE-89" in rule_ids


def test_secret_line_number_tracking_in_sarif():
    code_with_multiline_secrets = """# Comment line 1
# Comment line 2
# Comment line 3
AWS_KEY = "AKIAIOSFODNN7EXAMPLE987654321"
"""
    secrets = tools.scan_high_entropy_secrets(code_with_multiline_secrets)
    assert len(secrets) >= 1
    assert secrets[0]["line"] == 4

    sarif = tools.generate_sarif_report({"vulnerabilities": [], "secrets_found": secrets})
    secret_results = [r for r in sarif["runs"][0]["results"] if r["ruleId"] == "CWE-798"]
    assert len(secret_results) >= 1
    assert secret_results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 4


def test_generate_figures_with_dict_fallback():
    raw_dict_scores = {
        "spoofing": 8.0,
        "tampering": 9.0,
        "repudiation": 6.0,
        "information_disclosure": 8.5,
        "denial_of_service": 7.0,
        "elevation_of_privilege": 9.0,
    }
    figs = tools.generate_security_dashboard_figures(raw_dict_scores, cvss_score=9.1)
    assert figs["stride_radar"] is not None
    assert figs["cvss_gauge"] is not None
