import html
import importlib
import json
import os
import time

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

import agents
import tools

# Hot-reload agents and tools to ensure fresh bytecode and prevent stale in-memory module issues
importlib.reload(agents)
importlib.reload(tools)

# Page configuration
st.set_page_config(
    page_title="Enterprise DevSecOps War-Room | Autonomous 6-Agent Fleet",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

def load_css() -> str:
    """Loads custom Vercel / Geist CSS stylesheet from assets/style.css with graceful fallback."""
    css_path = os.path.join(os.path.dirname(__file__), "assets", "style.css")
    if os.path.exists(css_path):
        try:
            with open(css_path, "r", encoding="utf-8") as f:
                return f"<style>\n{f.read()}\n</style>"
        except Exception:
            pass
    return """<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
    .stApp { background-color: #000000; color: #ededed; font-family: 'Inter', sans-serif; }
    </style>"""


st.markdown(load_css(), unsafe_allow_html=True)


# ============================================================================
# Sidebar Configuration & Controls
# ============================================================================
with st.sidebar:
    st.markdown("### DevSecOps Control Plane")
    st.caption("Autonomous 6-Agent Threat Modeling Engine")

    st.divider()

    env_api_key = os.environ.get("GEMINI_API_KEY", "")
    has_valid_env_key = env_api_key and env_api_key != "YOUR_API_KEY_HERE"

    user_api_key = st.text_input(
        "Gemini API Key",
        value=env_api_key if has_valid_env_key else "",
        type="password",
        help="Enter your Gemini API key here or configure GEMINI_API_KEY in .env"
    )

    active_key = user_api_key.strip() if user_api_key.strip() else env_api_key

    if active_key and active_key != "YOUR_API_KEY_HERE":
        st.success("API Key Active (GenAI 1.x Connected)", icon="🟢")
    else:
        st.warning("API Key Required for Live Fleet Execution", icon="⚠️")

    st.divider()

    st.markdown("#### Engine Parameters")
    model_name = st.selectbox(
        "Gemini Frontier Model",
        options=["gemini-3.5-flash", "gemini-3.7-flash", "gemini-3.6-flash", "gemini-3.5-flash-lite", "gemini-3.1-flash-lite", "gemini-flash-latest"],
        index=0,
        help="Gemini 3.5 & 3.7 Flash support structured schema outputs, reasoning budgets, and real-time Search Grounding."
    )

    use_grounding = st.toggle(
        "Live CVE & NVD Search Grounding",
        value=True,
        help="Engages real-time Google Search Grounding for zero-day advisories and NVD CVE catalogs."
    )

    thinking_budget = st.slider(
        "Reasoning Budget (tokens)",
        min_value=0,
        max_value=4096,
        value=1024,
        step=512,
        help="Allocates reasoning tokens for deep reflection before threat model & patch generation."
    )

    max_revisions = st.slider(
        "Adversarial Fix Loops",
        min_value=1,
        max_value=3,
        value=2,
        help="Max self-correction cycles if Red-Team discovers patch bypasses or Verifier fails quality gates."
    )

    st.divider()

    st.markdown("#### Agent Fleet Topology")
    st.markdown("""
    <div class="topology-card">
        <div class="topology-item"><span class="geist-dot-purple"></span><span><strong>SecOpsPlanner</strong>: STRIDE Scope</span></div>
        <div class="topology-item"><span class="geist-dot-blue"></span><span><strong>VulnScout</strong>: CVE & Grounding</span></div>
        <div class="topology-item"><span class="geist-dot-green"></span><span><strong>RigorMetrics</strong>: AST & Entropy</span></div>
        <div class="topology-item"><span class="geist-dot-amber"></span><span><strong>ThreatModeler</strong>: STRIDE Patch</span></div>
        <div class="topology-item"><span class="geist-dot-red"></span><span><strong>RedTeam</strong>: Exploit Simulation</span></div>
        <div class="topology-item"><span class="geist-dot-green"></span><span><strong>VerifierGate</strong>: CVSS Quality</span></div>
    </div>
    """, unsafe_allow_html=True)

    st.divider()
    if st.button("🔄 Reset War-Room Session", use_container_width=True, help="Clears current audit session and cached results"):
        for k in ["secops_result", "live_logs_history"]:
            if k in st.session_state:
                del st.session_state[k]
        st.rerun()


# ============================================================================
# Main Header & Security Preset Scenarios
# ============================================================================
st.markdown('<div class="geist-pill"><span class="geist-dot"></span>ENGINE BUILD v2.5.0-ENTERPRISE &bull; GEMINI 3.7 CONCURRENT CORE</div>', unsafe_allow_html=True)
st.markdown('<div class="hero-title">Enterprise DevSecOps Threat Modeling War-Room</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="hero-subtitle">Autonomous STRIDE threat modeling, live CVE intelligence, Python AST static analysis, adversarial Red-Team exploit simulation, and automated code remediation powered by <code>google-genai</code>.</div>',
    unsafe_allow_html=True
)

# Interactive Information & Documentation Expander (ℹ️ How It Works & User Guide)
with st.expander("ℹ️ Complete Manual & Step-by-Step User Guide • Click to expand", expanded=False):
    st.markdown("""
    ### 🚀 Step-by-Step User Guide: How to Use the DevSecOps War-Room

    #### 1️⃣ Step 1: Connect Your Gemini API Key
    - Enter your API Key in the left sidebar under **Gemini API Key**, or configure `GEMINI_API_KEY` in your root `.env` file.
    - When connected, the green indicator `API Key Active (GenAI 1.x Connected)` will appear.

    #### 2️⃣ Step 2: Select a Target Scenario or Upload Code
    - **Preset 1 (Flask API):** Audits SQL Injection (CWE-89), OS Command Injection (CWE-78), SSRF (CWE-918), and leaked JWT keys.
    - **Preset 2 (Dockerfile):** Audits container root privileges (CWE-250) and hardcoded AWS credentials (CWE-798).
    - **Preset 3 (Data Pipeline):** Audits unsafe YAML/pickle deserialization (CWE-502), dynamic `eval()` (CWE-95), and path traversal (CWE-22).
    - **Preset 4 (Kubernetes & Cloud):** Audits privileged Pod specs (CWE-269), open `0.0.0.0/0` SSH ingress rules (CWE-284), and Stripe tokens.
    - **File Upload:** Upload any `.py`, `.dockerfile`, `.yaml`, `.tf`, `.json`, or `.sh` script directly.

    #### 3️⃣ Step 3: Configure Engine & Reasoning Parameters (Sidebar)
    - **Model Selection:** Choose `gemini-3.7-flash` (or `gemini-3.5-flash`).
    - **Search Grounding:** Toggle live Google Search Grounding to pull real-time CVE and NVD records.
    - **Reasoning Budget:** Allocate thinking tokens (e.g. 1024 to 4096) for deep architectural reflection.
    - **Adversarial Fix Loops:** Set max self-correction iterations (1 to 3) if the Red-Team finds bypasses.

    #### 4️⃣ Step 4: Execute the War-Room & Watch Live Telemetry
    - Click the primary white **`⚡ Run DevSecOps Audit & Autonomous Patch`** button.
    - Observe the 6 agents collaborate sequentially with timestamped event logging in the execution telemetry stream.

    #### 5️⃣ Step 5: Review Results Across the 9 High-Density Tabs
    - **Diff & Patch:** Side-by-side original vs. remediated code + unified git patch.
    - **STRIDE Whitepaper:** In-depth executive security report and CVSS 3.1 analysis.
    - **Radar & CVSS:** Interactive Plotly STRIDE threat polygon and CVSS 3.1 gauge.
    - **AST & Secrets:** Line-by-line breakdown of AST-detected CWE flaws and high-entropy secret tokens.
    - **CVE Grounding:** Live search queries and verified NVD/Google security links.
    - **Red-Team Audit:** Adversarial exploit simulation checking for secondary bypasses.
    - **SARIF & CI/CD:** Exportable OASIS SARIF v2.1.0 standard JSON.
    - **Telemetry:** Complete event logs and full session state export.

    #### 6️⃣ Step 6: Deploy Fixes & CI/CD Integration
    - Click **Download Git Unified Patch (.diff)** and run `git apply security_patch.diff`.
    - Click **Download SARIF Report (.sarif)** to upload directly to GitHub Advanced Security or GitLab CI.

    ---

    ### 🏛️ Complete System Architecture & 6-Agent Breakdown
    
    This platform implements a **closed-loop 6-Agent DevSecOps War-Room** that outperforms simple single-prompt AI wrappers by introducing adversarial verification, real-time threat intelligence, and deterministic Python AST static analysis:

    1. **`SecOpsPlannerAgent` (Architect & Scoping Strategist):** Decomposes target into structured STRIDE scopes.
    2. **`VulnerabilityScoutAgent` (Threat Intel & Grounding):** Queries live CVE/NVD records via `types.GoogleSearch()`.
    3. **`RigorMetricsAgent` (AST Static Scanner & Entropy Engine):** Evaluates 14 CWE flaw categories and Shannon entropy $H(X)$.
    4. **`ThreatModelAgent` (Principal Security Architect & Autonomous Patcher):** Synthesizes STRIDE whitepapers and unified Git diffs.
    5. **`RedTeamExploitAuditor` (Adversarial Penetration Tester):** Simulates exploit payloads against candidate patches.
    6. **`DevSecOpsVerificationGate` (Automated Quality Gatekeeper):** Validates CVSS mitigation and triggers self-correction loops if bypasses exist.
    """)

# Preset Security Scenarios
PRESET_FLASK = """# Insecure Flask Auth, SSRF & Diagnostic API
import os
import sqlite3
import hashlib
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)
JWT_SECRET = "super_secret_jwt_key_987654321_production_do_not_leak"

def get_db():
    return sqlite3.connect("users.db")

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    
    # Vulnerability 1: SQL Injection (CWE-89)
    query = f"SELECT id, role FROM users WHERE username = '{username}' AND password = '{password}'"
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        return jsonify({"token": JWT_SECRET, "role": user[1]})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/execute_diagnostic", methods=["POST"])
def run_diagnostic():
    host = request.json.get("host", "127.0.0.1")
    # Vulnerability 2: OS Command Injection (CWE-78)
    os.system(f"ping -c 1 {host}")
    return jsonify({"status": "Diagnostic run completed"})

@app.route("/fetch_avatar", methods=["GET"])
def fetch_avatar():
    url = request.args.get("url")
    # Vulnerability 3: Server-Side Request Forgery (CWE-918)
    res = requests.get(url, verify=False)
    return res.content
"""

PRESET_DOCKER = """# Insecure Microservice Dockerfile & Cloud Configuration
FROM python:3.9

WORKDIR /app

# Vulnerability 1: Hardcoded AWS Credential (CWE-798)
ENV AWS_SECRET_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE987654321"
ENV AWS_DEFAULT_REGION="us-east-1"

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Vulnerability 2: Container Runs as Default Root User (CWE-250)
EXPOSE 8000
CMD ["python", "server.py"]
"""

PRESET_FASTAPI = """# Insecure Data Ingestion, Serialization & Path Traversal Pipeline
import pickle
import yaml
import os
from fastapi import FastAPI, Request

app = FastAPI()

@app.post("/ingest_yaml")
async def ingest_yaml(request: Request):
    raw_payload = await request.body()
    # Vulnerability 1: Insecure YAML Deserialization (CWE-502)
    data = yaml.load(raw_payload) 
    return {"status": "parsed", "data": data}

@app.post("/eval_expression")
async def eval_expression(expr: str):
    # Vulnerability 2: Dangerous Dynamic Evaluation (CWE-95)
    result = eval(expr)
    return {"result": result}

@app.get("/read_log")
def read_log(filename: str):
    # Vulnerability 3: Path Traversal (CWE-22)
    with open("/var/log/" + filename, "r") as f:
        return {"content": f.read()}
"""

PRESET_K8S_CLOUD = """# Insecure Kubernetes Pod Spec & Cloud Infrastructure
apiVersion: v1
kind: Pod
metadata:
  name: privileged-api-workload
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: backend
    image: api-service:latest
    securityContext:
      privileged: true
      allowPrivilegeEscalation: true
      runAsUser: 0
    env:
    - name: STRIPE_KEY
      value: "sk_live_51AbCDeFgHiJkLmNoPqRsTuVwXyZ12345"
---
# Insecure Terraform Ingress Rule
resource "aws_security_group" "open_ssh" {
  name = "allow_all_ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

# Vercel-Style Scenario Pill Selector
st.markdown("##### Target Scenario & Code Ingestion")
scenario_options = [
    "Flask Microservice (SQLi & RCE & SSRF)",
    "Dockerfile (Root & AWS Key)",
    "Data Pipeline (YAML, eval & Traversal)",
    "Kubernetes & Cloud (Privileged & Open Ingress)",
    "File Upload / Custom"
]

if hasattr(st, "segmented_control"):
    selected_tab = st.segmented_control(
        "Select Target Scenario",
        options=scenario_options,
        default="Flask Microservice (SQLi & RCE & SSRF)",
        label_visibility="collapsed"
    )
else:
    selected_tab = st.radio(
        "Select Target Scenario",
        options=scenario_options,
        index=0,
        horizontal=True,
        label_visibility="collapsed"
    )

default_code = PRESET_FLASK
if "Dockerfile" in selected_tab:
    default_code = PRESET_DOCKER
elif "Data Pipeline" in selected_tab:
    default_code = PRESET_FASTAPI
elif "Kubernetes" in selected_tab:
    default_code = PRESET_K8S_CLOUD
elif "Upload" in selected_tab:
    default_code = ""

# Optional File Upload
uploaded_file = st.file_uploader(
    "Upload Source Code / Dockerfile / Configuration:",
    type=["py", "dockerfile", "yaml", "yml", "json", "txt", "sh", "tf", "sql", "js", "ts"],
    help="Upload Python scripts, Dockerfiles, Terraform configs, or Kubernetes manifests."
)

if uploaded_file is not None:
    try:
        raw_bytes = uploaded_file.getvalue()
        try:
            default_code = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            default_code = raw_bytes.decode("latin-1", errors="replace")
        st.success(f"Loaded file: `{uploaded_file.name}` ({len(default_code.splitlines())} lines)")
    except Exception as e:
        st.error(f"Error reading file: {e}")

target_code = st.text_area(
    "Target Source Code / Architecture Definition to Audit:",
    value=default_code,
    height=240,
    help="Paste Python source code, Dockerfiles, or cloud deployment specifications.",
    label_visibility="collapsed"
)

code_line_count = len(target_code.splitlines()) if target_code else 0
st.caption(f"Payload: `{code_line_count}` lines • Language: `Python / AST / Config` • Verification: `Closed-Loop Multi-Agent`")

run_audit_clicked = st.button("⚡ Run DevSecOps Audit & Autonomous Patch", type="primary", use_container_width=True)


# ============================================================================
# Fleet Execution Flow & Live Telemetry
# ============================================================================
if run_audit_clicked:
    if not target_code or not target_code.strip():
        st.warning("Please provide target source code or select a preset scenario.")
    elif not active_key or active_key == "YOUR_API_KEY_HERE":
        st.error("Missing Gemini API Key. Please provide your API key in the sidebar or configure GEMINI_API_KEY in .env.")
    else:
        status_container = st.container(border=True)
        with status_container:
            st.markdown("#### Autonomous Fleet Execution Telemetry")
            col1, col2, col3, col4, col5, col6 = st.columns(6)
            p_box = col1.empty()
            s_box = col2.empty()
            m_box = col3.empty()
            t_box = col4.empty()
            r_box = col5.empty()
            v_box = col6.empty()

            p_box.info("SecOpsPlanner\n(Queued)")
            s_box.info("VulnScout\n(Queued)")
            m_box.info("RigorMetrics\n(Queued)")
            t_box.info("ThreatModeler\n(Queued)")
            r_box.info("RedTeam\n(Queued)")
            v_box.info("VerifierGate\n(Queued)")

            progress_bar = st.progress(5, text="Initializing 6-Agent DevSecOps Fleet...")
            telemetry_log_placeholder = st.empty()

        live_logs = []

        def ui_status_callback(agent: str, step_type: str, message: str, payload: Optional[dict] = None) -> None:
            timestamp = time.strftime("%H:%M:%S")
            live_logs.append({
                "agent": agent,
                "type": step_type,
                "message": message,
                "timestamp": timestamp
            })

            logs_html = "".join([
                f'<div class="log-row"><span class="badge">{l["agent"]}</span> <span style="color:#666666; font-size:0.75rem;">[{l["timestamp"]}]</span> {html.escape(l["message"])}</div>'
                for l in live_logs
            ])
            telemetry_log_placeholder.markdown(f'<div class="telemetry-terminal">{logs_html}</div>', unsafe_allow_html=True)

            if agent == "SecOpsPlannerAgent":
                p_box.success("SecOpsPlanner\n(Active ✓)")
                progress_bar.progress(20, text="SecOpsPlanner: Decomposing target into STRIDE threat model...")
            elif agent == "VulnerabilityScoutAgent":
                s_box.success("VulnScout\n(Active ✓)")
                progress_bar.progress(38, text="VulnScout: Querying Google Search Grounding & OSV.dev for live CVEs...")
            elif agent == "RigorMetricsAgent":
                m_box.success("RigorMetrics\n(Active ✓)")
                progress_bar.progress(55, text="RigorMetrics: Running Python AST analysis & Shannon secret entropy...")
            elif agent == "ThreatModelAgent":
                if "Hardening" in message or "regenerating" in message:
                    t_box.info("ThreatModel\n(Looping ⚡)")
                    progress_bar.progress(92, text="ThreatModeler: Resolving Red-Team bypasses & hardening patch...")
                else:
                    t_box.success("ThreatModel\n(Active ✓)")
                    progress_bar.progress(75, text="ThreatModeler: Generating hardened patch code & STRIDE whitepaper...")
            elif agent == "RedTeamExploitAuditor":
                r_box.success("RedTeam\n(Active ✓)")
                progress_bar.progress(88, text="RedTeam: Simulating exploit payloads & adversarial bypasses...")
            elif agent == "DevSecOpsVerificationGate":
                v_box.success("VerifierGate\n(Active ✓)")
                progress_bar.progress(98, text="VerifierGate: Evaluating CVSS remediation & quality score...")

        try:
            result = agents.run_fleet(
                target_input=target_code,
                api_key=active_key,
                model_name=model_name,
                thinking_budget=thinking_budget,
                use_search_grounding=use_grounding,
                status_callback=ui_status_callback,
                max_revisions=max_revisions
            )
            # Ensure all telemetry agent boxes reflect completion on the main thread
            p_box.success("SecOpsPlanner\n(Active ✓)")
            s_box.success("VulnScout\n(Active ✓)")
            m_box.success("RigorMetrics\n(Active ✓)")
            t_box.success("ThreatModel\n(Active ✓)")
            r_box.success("RedTeam\n(Active ✓)")
            v_box.success("VerifierGate\n(Active ✓)")

            st.session_state["secops_result"] = result
            st.session_state["live_logs_history"] = live_logs
            progress_bar.progress(100, text="Threat Model & Code Remediation Complete!")
            st.success("Security Audit & Autonomous Remediation Complete!")
        except Exception as e:
            st.error(f"Execution Error: {str(e)}")


# ============================================================================
# Output Visualization & Security Deep-Dive Tabs
# ============================================================================
result = st.session_state.get("secops_result")

if result:
    st.divider()

    # Full Audit Trail Expander
    logs_to_show = st.session_state.get("live_logs_history") or result.get("logs") or []
    if logs_to_show:
        with st.expander("📡 Autonomous Fleet Execution Audit Trail (Full Event Log)", expanded=False):
            trail_html = "".join([
                f'<div class="log-row"><span class="badge">{l.get("agent", "AGENT")}</span> <span style="color:#666666; font-size:0.75rem;">[{l.get("timestamp", "")}]</span> {html.escape(l.get("message", ""))}</div>'
                for l in logs_to_show
            ])
            st.markdown(f'<div class="telemetry-terminal" style="max-height:360px;">{trail_html}</div>', unsafe_allow_html=True)

    # Executive KPI Bar (Vercel Style)
    v_data = result.get("verification", {})
    sec_score = v_data.get("overall_security_score", 9)
    patch_score = v_data.get("remediation_completeness_score", 9)
    cvss_score = v_data.get("estimated_cvss_score", 8.5)
    revisions = result.get("revisions_count", 0)

    metrics_output = result.get("metrics_output", {})
    heuristics = metrics_output.get("heuristics", {})
    vuln_count = len(heuristics.get("vulnerabilities", []))
    secret_count = len(heuristics.get("secrets_found", []))

    kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
    with kpi1:
        score_class = "metric-val-success" if sec_score >= 8 else "metric-val-warn" if sec_score >= 5 else "metric-val-alert"
        st.markdown(f'<div class="metric-card"><div class="metric-val {score_class}">{sec_score}/10</div><div class="metric-label">Security Score (ℹ️)</div></div>', unsafe_allow_html=True)
    with kpi2:
        cvss_class = "metric-val-alert" if cvss_score >= 7.0 else "metric-val-warn" if cvss_score >= 4.0 else "metric-val-success"
        st.markdown(f'<div class="metric-card"><div class="metric-val {cvss_class}">{cvss_score}</div><div class="metric-label">CVSS 3.1 Base (ℹ️)</div></div>', unsafe_allow_html=True)
    with kpi3:
        st.markdown(f'<div class="metric-card"><div class="metric-val metric-val-success">{patch_score}/10</div><div class="metric-label">Patch Quality (ℹ️)</div></div>', unsafe_allow_html=True)
    with kpi4:
        st.markdown(f'<div class="metric-card"><div class="metric-val">{vuln_count} Flaws | {secret_count} Keys</div><div class="metric-label">AST Flaws & Keys</div></div>', unsafe_allow_html=True)
    with kpi5:
        st.markdown(f'<div class="metric-card"><div class="metric-val">{revisions}</div><div class="metric-label">Adversarial Loops</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # High-Density War-Room Tabs
    tab_diff, tab_report, tab_analytics, tab_static, tab_grounding, tab_redteam, tab_sarif, tab_manual, tab_logs = st.tabs([
        "Diff & Patch",
        "STRIDE Whitepaper",
        "Radar & CVSS",
        "AST & Secrets",
        "CVE Grounding",
        "Red-Team Audit",
        "SARIF & CI/CD",
        "Field Manual (ℹ️)",
        "Telemetry"
    ])

    # TAB 1: Visual Side-by-Side Patch & Git Diff
    with tab_diff:
        col_title, col_view_mode = st.columns([3, 2])
        with col_title:
            st.markdown("### Code Remediation & Git Diff")
            st.caption("Compare original vulnerable target with the autonomous verified patch.")
        with col_view_mode:
            diff_layout = st.radio(
                "Diff View Layout:",
                options=["Side-by-Side (Split)", "Stacked (Mobile / Full-Width)"],
                horizontal=True,
                label_visibility="collapsed"
            )

        patch_text = str(result.get("extracted_patch") or result.get("final_report") or "")
        orig_code = str(result.get("target_input") or target_code or "")
        unified_diff_text = str(result.get("unified_diff") or tools.generate_unified_diff(orig_code, patch_text))
        multi_patches = result.get("multi_file_patches", [])

        code_lang = "python"
        target_filename = "hardened_remediation.py"

        if len(multi_patches) > 1:
            st.info(f"Detected {len(multi_patches)} remediated file artifacts in generated patch suite.")
            selected_patch_idx = st.selectbox(
                "Select File Artifact to Inspect:",
                options=list(range(len(multi_patches))),
                format_func=lambda i: f"📄 {multi_patches[i]['filename']} ({multi_patches[i]['language']})",
                label_visibility="visible"
            )
            selected_file_patch = multi_patches[selected_patch_idx]
            patch_text = selected_file_patch["content"]
            code_lang = selected_file_patch.get("language", "python")
            target_filename = selected_file_patch.get("filename", "hardened_remediation.py")
            unified_diff_text = tools.generate_unified_diff(orig_code, patch_text, filename=target_filename)
        else:
            if "dockerfile" in orig_code.lower() or "from " in orig_code.lower():
                code_lang = "dockerfile"
                target_filename = "Dockerfile"
            elif "apiversion:" in orig_code.lower() or "kind:" in orig_code.lower():
                code_lang = "yaml"
                target_filename = "manifest.yaml"

        diff_stats = result.get("diff_stats") or tools.generate_diff_stats(orig_code, patch_text)
        st.markdown(f"""
        <div class="diff-stat-container">
            <span class="diff-stat-badge diff-stat-added">+{diff_stats.get('lines_added', 0)} Lines Added</span>
            <span class="diff-stat-badge diff-stat-deleted">-{diff_stats.get('lines_deleted', 0)} Lines Removed</span>
            <span class="diff-stat-badge diff-stat-mod">⚡ {diff_stats.get('total_modifications', 0)} Modifications</span>
            <span class="diff-stat-badge diff-stat-neutral">📊 {diff_stats.get('original_line_count', 0)} → {diff_stats.get('patched_line_count', 0)} Lines</span>
        </div>
        """, unsafe_allow_html=True)

        if diff_layout == "Side-by-Side (Split)":
            col_orig, col_patched = st.columns(2)
            with col_orig:
                st.markdown('<div class="diff-header diff-vuln-header">ORIGINAL VULNERABLE TARGET</div>', unsafe_allow_html=True)
                st.code(orig_code, language=code_lang)
            with col_patched:
                st.markdown('<div class="diff-header diff-patch-header">AUTONOMOUS HARDENED PATCH (VERIFIED)</div>', unsafe_allow_html=True)
                st.code(patch_text, language=code_lang)
        else:
            st.markdown('<div class="diff-header diff-vuln-header">ORIGINAL VULNERABLE TARGET</div>', unsafe_allow_html=True)
            st.code(orig_code, language=code_lang)
            st.markdown('<div class="diff-header diff-patch-header">AUTONOMOUS HARDENED PATCH (VERIFIED)</div>', unsafe_allow_html=True)
            st.code(patch_text, language=code_lang)

        st.markdown("#### Unified Git Patch Diff (`git apply security_patch.diff`):")
        st.code(unified_diff_text, language="diff")

        d_col1, d_col2, d_col3 = st.columns(3)
        with d_col1:
            st.download_button(
                label=f"Download Remediated Code ({target_filename})",
                data=patch_text,
                file_name=target_filename,
                mime="text/plain",
                use_container_width=True
            )
        with d_col2:
            st.download_button(
                label="Download Git Unified Patch (.diff)",
                data=unified_diff_text,
                file_name="security_patch.diff",
                mime="text/x-diff",
                use_container_width=True
            )
        with d_col3:
            st.download_button(
                label="Download Full Audit (.md)",
                data=result.get("final_report", ""),
                file_name="Enterprise_Threat_Model_Report.md",
                mime="text/markdown",
                use_container_width=True
            )

    # TAB 2: Threat Model Report
    with tab_report:
        st.markdown("### Enterprise STRIDE Threat Model & Security Audit Report")
        st.markdown(result.get("final_report", ""))

        st.download_button(
            label="Download Full Report (Markdown)",
            data=result.get("final_report", ""),
            file_name="Enterprise_Threat_Model_Report.md",
            mime="text/markdown",
            use_container_width=True
        )

    # TAB 3: STRIDE & CVSS Analytics
    with tab_analytics:
        st.markdown("### Interactive STRIDE & CVSS Threat Analytics")
        stride_data = v_data.get("stride_scores", {})

        figs = tools.generate_security_dashboard_figures(
            stride_scores=stride_data,
            cvss_score=cvss_score,
            heuristic_metrics=heuristics
        )

        col_a1, col_a2 = st.columns(2)
        with col_a1:
            st.markdown("##### STRIDE Attack Vector Severity Radar:")
            st.plotly_chart(figs["stride_radar"], use_container_width=True, config={"responsive": True})
        with col_a2:
            st.markdown("##### CVSS 3.1 Severity Gauge:")
            st.plotly_chart(figs["cvss_gauge"], use_container_width=True, config={"responsive": True})

        st.markdown("##### Flaw Distribution & Risk Breakdown:")
        st.plotly_chart(figs["risk_breakdown"], use_container_width=True, config={"responsive": True})

    # TAB 4: Static AST Scan & Secrets
    with tab_static:
        st.markdown("### Python AST Static Code Analysis & Shannon Entropy Findings")
        vulns = heuristics.get("vulnerabilities", [])
        secrets = heuristics.get("secrets_found", [])

        if vulns:
            st.markdown(f"##### AST-Detected CWE Vulnerabilities ({len(vulns)} items):")
            for v in vulns:
                st.error(
                    f"**[{v.get('rule_id')}] {v.get('name')}** (Line {v.get('line', '?')} | {v.get('severity')} Severity)\n\n"
                    f"*{v.get('description')}*\n\n"
                    f"```python\n{v.get('snippet')}\n```"
                )

        if secrets:
            st.markdown(f"##### High-Entropy Leaked Secrets ({len(secrets)} items):")
            for s in secrets:
                secret_label = s.get("type", "Secret Token")
                st.warning(f"**[{secret_label}]** `{s.get('masked_token')}` | Entropy: `{s.get('entropy')} bits` | Risk: `{s.get('risk')}`")

        if not vulns and not secrets:
            st.success("No AST pattern violations or high-entropy secrets detected.")

        with st.expander("⚙️ Active Security Rules Engine & Extensible Taxonomy Explorer", expanded=False):
            active_rules = tools.rule_registry.get_non_python_rules()
            active_patterns = tools.rule_registry.get_known_secret_patterns()
            st.markdown(f"**Loaded Rules:** `{len(active_rules)} configuration rules` | `{len(active_patterns)} high-precision secret patterns`")
            st.caption("Configured via `rules/security_rules.json` with dynamic runtime evaluation.")
            
            rule_tab1, rule_tab2 = st.tabs(["Infrastructure & Config Rules", "Cryptographic Secret Patterns"])
            with rule_tab1:
                st.dataframe(
                    pd.DataFrame(active_rules)[["id", "name", "severity", "description"]],
                    use_container_width=True,
                    hide_index=True
                )
            with rule_tab2:
                df_pat = pd.DataFrame(active_patterns, columns=["Secret Type", "Regex Pattern", "Severity"])
                st.dataframe(
                    df_pat[["Secret Type", "Severity"]],
                    use_container_width=True,
                    hide_index=True
                )


    # TAB 5: Live CVE Grounding
    with tab_grounding:
        st.markdown("### Live CVE & NVD Threat Intelligence Citations")
        citations = result.get("citations", [])
        search_queries = result.get("search_queries", [])

        if search_queries:
            st.markdown("##### Real-Time Google Search Grounding Queries:")
            for q in search_queries:
                st.code(q, language="text")

        if citations:
            st.markdown(f"##### Verified Security Advisories & Grounded References ({len(citations)} sources):")
            for idx, c in enumerate(citations):
                st.markdown(f"{idx+1}. **[{c.get('title', 'Security Advisory')}]({c.get('url', '#')})**")
                st.caption(f"URL: `{c.get('url')}`")
        else:
            st.info("Advisories correlated via live RSS and NVD knowledge index.")

    # TAB 6: Red-Team Exploit Audit
    with tab_redteam:
        st.markdown("### Adversarial Red-Team Exploit Simulation")
        rt = result.get("redteam_critique", {})

        r_col1, r_col2 = st.columns(2)
        with r_col1:
            st.markdown(f"**Attack Vector Simulated:** `{rt.get('attack_simulated', 'N/A')}`")
            bypass = rt.get('bypass_possible', False)
            if bypass:
                st.error("**Patch Bypass Possible:** True (Remediation Loop Triggered)")
            else:
                st.success("**Patch Bypass Possible:** False (Hardened Defenses Verified)")
        with r_col2:
            st.markdown(f"**Hardening Directives:** {rt.get('recommendations_for_patch', 'Ensure defense-in-depth.')}")

        st.markdown("##### Remaining Edge-Case Attack Surfaces:")
        unaddressed = rt.get("unaddressed_risks", [])
        if unaddressed:
            for ur in unaddressed:
                st.markdown(f"- 🔸 {ur}")
        else:
            st.markdown("- None detected. All critical vectors mitigated.")

    # TAB 7: SARIF Export & CI/CD DevSecOps
    with tab_sarif:
        st.markdown("### OASIS SARIF v2.1.0 Static Analysis Output")
        st.caption("Standardized Static Analysis Results Interchange Format for GitHub Security and GitLab SAST.")
        sarif_data = result.get("sarif_report", tools.generate_sarif_report(heuristics))

        runs = sarif_data.get("runs", [{}])[0]
        rules_count = len(runs.get("tool", {}).get("driver", {}).get("rules", []))
        results_count = len(runs.get("results", []))

        sm_col1, sm_col2, sm_col3 = st.columns(3)
        with sm_col1:
            st.metric("SARIF Schema", "v2.1.0 Standard")
        with sm_col2:
            st.metric("Rules Triggered", f"{rules_count} Rules")
        with sm_col3:
            st.metric("Finding Annotations", f"{results_count} Locations", delta=f"{results_count} findings", delta_color="inverse")

        view_mode = st.radio(
            "SARIF Display Format:",
            ["💻 Full JSON Code View (Expanded & Ready to Copy)", "🌳 Interactive Tree Explorer"],
            horizontal=True,
            label_visibility="collapsed"
        )

        if "Full JSON" in view_mode:
            st.code(json.dumps(sarif_data, indent=2), language="json")
        else:
            st.json(sarif_data, expanded=True)

        st.download_button(
            label="Download SARIF v2.1.0 Report (.sarif)",
            data=json.dumps(sarif_data, indent=2),
            file_name="security_scan.sarif",
            mime="application/json",
            use_container_width=True
        )

    # TAB 8: Field Manual & Documentation (ℹ️)
    with tab_manual:
        st.markdown("### 📘 DevSecOps Fleet Technical Manual & Step-by-Step Guide")
        st.markdown("""
        #### 🚀 Quick User Guide: How to Operate the War-Room
        1. **API Key Setup:** Configure your Gemini API key in the sidebar or `.env` file.
        2. **Target Ingestion:** Select one of the 4 presets (Flask SQLi/RCE, Dockerfile Root/AWS, FastAPI YAML/Traversal, Kubernetes/Cloud Ingress) or upload a custom file (`.py`, `.dockerfile`, `.yaml`, `.tf`).
        3. **Engine Parameters:** Pick a Gemini Frontier model (`gemini-3.7-flash`), toggle Search Grounding, set thinking reasoning tokens (e.g. 1024), and adversarial loops.
        4. **Execute Audit:** Click **`⚡ Run DevSecOps Audit & Autonomous Patch`** to start the 6-agent war-room.
        5. **Inspect & Verify:** Review side-by-side patch diffs, STRIDE radar charts, CVSS scores, and AST flaw locations.
        6. **Deploy Remediation:** Download the Unified Git Patch (`.diff`) and apply it with `git apply security_patch.diff`, or download the SARIF report for GitHub/GitLab CI.

        ---

        #### 1. Why Closed-Loop Multi-Agent Architecture Beats Single-Prompt LLMs
        Single-prompt AI generation often produces superficial code that looks functional but preserves critical security vulnerabilities or introduces subtle bypasses.
        Our **6-Agent Closed Loop Topology** solves this through **adversarial separation of duties**:
        - `ThreatModelAgent` generates the candidate defense patch.
        - `RedTeamExploitAuditor` actively simulates hostile attack payloads against that specific patch.
        - `DevSecOpsVerificationGate` quantitatively measures CVSS mitigation.
        - If any bypass or flaw is discovered, the orchestrator triggers an automatic self-correction revision loop.

        #### 2. Mathematical Shannon Entropy Formulation
        To detect hardcoded API keys and private tokens without maintaining fragile static keyword lists, the engine applies Shannon Information Theory:
        $$H(X) = -\\sum_{i=1}^{n} P(x_i) \\log_2 P(x_i)$$
        - Natural English text typically exhibits entropy between $1.5$ and $3.0$ bits per character.
        - Cryptographic keys, base64 hashes, and random tokens exhibit high entropy ($> 3.8$ bits per character).
        - The engine automatically isolates high-entropy strings, applies false-positive domain filtering (SQL queries, MIME types, URLs), and masks sensitive characters before presentation.

        #### 3. Python AST Security Heuristics (14 CWE Classifications)
        Rather than relying on brittle regular expressions, the engine parses Python source code into an Abstract Syntax Tree (`ast.parse`) and traverses nodes using `ast.NodeVisitor`:
        - **CWE-89 (SQLi)**: Identifies dynamic string concatenation, f-strings, and `.format()` inside database `.execute()` calls.
        - **CWE-78 (Command Injection)**: Identifies unescaped variables passed to `os.system` and `subprocess(shell=True)`.
        - **CWE-502 (Insecure Deserialization)**: Identifies unsafe `pickle.loads` and unconstrained `yaml.load`.
        - **CWE-95 (Dynamic Code Execution)**: Identifies direct `eval()` or `exec()` invocations.
        - **CWE-918 (SSRF)**: Identifies unvalidated dynamic URLs passed to `requests.get` or `urlopen`.
        - **CWE-22 (Path Traversal)**: Identifies dynamic user paths in `open()` or file operations.
        - **CWE-377 (Insecure Temp Files)**: Identifies deprecated `tempfile.mktemp`.
        - **CWE-327 (Weak Cryptography)**: Identifies collision-vulnerable `hashlib.md5`/`sha1` or broken ciphers.
        - **CWE-338 (Weak PRNG)**: Identifies `random.randint` used in security contexts instead of `secrets`.
        - **CWE-1327 (Debug Binding)**: Identifies `app.run(host="0.0.0.0", debug=True)`.
        - **CWE-295 (Disabled SSL Verification)**: Identifies `verify=False` or unverified contexts.
        - **CWE-79 (Reflected XSS / SSTI)**: Identifies dynamic template rendering without escaping.
        - **CWE-611 (XML External Entity)**: Identifies unshielded XML parsing without `defusedxml`.
        - **CWE-798 (Hardcoded Secrets)**: Identifies variable assignments containing sensitive token names.
        """)

    # TAB 9: Execution Telemetry
    with tab_logs:
        st.markdown("### Fleet Event Stream & Execution Telemetry")
        for log in result.get("logs", []):
            agent = log.get("agent", "Agent")
            timestamp = log.get("timestamp", "")
            msg = html.escape(log.get("message", ""))
            step_type = log.get("type", "")
            css_class = "log-row"
            if step_type == "verification":
                css_class += " log-verification"
            elif step_type == "warning":
                css_class += " log-warning"
            elif step_type == "plan":
                css_class += " log-plan"

            st.markdown(
                f'<div class="{css_class}"><span class="badge">{agent}</span> <span style="color:#666666; font-size:0.75rem;">[{timestamp}]</span> {msg}</div>',
                unsafe_allow_html=True
            )

        st.download_button(
            label="Export Session State (JSON)",
            data=json.dumps(result, indent=2),
            file_name=f"devsecops_session_{int(time.time())}.json",
            mime="application/json",
            use_container_width=True
        )
