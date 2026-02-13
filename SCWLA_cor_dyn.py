#!/usr/bin/env python3
# SCWLA – Security Control Weakness & Logic Analyzer
# LLM-first | Optional Corpus Enrichment | Defensive

import os
import streamlit as st
import matplotlib.pyplot as plt
from huggingface_hub import InferenceClient
import zipfile
import tempfile

# ==================================================
# 🔐 CLEAR PROXIES
# ==================================================
for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]:
    os.environ[k] = ""

# ==================================================
# 🔐 HF CONFIG
# ==================================================
HF_TOKEN = "HFTOKEN"
MODEL = "meta-llama/Llama-3.1-8B-Instruct"

client = InferenceClient(
    model=MODEL,
    token=HF_TOKEN,
    timeout=180
)

# ==================================================
# 🧠 SECURITY CONTROLS (Detection Keywords)
# ==================================================
SECURITY_CONTROLS = {
    "Web Application Firewall (WAF)": ["cloudflare", "akamai", "imperva", "aws waf", "403 forbidden"],
    "Content Security Policy (CSP)": ["content-security-policy"],
    "TLS / HTTPS": ["https", "tls", "ssl certificate"],
    "Authentication System": ["login", "authentication", "signin", "jwt", "session"],
    "Authorization / Access Control": ["role", "permission", "access denied"],
    "Rate Limiting / Bot Protection": ["429 too many requests", "rate limit", "captcha"],
    "CORS Policy": ["access-control-allow-origin"],
    "Security Headers": ["x-frame-options", "x-content-type-options", "strict-transport-security", "referrer-policy"],
    "API Gateway": ["/api/", "api gateway", "graphql"],
    "Reverse Proxy / Load Balancer": ["nginx", "haproxy", "x-forwarded-for"],
    "Firewall": ["iptables", "firewall", "pf", "pfsense", "open port"],
    "IDS / IPS": ["snort", "suricata", "ids", "ips", "alert log"],
    "DDoS Protection": ["ddos", "traffic spike", "cloudflare ddos"],
    "Cloud Security Controls": ["aws", "azure", "gcp", "s3", "iam", "bucket public"],
    "Container Security": ["docker", "k8s", "kubernetes", "container escape"],
    "Secrets Management": ["vault", "secret manager", "env secret", "k8s secret"],
    "Patch Management": ["patch", "update", "cve", "security bulletin"],
    "Logging & Monitoring": ["audit log", "siem", "elk", "splunk"],
    "Security Awareness Training": ["phishing", "training", "user awareness"],
    "Incident Response Controls": ["playbook", "incident response", "ir drill"]
}

# ==================================================
# 📚 CORPUS LOADER (GENERIC)
# ==================================================
def load_corpus_from_path(base_path, control):
    fname = control.lower().replace(" ", "_").replace("/", "_") + ".txt"
    path = os.path.join(base_path, fname)

    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    return None


# ==================================================
# 🔍 CONTROL DETECTION
# ==================================================
def detect_controls(text):
    findings = {}
    lower = text.lower()

    for control, patterns in SECURITY_CONTROLS.items():
        for p in patterns:
            if p.lower() in lower:
                findings.setdefault(control, []).append(p)

    return findings


# ==================================================
# 🤖 LLaMA ANALYSIS (LLM-FIRST)
# ==================================================
def llama_scwla_analysis(control,
                         indicators,
                         temperature,
                         use_internal=False,
                         uploaded_folder_zip=None,
                         uploaded_multi_zip=None):

    corpus_blocks = []

    # ===============================
    # Internal Corpus (optional)
    # ===============================
    if use_internal:
        corpus = load_corpus_from_path("corpus", control)
        if corpus:
            corpus_blocks.append(
                f"[INTERNAL BASELINE CORPUS]\n{corpus}"
            )

    # ===============================
    # Uploaded Folder ZIP (optional)
    # ===============================
    if uploaded_folder_zip:
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(uploaded_folder_zip) as z:
                z.extractall(tmpdir)

            corpus = load_corpus_from_path(tmpdir, control)
            if corpus:
                corpus_blocks.append(
                    f"[ORG-SPECIFIC CORPUS]\n{corpus}"
                )

    # ===============================
    # Uploaded Multi ZIP (optional)
    # ===============================
    if uploaded_multi_zip:
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(uploaded_multi_zip) as z:
                z.extractall(tmpdir)

            corpus = load_corpus_from_path(tmpdir, control)
            if corpus:
                corpus_blocks.append(
                    f"[EXTERNAL / RESEARCH CORPUS]\n{corpus}"
                )

    merged_corpus = "\n\n".join(corpus_blocks)
    use_corpus_flag = bool(corpus_blocks)

    # ===============================
    # PROMPT (LLM-FIRST)
    # ===============================
    prompt = f"""
You are a senior cybersecurity architect and defensive strategist.

Analyze the following security control from a strategic and defensive perspective.

Security Control:
{control}

Observed Indicators:
{indicators}

Instructions:

- Think independently and critically first.
- Do NOT rely on corpus initially.
- If optional corpus information is provided, use it only to enrich or validate your reasoning.
- You may ignore corpus information if it is irrelevant or outdated.


Provide a DEFENSIVE analysis including:

1. Known limitations of this control
2. Defensive architectural weaknesses
3. High-level hardening guidance
4. Monitoring and detection recommendations

Rules:
- Defensive only, no exploit instructions
- Prefer your own reasoning if corpus is absent or incomplete
- Produce structured, actionable guidance
"""

    if use_corpus_flag:
        prompt += f"""

[OPTIONAL CONTEXTUAL CORPUS – ENRICHMENT ONLY]

{merged_corpus}
"""

    response = client.chat.completions.create(
        messages=[
            {"role": "system", "content": "You are a defensive cybersecurity expert."},
            {"role": "user", "content": prompt}
        ],
        temperature=temperature,
        max_tokens=900
    )

    return response.choices[0].message.content.strip()


# ==================================================
# 📊 VISUALIZATION
# ==================================================
def plot_controls_chart(findings):
    if not findings:
        return
    plt.figure()
    plt.bar(findings.keys(), [len(v) for v in findings.values()])
    plt.xticks(rotation=45, ha="right")
    plt.title("Detected Security Controls")
    plt.tight_layout()
    st.pyplot(plt)


# ==================================================
# 📄 REPORT BUILDER
# ==================================================
def build_report(results):
    lines = []
    lines.append("SCWLA – Security Control Weakness Analysis Report")
    lines.append("=" * 70)

    for control, analysis in results.items():
        lines.append("\n" + "-" * 70)
        lines.append(f"SECURITY CONTROL: {control}")
        lines.append("-" * 70)
        lines.append(analysis)

    return "\n".join(lines)


# ==================================================
# 🖥️ STREAMLIT UI
# ==================================================
st.set_page_config(page_title="SCWLA – Security Control Analyzer", layout="wide")
st.title("🛡️ Security Control Weakness & Logic Analyzer (SCWLA)")

st.sidebar.header("Configuration")

temperature = st.sidebar.slider(
    "LLaMA Temperature", 0.0, 1.0, 0.25, 0.05
)

use_internal = st.sidebar.checkbox(
    "Use Internal Corpus (Optional)", value=False
)

uploaded_folder_zip = st.sidebar.file_uploader(
    "Upload Corpus Folder ZIP (Optional)",
    type=["zip"]
)

uploaded_multi_zip = st.sidebar.file_uploader(
    "Upload Multi Corpus ZIP (Optional)",
    type=["zip"]
)

uploaded_recon = st.file_uploader(
    "Upload Assessment / Audit TXT",
    type=["txt"]
)

if uploaded_recon:
    text = uploaded_recon.read().decode("utf-8", errors="ignore")

    if st.button("Run SCWLA Analysis"):

        with st.spinner("Analyzing security control logic and weaknesses..."):

            findings = detect_controls(text)
            results = {}

            for control in findings:
                results[control] = llama_scwla_analysis(
                    control,
                    findings[control],
                    temperature,
                    use_internal=use_internal,
                    uploaded_folder_zip=uploaded_folder_zip,
                    uploaded_multi_zip=uploaded_multi_zip
                )

        st.success("SCWLA Analysis Complete")

        st.subheader("📊 Control Detection Overview")
        plot_controls_chart(findings)

        report = build_report(results)

        st.subheader("📄 Security Control Analysis Report")
        st.text_area("Report Output", report, height=550, disabled=True)

        st.download_button(
            "Download Report (.txt)",
            report,
            file_name="scwla_report.txt"
        )
