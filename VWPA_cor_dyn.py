#!/usr/bin/env python3
# VWPA – Vulnerability Weaponization Possibility Analyzer
# Defensive | Ethical | Weaponization-aware | Blue-team focused

import os
import re
import streamlit as st
import matplotlib.pyplot as plt
from huggingface_hub import InferenceClient
import zipfile, tempfile

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
# 🧠 VULNERABILITY CLASSES (NON-PAYLOAD)
# ==================================================
VULN_CLASSES = {

    "Exposed Administrative Interfaces": [
        "/admin", "/dashboard", "/manage", "/controlpanel"
    ],

    "Weak or Missing Authentication": [
        "login", "signin", "auth", "no authentication", "anonymous"
    ],

    "Open & Excessive Network Services": [
        "open port", "listening on", "0.0.0.0", "exposed service"
    ],

    "Outdated or Legacy Software": [
        "version 1.", "deprecated", "end of life", "old version"
    ],

    "Debug & Development Artifacts": [
        "debug", "stack trace", "traceback", "error details"
    ],

    "Insecure Security Headers": [
        "x-frame-options", "content-security-policy",
        "missing security headers"
    ],

    "Weak Cryptographic Configuration": [
        "md5", "sha1", "weak cipher", "tls 1.0", "tls 1.1"
    ],

    "Misconfigured CORS & Trust Boundaries": [
        "access-control-allow-origin", "credentials=true"
    ],

    "Excessive Privileges & Trust": [
        "root access", "admin privileges", "full access"
    ],

    "Information Disclosure via Metadata": [
        "server:", "x-powered-by", "technology fingerprint"
    ]
}

# ==================================================
# 🎯 WEAPONIZATION PERSPECTIVE MAP
# ==================================================
WEAPONIZATION_PERSPECTIVE = {
    "Exposed Administrative Interfaces": [
        "Initial access point for attackers",
        "Privilege escalation foothold",
        "Configuration manipulation",
        "Persistence via admin features"
    ],

    "Weak or Missing Authentication": [
        "Unauthorized system access",
        "Account takeover",
        "Credential stuffing enablement",
        "Identity impersonation"
    ],

    "Open & Excessive Network Services": [
        "Attack surface expansion",
        "Lateral movement staging",
        "Service chaining attacks",
        "Botnet or proxy abuse"
    ],

    "Outdated or Legacy Software": [
        "Exploit reuse",
        "Known CVE chaining",
        "Reliable exploit automation"
    ],

    "Debug & Development Artifacts": [
        "Internal logic exposure",
        "Sensitive data leakage",
        "Attack path discovery"
    ],

    "Insecure Security Headers": [
        "Client-side exploitation setup",
        "Clickjacking enablement",
        "Script execution amplification"
    ],

    "Weak Cryptographic Configuration": [
        "Session hijacking",
        "Credential interception",
        "Man-in-the-middle positioning"
    ],

    "Misconfigured CORS & Trust Boundaries": [
        "Cross-origin data theft",
        "Session abuse",
        "API misuse"
    ],

    "Excessive Privileges & Trust": [
        "Full system compromise",
        "Persistent attacker presence",
        "Security control bypass"
    ],

    "Information Disclosure via Metadata": [
        "Target profiling",
        "Exploit selection optimization",
        "Recon-to-attack acceleration"
    ]
}

# ==================================================
# 📚 CORPUS LOADER
# ==================================================
CORPUS_DIR = "corpus_vwpa"

def load_corpus(vuln):
    fname = vuln.lower().replace(" ", "_") + ".txt"
    path = os.path.join(CORPUS_DIR, fname)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return None

# ==================================================
# 🔍 VULNERABILITY DETECTION
# ==================================================
def detect_vulnerabilities(text):
    findings = {}
    lower = text.lower()
    for vuln, patterns in VULN_CLASSES.items():
        for p in patterns:
            if p.lower() in lower:
                findings.setdefault(vuln, []).append(p)
    return findings

# ==================================================
# 🤖 LLaMA WEAPONIZATION ANALYSIS (DEFENSIVE) — UPDATED
# ==================================================
def llama_weaponization_analysis(vuln, indicators, temperature,
                                 use_internal=False,
                                 uploaded_folder_zip=None,
                                 uploaded_zip=None):

    weapon_paths = WEAPONIZATION_PERSPECTIVE.get(vuln, [])
    corpus_text_extra = ""

    # Internal corpus
    if use_internal:
        corpus = load_corpus(vuln)
        if corpus:
            corpus_text_extra += f"\n[INTERNAL CORPUS]\n{corpus}\n"

    # Uploaded folder ZIP corpus
    if uploaded_folder_zip:
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(uploaded_folder_zip) as z:
                z.extractall(tmpdir)
            path = os.path.join(tmpdir, vuln.lower().replace(" ", "_") + ".txt")
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    corpus_text_extra += f"\n[UPLOADED FOLDER CORPUS]\n{f.read()}\n"

    # Uploaded multi ZIP corpus
    if uploaded_zip:
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(uploaded_zip) as z:
                z.extractall(tmpdir)
            path = os.path.join(tmpdir, vuln.lower().replace(" ", "_") + ".txt")
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    corpus_text_extra += f"\n[UPLOADED MULTI CORPUS]\n{f.read()}\n"

    use_corpus_flag = bool(corpus_text_extra.strip())

    # ===== PROMPT =====
    prompt = f"""
You are a senior blue-team cybersecurity strategist.

Analyze the following vulnerability from a defensive perspective.
Think deeply and autonomously about attacker behavior, possible weaponization, and defensive strategies.

Vulnerability:
{vuln}

Observed Indicators:
{indicators}

Possible Weaponization Perspectives:
{weapon_paths}
"""

    if use_corpus_flag:
        prompt += f"""
[DEFENSIVE REFERENCE CORPUS – USE IF HELPFUL]
Use this information to enrich your reasoning, but rely primarily on your own expert analysis.

{corpus_text_extra}
"""

    prompt += """
Instructions:

- Think critically and independently first.
- If corpus is available, use it to enrich (not replace) your reasoning.

Provide a structured DEFENSIVE analysis with these sections:

1. Why this vulnerability is valuable to attackers
2. Likely weaponization paths (high-level, no exploits)
3. How attackers could chain this with other weaknesses
4. Early warning indicators defenders should monitor
5. Concrete preventive and hardening actions
6. Strategic security control improvements

Rules:
- Defensive only
- No exploit steps or payloads
- Corpus is optional and supplemental
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
def plot_weaponization_chart(findings):
    if not findings:
        return
    plt.figure()
    plt.bar(findings.keys(), [len(v) for v in findings.values()])
    plt.xticks(rotation=45, ha="right")
    plt.title("Detected Vulnerabilities (Weaponization Sources)")
    plt.tight_layout()
    st.pyplot(plt)

# ==================================================
# 📄 REPORT BUILDER
# ==================================================
def build_report(results):
    lines = []
    lines.append("VWPA – Vulnerability Weaponization Possibility Report")
    lines.append("=" * 70)
    for vuln, analysis in results.items():
        lines.append("\n" + "-" * 70)
        lines.append(f"VULNERABILITY: {vuln}")
        lines.append("-" * 70)
        lines.append(analysis)
    return "\n".join(lines)

# ==================================================
# 🖥️ STREAMLIT UI
# ==================================================
st.set_page_config(page_title="VWPA – Weaponization Analyzer", layout="wide")
st.title("🛡️ Vulnerability Weaponization Possibility Analyzer (VWPA)")

st.sidebar.header("Configuration")
temperature = st.sidebar.slider("LLaMA Temperature", 0.0, 1.0, 0.25, 0.05)

use_internal = st.sidebar.checkbox("Use Internal Corpus", value=False)
use_uploaded_folder_zip = st.sidebar.file_uploader("Upload Corpus Folder ZIP", type=["zip"])
use_uploaded = st.sidebar.file_uploader("Upload Multi Corpus ZIP", type=["zip"])

uploaded = st.file_uploader("Upload Recon / Scan TXT", type=["txt"])

if uploaded:
    text = uploaded.read().decode("utf-8", errors="ignore")

    if st.button("Run Weaponization Analysis"):
        with st.spinner("Analyzing weaponization possibilities…"):
            findings = detect_vulnerabilities(text)
            results = {}

            for vuln in findings:
                results[vuln] = llama_weaponization_analysis(
                    vuln,
                    findings[vuln],
                    temperature,
                    use_internal=use_internal,
                    uploaded_folder_zip=use_uploaded_folder_zip,
                    uploaded_zip=use_uploaded
                )

        st.success("Weaponization Analysis Complete")

        st.subheader("📊 Weaponization Source Overview")
        plot_weaponization_chart(findings)

        report = build_report(results)

        st.subheader("📄 Defensive Weaponization Report")
        st.text_area("Report Output", report, height=550, disabled=True)

        st.download_button(
            "Download Report (.txt)",
            report,
            file_name="vwpa_weaponization_report.txt"
        )
