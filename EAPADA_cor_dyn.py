#!/usr/bin/env python3
# AI Payload Awareness & Defensive Analyzer (Ethical, Corpus-Aware, Structured)

import os
import streamlit as st
import matplotlib.pyplot as plt
from huggingface_hub import InferenceClient

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
# 🧠 PAYLOAD CLASSES
# ==================================================
PAYLOAD_CLASSES = {
    "Client-Side Injection": ["<script", "onerror=", "onload=", "onclick=", "javascript:", "data:text/html", "document.cookie", "window.location"],
    "DOM Manipulation Abuse": ["innerHTML", "outerHTML", "document.write", "location.hash", "eval("],
    "Clickjacking / UI Redress": ["iframe", "frameborder", "allowfullscreen"],
    "SQL Injection": ["' or ", "\" or ", "union select", "select from", "1=1", "sleep(", "benchmark("],
    "NoSQL Injection": ["$ne", "$gt", "$where", "mapReduce"],
    "Command Injection": ["; ", "&&", "||", "|", "`", "$(", "cmd.exe", "/bin/sh"],
    "SSTI": ["{{", "}}", "${", "#{", "<#"],
    "Path Traversal": ["../", "..\\", "%2e%2e", "%252e%252e"],
    "File Inclusion": ["file=", "page=", "include="],
    "File Upload Abuse": ["filename=", "content-type:", ".php", ".jsp", ".exe", ".sh"],
    "Auth Bypass": ["role=", "admin=true", "isAdmin", "access_level"],
    "Session Abuse": ["sessionid", "phpsessid", "jsessionid", "token="],
    "JWT Abuse": ["eyJ", "alg=none", "jwt"],
    "Authorization Abuse (IDOR)": ["user_id=", "account_id=", "order_id=", "object_id="],
    "Business Logic Abuse": ["step=", "state=", "workflow=", "process="],
    "Race Condition Indicators": ["retry", "resend", "confirm"],
    "Header Injection": ["\\r\\n", "%0d%0a", "Set-Cookie:"],
    "Request Smuggling": ["transfer-encoding", "content-length"],
    "CORS Misconfiguration": ["access-control-allow-origin", "credentials=true"],
    "Open Redirect": ["redirect=", "url=", "next=", "return="],
    "Cache Poisoning": ["host:", "x-forwarded-host"],
    "Parameter Discovery": ["debug", "test", "config", "backup"],
    "Endpoint Enumeration": ["/api/", "/admin", "/internal"],
    "Technology Fingerprinting": ["phpinfo", "server:", "x-powered-by"],
    "Unsafe Deserialization": ["rO0AB", "java.io.Serializable", "pickle", "__reduce__"],
    "Resource Exhaustion": ["AAAA", "regex", "recursive", "repeat"],
    "Application-Level DoS": ["timeout", "delay", "sleep"],
    "Cryptographic Misuse": ["md5", "sha1", "des", "base64"],
    "Sensitive Data Exposure": ["apikey", "secret", "password", "private_key"],
    "Insecure Configuration": ["debug=true", "dev=true", "test=true"]
}

# ==================================================
# 🧠 MITRE + OWASP MAPS
# ==================================================
MITRE_MAP = {
    "Client-Side Injection": ["TA0001", "T1059", "T1203"],
    "SQL Injection": ["TA0001", "T1190", "TA0006"],
    "Command Injection": ["TA0002", "T1059", "TA0004"],
    "Path Traversal": ["TA0001", "T1006", "TA0006"],
    "File Upload Abuse": ["TA0002", "TA0003", "T1505"],
    "SSTI": ["TA0002", "T1059"],
    "Auth Bypass": ["TA0001", "T1078"],
    "Session Abuse": ["TA0006", "T1539"],
    "IDOR": ["TA0001", "TA0005"],
    "Open Redirect": ["TA0043", "TA0006"],
    "Business Logic Abuse": ["TA0005", "TA0040"],
    "Header Injection": ["TA0005", "TA0040"],
    "CORS Misconfig": ["TA0006", "TA0008"],
    "Cache Poisoning": ["TA0005", "TA0040"],
    "Recon": ["TA0043", "T1596"],
    "Enumeration": ["TA0043", "T1110"],
    "Unsafe Deserialization": ["TA0002", "TA0004"],
    "Resource Exhaustion": ["TA0040", "T1499"],
    "Crypto Failures": ["TA0006", "T1552"],
    "DOM Manipulation Abuse": ["TA0001", "T1203"],
    "Clickjacking / UI Redress": ["TA0001", "T1189"],
    "NoSQL Injection": ["TA0001", "T1190"],
    "JWT Abuse": ["TA0006", "T1552"],
    "Authorization Abuse (IDOR)": ["TA0001", "TA0005"],
    "Race Condition Indicators": ["TA0005", "TA0040"],
    "Request Smuggling": ["TA0005", "TA0040"],
    "Parameter Discovery": ["TA0043", "T1596"],
    "Endpoint Enumeration": ["TA0043", "T1595"],
    "Technology Fingerprinting": ["TA0043", "T1592"],
    "Application-Level DoS": ["TA0040", "T1499"],
    "Sensitive Data Exposure": ["TA0006", "T1552"],
    "Insecure Configuration": ["TA0005", "TA0040"]
}

OWASP_MAP = {
    "Client-Side Injection": "A03: Injection",
    "SQL Injection": "A03: Injection",
    "Command Injection": "A03: Injection",
    "Path Traversal": "A01: Broken Access Control",
    "File Upload Abuse": "A08: Software and Data Integrity Failures",
    "SSTI": "A03: Injection",
    "Auth Bypass": "A07: Identification & Authentication Failures",
    "Session Abuse": "A07: Identification & Authentication Failures",
    "IDOR": "A01: Broken Access Control",
    "Open Redirect": "A01: Broken Access Control",
    "Business Logic Abuse": "A04: Insecure Design",
    "Header Injection": "A05: Security Misconfiguration",
    "CORS Misconfig": "A05: Security Misconfiguration",
    "Cache Poisoning": "A05: Security Misconfiguration",
    "Recon": "A05: Security Misconfiguration",
    "Enumeration": "A07: Identification & Authentication Failures",
    "Unsafe Deserialization": "A08: Software and Data Integrity Failures",
    "Resource Exhaustion": "A04: Insecure Design",
    "Crypto Failures": "A02: Cryptographic Failures",
    "DOM Manipulation Abuse": "A03: Injection",
    "Clickjacking / UI Redress": "A05: Security Misconfiguration",
    "NoSQL Injection": "A03: Injection",
    "JWT Abuse": "A02: Cryptographic Failures",
    "Authorization Abuse (IDOR)": "A01: Broken Access Control",
    "Race Condition Indicators": "A04: Insecure Design",
    "Request Smuggling": "A05: Security Misconfiguration",
    "Parameter Discovery": "A05: Security Misconfiguration",
    "Endpoint Enumeration": "A05: Security Misconfiguration",
    "Technology Fingerprinting": "A05: Security Misconfiguration",
    "Application-Level DoS": "A04: Insecure Design",
    "Sensitive Data Exposure": "A02: Cryptographic Failures",
    "Insecure Configuration": "A05: Security Misconfiguration"
}

# ==================================================
# 🔍 DETECTION
# ==================================================
def detect_payload_classes(text):
    findings = {}
    for cls, patterns in PAYLOAD_CLASSES.items():
        for p in patterns:
            if p.lower() in text.lower():
                findings.setdefault(cls, []).append(p)
    return findings

# ==================================================
# 📊 RISK SCORING
# ==================================================
def calculate_risk(findings):
    return min(len(findings) * 2, 10)

def risk_level(score):
    return "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"

# ==================================================
# 📚 CORPUS LOADER (corpus2/)
# ==================================================
CORPUS_DIR = "corpus2"

def load_corpus(vuln):
    path = os.path.join(CORPUS_DIR, f"{vuln}.txt")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return None

# ==================================================
# 🤖 LLaMA DEFENSIVE ANALYSIS (updated for merged corpus)
# ==================================================
def llama_defensive_analysis(vuln, indicators, temperature, use_corpus, merged_corpus=""):
    mitre = MITRE_MAP.get(vuln, ["Not mapped"])
    owasp = OWASP_MAP.get(vuln, "Not mapped")

    corpus_text = ""
    if use_corpus and merged_corpus:
        corpus_text = f"""
[OPTIONAL DEFENSIVE CORPUS]
This information is reference material from multiple sources.
You may use, expand, or challenge it using your own expert reasoning.

{merged_corpus}
"""

    prompt = f"""
You are a senior defensive cybersecurity analyst.

Think internally before responding.

Vulnerability Category:
{vuln}

Detected Indicators:
{indicators}

MITRE ATT&CK:
{mitre}

OWASP:
{owasp}

{corpus_text}

Provide a DEFENSIVE analysis with the following sections:

1. Overview of the attack class
2. Attacker goals and motivation
3. Risk and business impact
4. Defensive prevention & hardening
5. Secure configuration guidance
6. Monitoring and detection considerations

Rules:
- Defensive only
- No exploit payloads
- Prefer your own reasoning
- Use corpus only if helpful
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
def plot_payload_chart(findings):
    if not findings:
        return
    plt.figure()
    plt.bar(findings.keys(), [len(v) for v in findings.values()])
    plt.xticks(rotation=45, ha="right")
    plt.title("Detected Payload Classes")
    plt.tight_layout()
    st.pyplot(plt)

# ==================================================
# 📄 REPORT BUILDER
# ==================================================
def build_full_report(results, risk):
    lines = []
    lines.append("AI PAYLOAD AWARENESS & DEFENSIVE ANALYSIS REPORT")
    lines.append("=" * 65)
    lines.append(f"Overall Risk Score: {risk}")
    lines.append(f"Risk Level: {risk_level(risk)}\n")

    for vuln, analysis in results.items():
        lines.append("-" * 65)
        lines.append(f"VULNERABILITY: {vuln}")
        lines.append("-" * 65)
        lines.append(analysis)
        lines.append("")

    return "\n".join(lines)

# ==================================================
# ==================================================
# 🖥️ STREAMLIT UI
# ==================================================
st.set_page_config(page_title="AI Payload Awareness (Defensive)", layout="wide")
st.title("🛡️ AI Payload Awareness & Defensive Analyzer")

st.sidebar.header("Configuration")
temperature = st.sidebar.slider("LLaMA Temperature", 0.0, 1.0, 0.25, 0.05)

# ===== Corpus Toggles =====
use_internal = st.sidebar.checkbox("Use Internal Corpus (corpus2)", value=False)
use_uploaded_folder_zip = st.sidebar.checkbox("Upload Corpus Folder ZIP", value=False)
use_uploaded = st.sidebar.checkbox("Upload ZIP with Multiple Corpora", value=False)

# ===== Upload ZIP corpus files =====
uploaded_folder_zip = None
if use_uploaded_folder_zip:
    uploaded_folder_zip = st.sidebar.file_uploader("Upload Folder ZIP with Corpus TXT Files", type=["zip"])

uploaded_zip = None
if use_uploaded:
    uploaded_zip = st.sidebar.file_uploader("Upload ZIP with Multiple Corpus TXT Files", type=["zip"])

uploaded = st.file_uploader("Upload Recon / Log TXT", type=["txt"])

if uploaded:
    text = uploaded.read().decode("utf-8", errors="ignore")

    if st.button("Run Defensive Analysis"):
        with st.spinner("Analyzing defensively…"):
            findings = detect_payload_classes(text)
            risk = calculate_risk(findings)
            results = {}

            for vuln in findings:
                # ==============================
                # 🔹 Build Corpus Blocks
                # ==============================
                corpus_blocks = []

                if use_internal:
                    corpus_text = load_corpus(vuln)
                    if corpus_text:
                        corpus_blocks.append(f"[INTERNAL CORPUS]\n{corpus_text}")

                if use_uploaded_folder_zip and uploaded_folder_zip:
                    import zipfile, tempfile
                    with tempfile.TemporaryDirectory() as tmpdir:
                        with zipfile.ZipFile(uploaded_folder_zip) as z:
                            z.extractall(tmpdir)
                        path = os.path.join(tmpdir, f"{vuln}.txt")
                        if os.path.exists(path):
                            with open(path, "r", encoding="utf-8") as f:
                                corpus_blocks.append(f"[UPLOADED FOLDER CORPUS]\n{f.read()}")

                if use_uploaded and uploaded_zip:
                    import zipfile, tempfile
                    with tempfile.TemporaryDirectory() as tmpdir:
                        with zipfile.ZipFile(uploaded_zip) as z:
                            z.extractall(tmpdir)
                        path = os.path.join(tmpdir, f"{vuln}.txt")
                        if os.path.exists(path):
                            with open(path, "r", encoding="utf-8") as f:
                                corpus_blocks.append(f"[UPLOADED MULTI CORPUS]\n{f.read()}")

                # ==============================
                # 🔹 Merge Corpus
                # ==============================
                merged_corpus = "\n\n".join(corpus_blocks)
                use_corpus_flag = bool(corpus_blocks)

                # ==============================
                # 🔹 LLaMA Defensive Analysis
                # ==============================
                results[vuln] = llama_defensive_analysis(
                    vuln,
                    findings[vuln],
                    temperature,
                    use_corpus_flag,
                    merged_corpus
                )

        st.success("Analysis Complete")

        # ===== DASHBOARD =====
        st.subheader("📊 Visual Dashboard")
        plot_payload_chart(findings)

        st.metric("Overall Risk Score", risk)
        st.metric("Risk Level", risk_level(risk))

        # ===== REPORT =====
        report_txt = build_full_report(results, risk)

        st.subheader("📄 Structured Defensive Report")
        st.text_area("Report Output", report_txt, height=500, disabled=True)

        st.download_button(
            "Download Report (.txt)",
            report_txt,
            file_name="defensive_payload_awareness_report.txt"
        )
