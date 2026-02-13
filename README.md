# 🛡️ Cyber Defense Intelligence Toolkit

A **blue-team–focused, ethical security analysis toolkit** that combines control posture assessment, attack signal awareness, and weaponization risk modeling into a single, cohesive defensive workflow.

This toolkit is designed for **security architects, blue teams, AppSec engineers, SOC analysts, and GRC professionals** who want structured, explainable, and audit-friendly security intelligence — without exploit generation or offensive payloads.

---

## 📊 Project Overview

- **Corpus TXT Count:** 60+ defensive knowledge files  
- **Extensible Knowledge Design:** Corpus files can be expanded or customized  
- **AI Engine:** LLaMA via Hugging Face  
- **Architecture:** Rule-based detection + Structured AI reasoning + Optional knowledge grounding  

The system is modular, explainable, and safe for enterprise defensive environments.

---

# 📦 Toolkit Components

This repository contains **three independent but complementary tools**, each with optional defensive corpus support.

---

## 1️⃣ SCWLA – Security Control Weakness Logic Analyzer

### 🎯 Purpose
Assess the presence, gaps, and weaknesses of defensive security controls based on recon or scan output.

### 🔎 Key Capabilities

- Rule-based detection of security controls (WAF, Authentication, TLS, Logging, IR, etc.)
- Line-level evidence extraction
- Optional corpus-based grounding
- LLaMA-based defensive-only reasoning
- Structured `.txt` report output (audit-friendly)

### 🧪 Use Cases

- Security architecture reviews
- Pre-audit readiness checks
- Defensive control gap analysis

**Corpus:** `corpus_scwla.zip`

---

## 2️⃣ EAPADA – AI Payload Awareness & Defensive Analyzer

### 🎯 Purpose
Identify **attack class signals and malicious intent indicators** (not exploits) within recon data, logs, or scan output.

### 🔎 Key Capabilities

- Detection of payload *classes*:
  - Injection signals
  - Authentication abuse
  - Logic manipulation
  - DoS indicators
  - Enumeration patterns
- MITRE ATT&CK contextual mapping
- OWASP Top 10 contextual mapping
- Lightweight defensive risk scoring
- Optional corpus grounding
- Visual dashboard + structured `.txt` report

### 🚫 What It Is NOT

- ❌ Exploit generator  
- ❌ Payload crafting tool  
- ❌ Weapon builder  

### 🧪 Use Cases

- SOC alert triage
- AppSec log review
- Threat signal awareness

**Corpus:** `corpus_eapada.zip`

---

## 3️⃣ VWPA – Vulnerability Weaponization Projection Analyzer

### 🎯 Purpose
Analyze **why vulnerabilities are valuable to attackers** and how they could be weaponized — strictly from a defensive and strategic perspective.

### 🔎 Key Capabilities

- Detection of vulnerability preconditions
- Strategic weaponization value modeling (no exploit steps)
- Attack chaining and attacker ROI reasoning
- Early warning indicators
- Defensive hardening guidance
- Optional corpus grounding

### 🧠 Philosophy

> **Think like an attacker. Respond like a defender.**

### 🧪 Use Cases

- Threat modeling
- Risk prioritization
- Security roadmap planning

**Corpus:** `corpus_vwpa.zip`

---

# 🧠 AI Knowledge Modes (Flexible Corpus Options)

Each tool supports **four knowledge configurations**, allowing flexible defensive reasoning:

---

## 🔹 Option 1 — Independent AI Mode (No Corpus)

- No corpus selected
- LLaMA reasons using its pretrained knowledge
- Useful for general analysis
- Best for quick assessments or research scenarios
**Behavior:**  
LLaMA reasons independently.
---

## 🔹 Option 2 — Internal Corpus Mode

- Uses built-in corpus directory (e.g., `corpus_scwla/`)
- Ideal for standardized internal defensive knowledge
- Organization-controlled documentation
- AI uses corpus as enrichment, not blind grounding
**Behavior:**  
LLaMA enriches its reasoning using internal corpus  
AND still reasons independently beyond corpus content.
---

## 🔹 Option 3 — Uploaded Corpus (ZIP)

- Upload custom corpus ZIP file
- Extracts `.txt` files dynamically
- Useful for:
  - Client-specific documentation
  - Audit references
  - Project-based knowledge sets
**Behavior:**  
LLaMA enriches its reasoning using uploaded corpus  
AND reasons independently beyond corpus content.
---

## 🔹 Option 4 — Uploaded Multi-Corpora (ZIP)

- Upload custom corpora ZIP which contains multi corpus
- Extract all files dynamically
**Behavior:**  
LLaMA enriches its reasoning using uploaded corpora  
AND reasons independently beyond corpora content.

---

# When multiple options are selected:
**Behavior:**

1. All selected sources are merged
2. LLaMA receives merged corpus context
3. LLaMA enriches reasoning using combined knowledge
4. LLaMA still reasons independently and may expand beyond corpus content

```python
merged_corpus = "\n\n".join(corpus_blocks)
use_corpus_flag = bool(corpus_blocks)
```

- AI uses combined defensive knowledge
- Best for enterprise environments with layered documentation

---

# 🧠 Important Reasoning Design Principle

This toolkit does **NOT** force strict grounding.

If any corpus option is selected:

- LLaMA uses corpus as enrichment
- LLaMA may expand, challenge, or refine corpus knowledge
- LLaMA still performs independent reasoning

If all options are selected:

1. Corpus sources are merged first  
2. LLaMA receives unified defensive knowledge  
3. LLaMA enriches reasoning  
4. LLaMA reasons independently  

Corpus is **supportive knowledge**, not a restriction layer.

---

# 🔄 Defensive Intelligence Loop



 SCWLA  | What defensive controls exist, and how strong are they?
 EAPADA | What attack behaviors or malicious signals are present?
 VWPA   | Which weaknesses are most likely to be weaponized — and why?

Together they provide:

1. **Control posture awareness**
2. **Attack signal awareness**
3. **Weaponization risk prioritization**

Structured. Explainable. Defensive.

---

# 🚀 Getting Started

## Requirements

- Python 3.9+
- Streamlit
- huggingface_hub
- matplotlib

```bash
pip install streamlit huggingface_hub matplotlib
```

---

## 🔐 Environment Variable (Required)

Never hard-code API tokens.

### macOS / Linux
```bash
export HF_TOKEN=hf_xxxxxxxxxxxxx
```

### Windows
```bash
setx HF_TOKEN hf_xxxxxxxxxxxxx
```

---

## ▶ Running a Tool

```bash
streamlit run scwla_corpus.py
streamlit run eapada_corpus.py
streamlit run vwpa_corpus.py
```

Before running:
- Unzip internal corpus folders if required
- Or upload corpus ZIP inside the UI

---

# 🔒 Ethical & Defensive Scope

This toolkit is:

- ✅ Defensive-only
- ✅ Ethical by design
- ✅ Enterprise-safe
- ✅ Audit-friendly

It intentionally avoids:

- Exploit instructions
- Payload construction
- Weapon development
- Attack automation

AI reasoning is strictly constrained to:

- Risk analysis
- Strategic understanding
- Defensive mitigation guidance

---

# 📄 Output & Reporting

Each tool produces:

- On-screen structured analysis
- Downloadable `.txt` reports suitable for:
  - Security audits
  - Architecture documentation
  - Incident records
  - Risk assessments

---

# 🧭 Intended Audience

- Blue Team Analysts
- SOC Engineers
- Application Security Engineers
- Security Architects
- GRC & Audit Teams
- Defensive Security Researchers

---

# 🧩 Extensibility

The toolkit is modular and extensible:

- Add new detection rules
- Expand vulnerability modeling
- Extend corpus knowledge base
- Integrate into SOC workflows
- Add custom scoring logic

Pull requests focused on **defensive improvements** are welcome.

---

# ⚠️ Disclaimer

This toolkit is intended **solely for defensive security analysis and education**.

Use only on systems you own or have explicit authorization.

The author is not responsible for misuse.

---

# 👤 Author

**Khin La Pyae Woon**  
AI-Enhanced Ethical Hacking | Cybersecurity | Digital Forensic | Analyze | Developing 

🌐 Portfolio:  
https://khinlapyaewoon-cyberdev.vercel.app  

🔗 LinkedIn:  
https://www.linkedin.com/in/khin-la-pyae-woon-ba59183a2  

💬 WhatsApp:  
https://wa.me/qr/MJYX74CQ5VA4D1  

---

🛡️ *Defensive security is not about knowing every exploit — it’s about understanding risk, intent, and control.*
