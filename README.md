# 🛡️ Cyber Defense Intelligence Toolkit

A **blue-team–focused, ethical security analysis toolkit** that combines control posture assessment, attack signal awareness, and weaponization risk modeling into a single, cohesive defensive workflow.

This toolkit is designed for **security architects, blue teams, AppSec engineers, SOC analysts, and GRC professionals** who want structured, explainable, and audit-friendly security intelligence — without exploit generation or offensive payloads.

***Corpus txt count: 60 txts
***Knowledge in each corpus can be added if need.

---

## 📦 Toolkit Components

This repository contains **three independent but complementary tools**, each with its own optional defensive knowledge corpus (provided as ZIP files).

### 1️⃣ SCWLA – Security Control Weakness & Landscape Analyzer

**Purpose:**
Assess the presence, gaps, and weaknesses of defensive security controls based on recon or scan output.

**Key Capabilities:**

* Rule-based detection of security controls (WAF, Auth, TLS, Logging, IR, etc.)
* Line-level evidence for each detected control
* Optional internal defensive corpus grounding
* LLaMA-based defensive-only analysis
* LLaMA may challenge or expand corpus grounding if choose corpus as helper
* LLaMA may work itself if don't choose corpus
* Audit-friendly TXT report output

**Use cases:**

* Security architecture reviews
* Pre-audit readiness checks
* Defensive control gap analysis

**Corpus:** `corpus_scwla.zip`
***Knowledge in each corpus can be added if need.
---

### 2️⃣ EAPADA – AI Payload Awareness & Defensive Analyzer

**Purpose:**
Identify **attack class signals and malicious intent indicators** (not exploits) within recon, logs, or scan data.

**Key Capabilities:**

* Detection of payload *classes* (Injection, Auth abuse, Logic flaws, DoS indicators, etc.)
* MITRE ATT&CK and OWASP Top 10 contextual mapping
* Lightweight risk scoring for defensive prioritization
* Optional defensive corpus grounding
* LLaMA-based defensive-only analysis
* LLaMA may challenge or expand corpus grounding if choose corpus as helper
* LLaMA may work itself if don't choose corpus
* Visual dashboard + structured TXT report

**What it is NOT:**

* ❌ Exploit generator
* ❌ Payload crafting tool

**Use cases:**

* SOC alert triage
* AppSec log review
* Defensive threat awareness

**Corpus:** `corpus_eapada.zip`
***Knowledge in each corpus can be added if need.
---

### 3️⃣ VWPA – Vulnerability Weaponization Possibility Analyzer

**Purpose:**
Analyze **why certain vulnerabilities are valuable to attackers** and how they could be *weaponized*, strictly from a defensive and strategic perspective.

**Key Capabilities:**

* Detection of pre-exploit vulnerability conditions
* Weaponization value modeling (no exploits, no payloads)
* Chaining and attacker ROI analysis
* Early warning indicators for defenders
* LLaMA-based defensive-only analysis
* LLaMA may challenge or expand corpus grounding if choose corpus as helper
* LLaMA may work itself if don't choose corpus
* Strategic hardening and control improvement guidance

**Philosophy:**

> *Think like an attacker, respond like a defender.*

**Use cases:**

* Threat modeling
* Risk prioritization
* Security strategy and roadmap planning

**Corpus:** `corpus_vwpa.zip`
***Knowledge in each corpus can be added if need.
---

## 🧠 How the Toolkit Fits Together

| Tool   | Core Question Answered                                         |
| ------ | -------------------------------------------------------------- |
| SCWLA  | *What defensive controls do we have, and how strong are they?* |
| EAPADA | *What kinds of attack behaviors or probes are we seeing?*      |
| VWPA   | *Which weaknesses are most likely to be weaponized — and why?* |

Together, they form a **defensive intelligence loop**:

1. Control posture awareness
2. Attack signal awareness
3. Weaponization risk prioritization

---

## 🚀 Getting Started

### Requirements

* Python 3.9+
* Streamlit
* `huggingface_hub`
* Matplotlib

```bash
pip install streamlit huggingface_hub matplotlib
```

### Environment Variable (Required)

For security reasons, **do not hard-code tokens**.

```bash
export HF_TOKEN=hf_xxxxxxxxxxxxx
# or on Windows
setx HF_TOKEN hf_xxxxxxxxxxxxx
```

### Running a Tool

```bash
streamlit run scwla_corpus.py
streamlit run eapada_corpus.py
streamlit run vwpa_corpus.py
```

Unzip the corresponding corpus ZIP into the expected directory before running.

---

## 🔐 Ethical & Defensive Scope

This toolkit is:

* ✅ Defensive-only
* ✅ Ethical by design
* ✅ Safe for blue-team and enterprise environments

It intentionally avoids:

* Exploit steps
* Payload construction
* Weapon development

All AI reasoning is constrained to **defensive analysis, risk understanding, and mitigation guidance**.

---

## 📄 Output & Reporting

Each tool produces:

* On-screen structured analysis
* Downloadable `.txt` reports suitable for:

  * Audits
  * Architecture reviews
  * Incident documentation

---

## 🧭 Intended Audience

* Blue Team Analysts
* SOC Engineers
* Application Security Engineers
* Security Architects
* GRC & Audit Teams
* Defensive Security Researchers

---

## ⚠️ Disclaimer

This toolkit is intended **solely for defensive security analysis and education**. It must only be used on systems you own or have explicit authorization to assess.

---

## 📬 Contribution & Extension

The toolkit is modular by design:

* New controls, classes, or vulnerability models can be added easily
* Corpus files allow domain-specific defensive knowledge

Pull requests focused on **defensive improvements** are welcome.

---

🛡️ *Defensive security is not about knowing every exploit — it’s about understanding risk, intent, and control.*

---

👤 Author
Khin La Pyae Woon
AI-Enhanced Ethical Hacking | Cybersecurity | Digital Forensic | Analyze | Developing

🌐 Portfolio: https://khinlapyaewoon-cyberdev.vercel.app
🔗 LinkedIn: www.linkedin.com/in/khin-la-pyae-woon-ba59183a2
💬 WhatsApp: https://wa.me/qr/MJYX74CQ5VA4D1

