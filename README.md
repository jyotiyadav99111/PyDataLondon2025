# PyData London 2025 – Agentic Threat‑Triage Demo 🚀

This folder contains a working demo of an **LLM‑powered agent** for triaging suspicious domains/IPs—built for the PyData London 2025 talk.

---

## 🛠️ Features

- Uses **LangChain’s function‑calling agent** for step‑by‑step analysis  
- Enrichment via **WHOIS**, **GeoIP**, and **VirusTotal** (or configurable equivalents)  
- Output includes a **score**, a **chain‑of‑thought explanation**, and JSON‑structured metadata  
- **Schema‑validated JSON** makes it easy to integrate into pipelines (e.g., Airflow, dbt)

---

## 📥 Getting Started

### 1. Clone the repo

```bash
git clone https://github.com/jyotiyadav99111/PyDataLondon2025.git
cd PyDataLondon2025/Code
```

### 2. Create a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate   # macOS/Linux
# On Windows: .venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Provide API keys

Create a `.env` file in this folder containing:

```
OPENAI_API_KEY=sk-...
VT_API_KEY=your_virustotal_key   # if using VirusTotal
```

These are loaded at runtime—no secrets in code.

---

## ▶️ Run the demo

```bash
python triage_agent.py --domain update-paypal-account[.]com
```

---

## 🛡️ Security & Responsible Use

- **Sensitive data** is neither logged nor stored by default
- All **external calls** (e.g. WHOIS, VT) pass through vetted APIs
- Use this in **offline/demo contexts only** unless you add production-grade governance

---

## 🗣️ Talk slide references

For context during the demo:

- Slides #8–10 show the **agent architecture** and enrichment steps  
- Slide #13 shows how the **LLM justifies its verdict**  
- Slide #16 corresponds to this live `triage_agent.py` demo

---

Thanks for checking it out—hope it inspires how agentic LLMs can automate triage in *any* data-heavy domain.

