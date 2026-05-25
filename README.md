# 👁️ OSINT-Argus — Multi-Agent OSINT Cybersecurity System

> **Agentic AI system that uses Open-Source Intelligence (OSINT) to analyse domains, emails and CVEs — protecting users from phishing, malware and infrastructure threats.**

Built with **LangGraph**, **LangChain** and **ChromaDB**. Designed as a modular, extensible multi-agent pipeline where each agent handles one specialised analysis task.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Agents](#agents)
- [Tools](#tools)
- [State & Routing](#state--routing)
- [Memory (ChromaDB)](#memory-chromadb)
- [Setup](#setup)
- [Configuration](#configuration)
- [Running the App](#running-the-app)
- [Example Output](#example-output)
- [Sprint Status](#sprint-status)
- [Roadmap — Sprint 3](#roadmap--sprint-3)
- [Tech Stack](#tech-stack)

---

## Overview

OSINT-Argus is a **supervisor-pattern multi-agent system** that accepts a free-form user input (a domain name, raw email, or URL), classifies it automatically, and routes it to the appropriate specialised agent. Each agent executes a defined set of OSINT tools and returns structured findings that are aggregated into a final risk report.

The goal is to give any user — without technical OSINT knowledge — a clear, actionable answer to the question: **"Is this domain / email / link safe?"**

The system outputs a **risk score (0–100)**, a **risk level** (LOW / MEDIUM / HIGH / CRITICAL), a plain-language summary, and a concrete **action recommendation** — ready to drive a traffic-light UI on any frontend.

---

## Architecture

```
User Input
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  Input Classifier  (regex-based, fast pre-check)        │
└────────────────────────┬────────────────────────────────┘
                         │ input_type: domain | email | unknown
                         ▼
┌─────────────────────────────────────────────────────────┐
│  OrchestratorAgent  (LLM-powered routing supervisor)    │
│  • Validates / overrides classifier result              │
│  • Sets next_agent in shared ArgusState                 │
│  • Drives adaptive email pipeline (EmailPipelineDecision)│
│  • Routes to OutputAgent when analysis is complete      │
└────────────┬───────────────────────┬────────────────────┘
             │                       │
          domain                   email
             ▼                       ▼
┌────────────────────┐     ┌─────────────────────────────┐
│   DomainAgent      │     │   EmailAgent                │
│   (AgentExecutor + │     │   Pass 1 — Extraction       │
│    6 OSINT tools)  │     │   (headers, URLs, domains)  │
└────────┬───────────┘     │   Pass 2 — Judgement        │
         │                 │   (VirusTotal + LLM report) │
         │                 └──────────────┬──────────────┘
         │                                │
         └──────────┬─────────────────────┘
                    │ both routes back to OrchestratorAgent
                    ▼
┌─────────────────────────────────────────────────────────┐
│  OutputAgent  (LLM structured output)                   │
│  • Aggregates all findings                              │
│  • Produces risk_score (0–100), risk_level, summary     │
│  • Generates action_advice for the user                 │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  ArgusState  (shared LangGraph state, TypedDict)        │
│  • findings, risk_score, risk_level                     │
│  • summary, action_advice, memory_context               │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  ChromaDB  (persistent vector store)                    │
│  • Saves analysis results for future RAG context        │
└─────────────────────────────────────────────────────────┘
```

The graph is compiled with **LangGraph `StateGraph`** and uses conditional edges so that the orchestrator's routing decision (`next_agent`) determines which agent node runs next. Every analysis agent routes back to the orchestrator; the orchestrator decides when enough data is gathered and routes to `OutputAgent`.

---

## Project Structure

```
MultiAgent-OSINT-Argus/
│
├── app/
│   ├── main.py                    # Entry point — reads input, builds state, invokes graph
│   ├── graph.py                   # LangGraph StateGraph — nodes, edges, entry point
│   ├── state.py                   # ArgusState TypedDict — shared state schema
│   ├── config.py                  # Loads .env — API keys, base URL, model name
│   │
│   ├── agents/
│   │   ├── base_agent.py          # Abstract BaseAgent — defines run(state) interface
│   │   ├── orchestrator_agent.py  # LLM routing supervisor + adaptive email pipeline
│   │   ├── domain_agent.py        # Domain OSINT analysis via 6 tools + LLM report
│   │   ├── email_agent.py         # Email phishing analysis — Pass 1 extraction, Pass 2 judgement
│   │   └── output_agent.py        # Final risk report — score, level, summary, action advice
│   │
│   ├── models/
│   │   ├── llm.py                 # ChatOpenAI factory — configured LLM instance
│   │   └── router.py              # Pydantic models: RouteDecision, EmailPipelineDecision, OutputReport
│   │
│   ├── memory/
│   │   └── chroma_memory.py       # ChromaDB client — save_analysis() + search_memory()
│   │
│   └── tools/
│       ├── classifier.py          # Regex classifier — fast pre-routing before LLM
│       ├── whois_tool.py          # WHOIS lookup — registrar, dates, name servers
│       ├── dns_tool.py            # DNS records — A, MX, NS
│       ├── domain_tools.py        # SSL, SPF/DMARC/DKIM, URLhaus, crt.sh
│       └── email_tools.py         # URL extraction, header parsing, Reply-To check, VirusTotal
│
├── app/email_test.txt             # Sample phishing email for local testing
├── .env                           # Local secrets (not committed)
├── .env.example                   # Template for required environment variables
├── requirements.txt               # Python dependencies
└── README.md                      # This file
```

---

## Agents

### `BaseAgent` — Abstract Interface

Every agent inherits from `BaseAgent` and must implement one method:

```python
def run(self, state: ArgusState) -> ArgusState
```

The agent receives the full shared state, performs its work, appends its findings to `state["findings"]`, and returns the mutated state. This contract guarantees composability inside the LangGraph graph.

---

### `OrchestratorAgent` — Routing Supervisor
**File:** `app/agents/orchestrator_agent.py`

The central coordinator. Handles two distinct routing modes depending on the conversation stage:

**Initial routing** (first call): Uses `with_structured_output(RouteDecision)` to classify the input and set `next_agent`. Initialises email pipeline fields if the input is an email.

**Email pipeline routing** (subsequent calls during email analysis): Uses `with_structured_output(EmailPipelineDecision)` to adaptively decide after each domain scan whether to scan another domain, trigger EmailAgent Pass 2 (judgement), or skip straight to output if the threat is already critical.

**Post-domain routing**: After `DomainAgent` completes for a direct domain input, the orchestrator detects the finished finding via `_agent_ran()` and routes to `OutputAgent` — preventing re-routing loops.

**Supported routes:**

| Trigger | Next Agent |
|---------|------------|
| Domain input, first call | `domain` |
| Domain input, DomainAgent already ran | `output` |
| Email input, more domains to scan | `domain` |
| Email input, enough data for judgement | `email` (Pass 2) |
| Email input, critical signal found | `output` (skip Pass 2) |
| Email Pass 2 complete | `output` |
| Unknown input | `output` |

---

### `DomainAgent` — Full Domain OSINT Analysis
**File:** `app/agents/domain_agent.py`

Built on a **LangChain `AgentExecutor`** with `create_tool_calling_agent`. Supports both standalone domain analysis and being called mid-pipeline for individual domains inside an email scan (reads `state.get("current_domain") or state["user_input"]`).

**Mandatory execution order (enforced via system prompt):**
1. `run_whois` → domain age, registrar, expiry
2. `run_dns_lookup` → A, MX, NS records
3. `run_crtsh` → subdomain enumeration via Certificate Transparency
4. `run_urlhaus` → malware database check (abuse.ch)
5. `run_spf_dmarc_check` → email security posture (SPF, DMARC, DKIM)
6. `run_ssl_check` → TLS certificate validity and expiry

After all tools have run, the LLM produces a structured JSON report:

```json
{
  "threat_indicators": ["..."],
  "exposure_findings": ["..."],
  "summary": "2-3 sentence overall assessment"
}
```

---

### `EmailAgent` — Phishing Analysis (Two-Pass)
**File:** `app/agents/email_agent.py`

Analyses raw email content in two passes, orchestrated adaptively by the `OrchestratorAgent`.

**Pass 1 — Extraction** (`_run_pass1`): Pure Python, no LLM call. Parses email headers, extracts all URLs, derives domains to scan, detects Reply-To mismatches. Writes `email_extraction` and `domains_to_scan` to state so the orchestrator can drive domain scans.

**Pass 2 — Judgement** (`_run_pass2`): LLM-powered. Receives the domain analysis findings already gathered by `DomainAgent`, calls `check_virustotal_domain` on the sender domain, then produces a JSON content assessment:

```json
{
  "phishing_indicators": ["Dringlichkeit", "Impersonation", "Reply-To Mismatch"],
  "content_risk": "HIGH",
  "sender_assessment": "Domain paypa1-verify.ru ist bekannte Phishing-Domain",
  "summary": "..."
}
```

---

### `OutputAgent` — Final Risk Report
**File:** `app/agents/output_agent.py`

The terminal agent. Collects every finding from `state["findings"]`, formats them into a compact prompt, and uses `with_structured_output(OutputReport)` to produce a fully typed final report.

**Output written to state:**

| Field | Type | Description |
|-------|------|-------------|
| `risk_score` | `int` (0–100) | Numeric risk — maps directly to frontend progress bar or gauge |
| `risk_level` | `"LOW" \| "MEDIUM" \| "HIGH" \| "CRITICAL"` | Traffic-light level |
| `summary` | `str` | Plain-language summary for end users (no jargon) |
| `action_advice` | `str` | Concrete recommendation: what to do right now |
| `indicators` | `List[str]` | Top 3–5 key risk factors found |

**Traffic-light mapping for frontend:**

| Score | Level | Colour |
|-------|-------|--------|
| 0–33 | LOW | 🟢 Green — no action needed |
| 34–66 | MEDIUM | 🟡 Yellow — proceed with caution |
| 67–84 | HIGH | 🔴 Red — action recommended |
| 85–100 | CRITICAL | 🚨 Red — act immediately |

**Example action_advice per level:**
- **LOW:** "Diese Domain ist unbedenklich. Du kannst sie besuchen."
- **MEDIUM:** "Öffne den Link nicht direkt. Navigiere stattdessen manuell zur offiziellen Website."
- **HIGH:** "Besuche diese Domain nicht. Lösche die E-Mail und melde sie als Spam."
- **CRITICAL:** "Sofort handeln: Klicke keine Links, öffne keine Anhänge. Melde die E-Mail an deine IT-Abteilung."

---

## Tools

All tools are registered as **LangChain `@tool`** decorated functions.

### `run_whois` — WHOIS Lookup
**File:** `app/tools/whois_tool.py`

Queries public WHOIS databases for domain registration metadata. Returns registrar, creation date, expiration date, and name servers. Freshly registered domains are a common phishing indicator.

---

### `run_dns_lookup` — DNS Record Lookup
**File:** `app/tools/dns_tool.py`

Resolves `A`, `MX`, and `NS` records using `dnspython`. Missing MX records can indicate a domain not intended for email but used for spoofing.

---

### `run_ssl_check` — TLS Certificate Analysis
**File:** `app/tools/domain_tools.py`

Direct TLS handshake on port 443 using Python's `ssl` module with `certifi`. Detects expired certs, certs expiring within 14/30 days, self-signed certs, and WAF/TLS-interception (Cloudflare, Myra).

**Verdicts:** `OK` | `WARNING` | `CRITICAL` | `UNKNOWN`

---

### `run_spf_dmarc_check` — Email Security Posture
**File:** `app/tools/domain_tools.py`

Checks whether a domain is protected against email spoofing via SPF, DMARC (`_dmarc.<domain>`), and DKIM (probes 7 common selectors). A missing or weak configuration means anyone can spoof `@<domain>` emails.

**Verdicts:** `SECURE` | `EXPOSED`

---

### `run_urlhaus` — Malware Database Check
**File:** `app/tools/domain_tools.py`

Queries the **URLhaus API** (abuse.ch) — no API key required. Extracts whether the domain is a known malware host, active/total malicious URL counts, malware family tags, and blacklist status.

**Verdicts:** `CLEAN` | `MALICIOUS` | `UNKNOWN`

---

### `run_crtsh` — Subdomain Enumeration via Certificate Transparency
**File:** `app/tools/domain_tools.py`

Queries `crt.sh` for all SSL certificates ever issued for a domain. Caps at 100 certs, returns top 20 unique subdomains. Flags domains with more than 15 subdomains as elevated attack surface.

---

### Email Tools
**File:** `app/tools/email_tools.py`

A set of pure-Python helper functions used by `EmailAgent` Pass 1 plus one LangChain tool:

| Function | Description |
|----------|-------------|
| `extract_urls(text)` | Regex-based URL extraction from raw email body |
| `extract_domain_from_url(url)` | Strips scheme and path, returns bare domain |
| `parse_email_headers(text)` | Extracts From, To, Subject, Reply-To, Date |
| `extract_sender_domain(from_header)` | Parses `Name <user@domain>` and `user@domain` formats |
| `check_reply_to_mismatch(headers)` | Detects Reply-To ≠ From domain — classic phishing signal |
| `check_virustotal_domain` | `@tool` — VirusTotal v3 domain reputation (requires `VT_API_KEY`) |

---

## State & Routing

### `ArgusState` — Shared Graph State
**File:** `app/state.py`

```python
class ArgusState(TypedDict):
    # Sprint 1
    user_input:     str
    input_type:     str
    current_agent:  str
    next_agent:     str
    findings:       List[Dict[str, Any]]
    risk_score:     Optional[int]
    summary:        Optional[str]
    memory_context: Optional[str]

    # Sprint 2 — Email pipeline
    email_pass:       int                      # 0=init | 1=extraction done | 2=judgement done
    domains_to_scan:  List[str]                # from EmailAgent Pass 1
    domains_scanned:  List[str]                # updated by Orchestrator after each DomainAgent run
    current_domain:   Optional[str]            # domain currently being analysed by DomainAgent
    email_extraction: Optional[Dict[str, Any]] # Pass 1 result

    # Sprint 2 — OutputAgent
    risk_level:    Optional[str]   # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    action_advice: Optional[str]   # concrete action recommendation for the user
```

### Pydantic Models
**File:** `app/models/router.py`

**`RouteDecision`** — initial routing by the Orchestrator:
```python
class RouteDecision(BaseModel):
    input_type: Literal["domain", "email", "url", "unknown"]
    next_agent:  Literal["domain", "email", "cve", "output"]
    reasoning:   str
```

**`EmailPipelineDecision`** — adaptive email pipeline routing:
```python
class EmailPipelineDecision(BaseModel):
    action:        Literal["scan_domain", "proceed_to_judgement", "proceed_to_output"]
    target_domain: Optional[str]                    # only for action=scan_domain
    reasoning:     str
    confidence:    Literal["LOW", "MEDIUM", "HIGH"]
```

**`OutputReport`** — final risk report from OutputAgent:
```python
class OutputReport(BaseModel):
    risk_score:    int                                          # 0–100, validated
    risk_level:    Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    explanation:   str                                          # technical, for experts
    summary:       str                                          # plain language, for users
    action_advice: str                                          # concrete recommendation
    indicators:    List[str]                                    # top 3–5 risk factors
```

### Input Classifier
**File:** `app/tools/classifier.py`

Lightweight regex pre-classifier before the LLM call.

| Pattern | Classification |
|---------|----------------|
| `user@domain.tld` | `email` |
| `domain.tld` (no `@`) | `domain` |
| Anything else | `unknown` |

---

## Memory (ChromaDB)

**File:** `app/memory/chroma_memory.py`

Persistent ChromaDB client stored in `./chroma_db/`. The collection `argus_memory` stores past analysis results as documents, enabling **Retrieval-Augmented Generation (RAG)** in future runs.

```python
save_analysis(query="example.com", content="<full analysis JSON>")
results = search_memory(query="example.com")  # top 3 nearest neighbours
```

> Active RAG injection into agent prompts is planned for Sprint 3.

---

## Setup

### Prerequisites

- Python 3.11+
- Access to an OpenAI-compatible API (e.g. [SAIA / Academic Cloud](https://chat-ai.academiccloud.de))
- Optional: VirusTotal API key (free tier sufficient for EmailAgent)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/MultiAgent-OSINT-Argus.git
cd MultiAgent-OSINT-Argus

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up environment variables
cp .env.example .env
# Edit .env with your actual API keys
```

---

## Configuration

```env
# Required — OpenAI-compatible API
OPENAI_API_KEY=your_api_key_here
OPENAI_BASE_URL=https://chat-ai.academiccloud.de/v1
MODEL_NAME=mistral-large-instruct

# Required for EmailAgent Pass 2
VT_API_KEY=your_virustotal_key

# Future — Sprint 3
SHODAN_API_KEY=your_shodan_key
```

**Notes:**
- `OPENAI_BASE_URL` supports any OpenAI-compatible endpoint. Developed and tested against the **German Academic Cloud (SAIA)**.
- LLM timeout is set to **120 seconds** with 2 retries — adjusted from Sprint 1's 30s/1 retry after encountering SAIA latency issues.
- `VT_API_KEY` is now actively used by EmailAgent Pass 2 for sender domain reputation checks.

---

## Running the App

```bash
python -m app.main
```

```
╔══════════════════════════════════════════════╗
║       👁️  OSINT-Argus Multi-Agent            ║
║     DomainAgent · EmailAgent · CVEAgent      ║
║          RAG Memory · LangGraph              ║
╚══════════════════════════════════════════════╝

📝 Eingabe (leere Zeile zum Abschließen):
```

Multi-line input is supported — paste a full email, then press Enter on an empty line to submit. For pipe mode (`cat email.txt | python -m app.main`), EOF is handled automatically.

**Supported inputs:**

| Input | Routed To | Status |
|-------|-----------|--------|
| `example.com` | DomainAgent → OutputAgent | ✅ Working |
| `sub.example.com` | DomainAgent → OutputAgent | ✅ Working |
| Raw email with headers | EmailAgent (2-pass) → OutputAgent | ✅ Working |
| CVE topic / keyword | CVEAgent | 🔜 Sprint 3 |

---

## Example Output

### Domain Analysis — `example.com`

```python
# state["findings"] (abbreviated)
[
  {
    "agent": "OrchestratorAgent",
    "decision": { "input_type": "domain", "next_agent": "domain", "reasoning": "..." }
  },
  {
    "agent": "DomainAgent",
    "domain": "example.com",
    "ssl":            { "verdict": "OK", "days_until_expiry": 248 },
    "email_security": { "verdict": "EXPOSED", "email_spoofing_possible": True },
    "urlhaus":        { "verdict": "CLEAN" },
    "ai_analysis": {
      "threat_indicators": [],
      "exposure_findings": ["Kein SPF-Record", "Kein DMARC-Record"],
      "summary": "example.com ist eine IANA-Reservierungsdomain..."
    }
  },
  {
    "agent":        "OutputAgent",
    "risk_score":   18,
    "risk_level":   "LOW",
    "explanation":  "Die Domain example.com ist eine IANA-Reservierungsdomain...",
    "summary":      "Diese Domain ist unbedenklich und wird von IANA verwaltet.",
    "action_advice":"Keine Aktion erforderlich. Du kannst diese Domain besuchen.",
    "indicators":   ["Kein SPF-Record konfiguriert", "Kein DMARC-Record vorhanden"]
  }
]
```

### Email Analysis — Phishing Mail

```
═══════════════════════════════════════════════════════════
  🚨  OSINT-Argus Risikobericht
═══════════════════════════════════════════════════════════
  Risiko-Score : 94/100  [CRITICAL]
  Zusammenfassung:
    Diese E-Mail ist eine klassische PayPal-Phishing-Mail.
    Der Absender nutzt eine gefälschte Domain (paypa1-verify.ru)
    und der Reply-To zeigt auf eine andere verdächtige Domain.

  🎯 Empfehlung:
    Sofort handeln: Klicke keine Links, öffne keine Anhänge.
    Lösche die E-Mail und melde sie als Spam. Falls du bereits
    auf den Link geklickt hast, ändere sofort dein Passwort.

  ⚠️  Indikatoren:
     • Absender-Domain paypa1-verify.ru als MALICIOUS eingestuft (VirusTotal)
     • Reply-To Mismatch: account-helpdesk.xyz ≠ paypa1-verify.ru
     • Dringlichkeitstaktik: "Konto wird gesperrt in 24 Stunden"
     • Impersonation: gibt sich als PayPal-Sicherheitsteam aus
     • Verdächtiger Login-Link auf account-verify.xyz
═══════════════════════════════════════════════════════════
```

---

## Sprint Status

### ✅ Sprint 1 — Base Setup (Complete)

| Feature | Status | Notes |
|---------|--------|-------|
| LangGraph `StateGraph` | ✅ | `OrchestratorAgent` + `DomainAgent` |
| `ArgusState` TypedDict | ✅ | Full state contract |
| WHOIS tool | ✅ | `python-whois` |
| DNS tool | ✅ | `dnspython`, A/MX/NS |
| SSL check | ✅ | WAF detection, expiry warnings |
| SPF/DMARC/DKIM check | ✅ | Spoofing exposure detection |
| URLhaus check | ✅ | abuse.ch, no key required |
| Subdomain enumeration (crt.sh) | ✅ | Certificate Transparency |
| Input Classifier (regex) | ✅ | Fast pre-routing |
| OrchestratorAgent (LLM routing) | ✅ | `RouteDecision` structured output |
| DomainAgent (AgentExecutor) | ✅ | 6 tools + LLM JSON report |
| ChromaDB connected | ✅ | Persistent `argus_memory` collection |
| Model selection & evaluation | ✅ | Mistral Large via SAIA |

### ✅ Sprint 2 — Email Pipeline + Output (Complete)

| Feature | Status | Notes |
|---------|--------|-------|
| `EmailAgent` Pass 1 — header & URL extraction | ✅ | Pure Python, no LLM call |
| `EmailAgent` Pass 2 — LLM phishing judgement | ✅ | VirusTotal + content analysis |
| `email_tools.py` — URL/header/VirusTotal utilities | ✅ | `check_virustotal_domain` as LangChain `@tool` |
| `EmailPipelineDecision` Pydantic model | ✅ | Adaptive orchestration |
| Adaptive Orchestrator email routing | ✅ | LLM decides scan vs. judge vs. skip |
| Multi-domain scanning within email pipeline | ✅ | Orchestrator loops DomainAgent per domain |
| `DomainAgent` — `current_domain` support | ✅ | Works standalone and inside email pipeline |
| `OutputAgent` — final risk report | ✅ | `OutputReport` structured output |
| Risk score (0–100) + risk level | ✅ | Frontend-ready traffic-light mapping |
| Plain-language summary | ✅ | Jargon-free, for end users |
| Action advice | ✅ | Specific per input type and risk level |
| `graph.py` — full pipeline wired | ✅ | domain/email → orchestrator → output → END |
| LLM timeout increased to 120s | ✅ | Handles SAIA latency |
| Multi-line CLI input + pipe mode | ✅ | Paste full emails, or `cat file \| python -m app.main` |

---

## Roadmap — Sprint 3

### CVEAgent
- NVD NIST API integration (`nvd.nist.gov/rest/json`)
- MITRE ATT&CK technique mapping
- CVSS severity enrichment
- Routing from OrchestratorAgent for CVE IDs and vulnerability topics

### System-wide improvements
- Active RAG injection from ChromaDB into agent prompts
- Shodan integration in DomainAgent for infrastructure scanning
- End-to-end test suite covering all 3 input scenarios
- Frontend (REST API or Streamlit) consuming `risk_score`, `risk_level`, `action_advice`

---

## Tech Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Agent orchestration | [LangGraph](https://github.com/langchain-ai/langgraph) | latest |
| LLM tooling | [LangChain](https://github.com/langchain-ai/langchain) | latest |
| LLM provider | OpenAI-compatible API (SAIA / Academic Cloud) | — |
| Default model | `mistral-large-instruct` | — |
| Vector store | [ChromaDB](https://www.trychroma.com/) | latest |
| WHOIS | `python-whois` | latest |
| DNS resolution | `dnspython` | latest |
| HTTP client | `httpx` | latest |
| TLS inspection | Python `ssl` + `certifi` | stdlib |
| Schema validation | `pydantic` | v2 |
| Config management | `python-dotenv` | latest |

---

## License

MIT — see `LICENSE` for details.

---

*OSINT-Argus is an academic project developed as part of an Agentic AI course. It is intended for educational and defensive security research purposes only.*