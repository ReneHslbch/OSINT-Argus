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
- [Roadmap — Sprint 2](#roadmap--sprint-2)
- [Tech Stack](#tech-stack)

---

## Overview

OSINT-Argus is a **supervisor-pattern multi-agent system** that accepts a free-form user input (a domain name, email address, or URL), classifies it automatically, and routes it to the appropriate specialised agent. Each agent executes a defined set of OSINT tools and returns structured findings that are aggregated into a final risk report.

The goal is to give any user — without technical OSINT knowledge — a clear, actionable answer to the question: **"Is this domain / email / link safe?"**

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
│  • Uses structured output (RouteDecision Pydantic model)│
└────────────┬───────────────────────┬────────────────────┘
             │                       │
          domain                  email / cve / output
             ▼                       ▼
┌────────────────────┐        ┌──────────────────────┐
│   DomainAgent      │        │  [Sprint 2 Agents]   │
│   (LangChain       │        │  EmailAgent          │
│    AgentExecutor + │        │  CVEAgent            │
│    6 OSINT tools)  │        │  OutputAgent         │
└────────┬───────────┘        └──────────────────────┘
         │ findings[]
         ▼
┌─────────────────────────────────────────────────────────┐
│  ArgusState  (shared LangGraph state, TypedDict)        │
│  • findings, risk_score, summary, memory_context        │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  ChromaDB  (persistent vector store)                    │
│  • Saves analysis results for future RAG context        │
└─────────────────────────────────────────────────────────┘
```

The graph is compiled with **LangGraph `StateGraph`** and uses conditional edges so that the orchestrator's routing decision (`next_agent`) determines which agent node runs next.

---

## Project Structure

```
MultiAgent-OSINT-Argus/
│
├── app/
│   ├── main.py                  # Entry point — reads user input, builds initial state, invokes graph
│   ├── graph.py                 # LangGraph StateGraph definition — nodes, edges, entry point
│   ├── state.py                 # ArgusState TypedDict — shared state schema for all agents
│   ├── config.py                # Loads .env — API keys, base URL, model name
│   │
│   ├── agents/
│   │   ├── base_agent.py        # Abstract BaseAgent (ABC) — defines run(state) interface
│   │   ├── orchestrator_agent.py # LLM-based routing supervisor — sets next_agent
│   │   └── domain_agent.py      # Full domain analysis via 6 OSINT tools + LLM report
│   │
│   ├── models/
│   │   ├── llm.py               # ChatOpenAI factory — returns configured LLM instance
│   │   └── router.py            # RouteDecision Pydantic model — structured output schema
│   │
│   ├── memory/
│   │   └── chroma_memory.py     # ChromaDB client — save_analysis() + search_memory()
│   │
│   └── tools/
│       ├── classifier.py        # Regex classifier — fast pre-routing before LLM
│       ├── whois_tool.py        # WHOIS lookup — registrar, dates, name servers
│       ├── dns_tool.py          # DNS records — A, MX, NS
│       └── domain_tools.py      # 4 advanced tools: SSL, SPF/DMARC/DKIM, URLhaus, crt.sh
│
├── .env                         # Local secrets (not committed)
├── .env.example                 # Template for required environment variables
├── requirements.txt             # Python dependencies
└── README.md                    # This file
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

The central coordinator of the system. Uses the configured LLM with **structured output** (via `with_structured_output(RouteDecision)`) to classify the user's input and decide which agent to dispatch next.

**How it works:**
1. Receives the user input from state
2. Sends a system prompt + user input to the LLM
3. LLM returns a `RouteDecision` Pydantic object with `input_type`, `next_agent`, and `reasoning`
4. Sets `state["next_agent"]` which LangGraph uses as the conditional edge key
5. Appends the routing decision to `state["findings"]` for full auditability

**Supported routes:**

| Input Type | Next Agent |
|------------|------------|
| `domain`   | `domain`   |
| `email`    | `email` *(Sprint 2)* |
| `cve` topic | `cve` *(Sprint 2)* |
| unknown    | `output`   |

---

### `DomainAgent` — Full Domain OSINT Analysis
**File:** `app/agents/domain_agent.py`

The most complete agent in Sprint 1. Built on a **LangChain `AgentExecutor`** with `create_tool_calling_agent`, giving the LLM the ability to autonomously call all 6 OSINT tools in sequence and reason over the results.

**Mandatory execution order (enforced via system prompt):**
1. `run_whois` → domain age, registrar, expiry
2. `run_dns_lookup` → A, MX, NS records
3. `run_crtsh` → subdomain enumeration via Certificate Transparency
4. `run_urlhaus` → malware database check (abuse.ch)
5. `run_spf_dmarc_check` → email security posture (SPF, DMARC, DKIM)
6. `run_ssl_check` → TLS certificate validity and expiry

After all tools have run, the LLM produces a **structured JSON report**:

```json
{
  "threat_indicators": ["..."],
  "exposure_findings": ["..."],
  "summary": "2-3 sentence overall assessment"
}
```

The agent handles both clean JSON and markdown-fenced responses (`\`\`\`json ... \`\`\``), with a full fallback parser for edge cases.

**Findings written to state:**
```python
{
  "agent": "DomainAgent",
  "domain": "example.com",
  "whois": { ... },
  "dns": { ... },
  "crtsh": { ... },
  "urlhaus": { ... },
  "email_security": { ... },
  "ssl": { ... },
  "ai_analysis": {
    "threat_indicators": [...],
    "exposure_findings": [...],
    "summary": "..."
  }
}
```

---

## Tools

All tools are registered as **LangChain `@tool`** decorated functions, making them directly callable by any `AgentExecutor` or tool-calling LLM.

### `run_whois` — WHOIS Lookup
**File:** `app/tools/whois_tool.py`

Queries public WHOIS databases for domain registration metadata. Returns registrar, creation date, expiration date, and name servers. Useful for detecting freshly registered domains (a common phishing indicator).

**Returns:** `registrar`, `creation_date`, `expiration_date`, `name_servers`

---

### `run_dns_lookup` — DNS Record Lookup
**File:** `app/tools/dns_tool.py`

Resolves `A`, `MX`, and `NS` records using `dnspython`. Missing MX records can indicate a domain not intended for email but used for spoofing. Unexpected A records can signal compromise.

**Returns:** dict with `A`, `MX`, `NS` record arrays

---

### `run_ssl_check` — TLS Certificate Analysis
**File:** `app/tools/domain_tools.py`

Performs a direct TLS handshake on port 443 using Python's `ssl` module with `certifi` as the CA bundle. Detects:

- Expired certificates
- Certificates expiring within 14 days (CRITICAL) or 30 days (WARNING)
- Self-signed certificates
- WAF/TLS-interception (Cloudflare, Myra)
- Port 443 unreachable

**Verdicts:** `OK` | `WARNING` | `CRITICAL` | `UNKNOWN`

---

### `run_spf_dmarc_check` — Email Security Posture
**File:** `app/tools/domain_tools.py`

Checks whether a domain is protected against email spoofing by querying TXT DNS records for:

- **SPF** — must exist and contain `-all` or `~all`
- **DMARC** (`_dmarc.<domain>`) — must exist; `p=none` flags as monitoring-only
- **DKIM** — probes 7 common selectors (`default`, `google`, `mail`, `k1`, `dkim`, `s1`, `s2`)

A missing or weak configuration means anyone can spoof `@<domain>` emails.

**Verdicts:** `SECURE` | `EXPOSED`

---

### `run_urlhaus` — Malware Database Check
**File:** `app/tools/domain_tools.py`

Queries the **URLhaus API** (`urlhaus-api.abuse.ch/v1/host/`) — a public malware URL feed maintained by abuse.ch. No API key required.

Extracts:
- Whether the domain is known as a malware host
- Count of active vs total malicious URLs
- Malware family tags
- Blacklist status

Handles HTTP 401 (WAF block) and HTTP 429 (rate limit) gracefully with informative error messages.

**Verdicts:** `CLEAN` | `MALICIOUS` | `UNKNOWN`

---

### `run_crtsh` — Subdomain Enumeration via Certificate Transparency
**File:** `app/tools/domain_tools.py`

Queries `crt.sh` for all SSL certificates ever issued for a domain. Since every certificate must be publicly logged, this reveals all subdomains without any DNS brute-forcing.

- Caps at 100 certificates to prevent memory overhead on large domains
- Returns top 20 unique subdomains
- Flags domains with more than 15 subdomains as having elevated attack surface
- Filters wildcard entries (`*.example.com`)

---

## State & Routing

### `ArgusState` — Shared Graph State
**File:** `app/state.py`

```python
class ArgusState(TypedDict):
    user_input: str          # Raw input from the user
    input_type: str          # Classified type: domain | email | url | unknown
    current_agent: str       # Currently executing agent
    next_agent: str          # Routing target — used by LangGraph conditional edges
    findings: List[Dict]     # Append-only log of all agent outputs
    risk_score: Optional[int]  # Aggregate risk (0–100), set by OutputAgent in Sprint 2
    summary: Optional[str]     # Human-readable final report
    memory_context: Optional[str]  # Retrieved ChromaDB context for RAG enrichment
```

### `RouteDecision` — Structured Routing Schema
**File:** `app/models/router.py`

A Pydantic model that constrains the OrchestratorAgent's LLM output to a valid, typed routing decision:

```python
class RouteDecision(BaseModel):
    input_type: Literal["domain", "email", "url", "unknown"]
    next_agent: Literal["domain", "email", "cve", "output"]
    reasoning: str  # Audit trail — why this route was selected
```

Using `with_structured_output(RouteDecision)` guarantees the LLM cannot hallucinate an invalid agent name, making routing deterministic and safe.

### Input Classifier
**File:** `app/tools/classifier.py`

A lightweight regex pre-classifier that runs **before** the LLM to provide a fast first-pass answer. The OrchestratorAgent can confirm or override this classification.

| Pattern | Classification |
|---------|----------------|
| `user@domain.tld` | `email` |
| `domain.tld` (no `@`) | `domain` |
| Anything else | `unknown` |

---

## Memory (ChromaDB)

**File:** `app/memory/chroma_memory.py`

Uses a **persistent ChromaDB client** stored in `./chroma_db/`. The collection `argus_memory` stores past analysis results as documents, enabling **Retrieval-Augmented Generation (RAG)** in future runs.

```python
# Save an analysis result
save_analysis(query="example.com", content="<full analysis JSON>")

# Retrieve relevant past context (top 3 nearest neighbours)
results = search_memory(query="example.com")
```

This means that if a domain was analysed before, the system can recall and reuse those findings to enrich the current analysis — without re-querying all external APIs.

> **Note:** ChromaDB integration is initialised and connected in Sprint 1. Active RAG injection into agent prompts is planned for Sprint 2.

---

## Setup

### Prerequisites

- Python 3.11+
- Access to an OpenAI-compatible API (e.g. [SAIA / Academic Cloud](https://chat-ai.academiccloud.de))

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
# Edit .env with your actual API keys (see Configuration below)
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```env
# Required — OpenAI-compatible API
OPENAI_API_KEY=your_api_key_here
OPENAI_BASE_URL=https://chat-ai.academiccloud.de/v1   # or https://api.openai.com/v1
MODEL_NAME=mistral-large-instruct                      # or gpt-4o, etc.

# Optional — required for Sprint 2 agents
VT_API_KEY=your_virustotal_key       # EmailAgent — VirusTotal lookups
SHODAN_API_KEY=your_shodan_key       # Future infrastructure scanning
```

**Notes:**
- `OPENAI_BASE_URL` supports any OpenAI-compatible endpoint. The project was developed and tested against the **German Academic Cloud (SAIA)** endpoint.
- `MODEL_NAME` was selected after evaluating multiple models for structured output reliability (tool-calling accuracy and JSON schema adherence).
- The `VT_API_KEY` and `SHODAN_API_KEY` are not used in Sprint 1 but must be present in `.env` for future sprints.

---

## Running the App

```bash
python -m app.main
```

The CLI banner will appear and prompt for input:

```
╔══════════════════════════════════════════════╗
║       👁️  OSINT-Argus Multi-Agent           ║
║     DomainAgent · EmailAgent · CVEAgent      ║
║          RAG Memory · LangGraph              ║
╚══════════════════════════════════════════════╝

🔍 Input : example.com
```

**Supported inputs (Sprint 1):**

| Input | Routed To | Status |
|-------|-----------|--------|
| `example.com` | DomainAgent | ✅ Working |
| `sub.example.com` | DomainAgent | ✅ Working |
| `user@example.com` | EmailAgent | 🔜 Sprint 2 |
| CVE topic / keyword | CVEAgent | 🔜 Sprint 2 |

---

## Example Output

For input `example.com`, the graph produces a findings list similar to:

```python
[
  {
    "agent": "OrchestratorAgent",
    "decision": {
      "input_type": "domain",
      "next_agent": "domain",
      "reasoning": "Input matches domain pattern — routing to DomainAgent."
    }
  },
  {
    "agent": "DomainAgent",
    "domain": "example.com",
    "whois": {
      "registrar": "RESERVED-Internet Assigned Numbers Authority",
      "creation_date": "1995-08-14 04:00:00",
      "expiration_date": "2025-08-13 04:00:00",
      "name_servers": ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"]
    },
    "dns": { "A": ["93.184.216.34"], "MX": [], "NS": [...] },
    "ssl": {
      "valid": true,
      "days_until_expiry": 248,
      "issuer": "DigiCert Inc",
      "verdict": "OK"
    },
    "email_security": {
      "spf": { "configured": false, "issues": ["Kein SPF-Record — Spoofing möglich"] },
      "dmarc": { "configured": false },
      "email_spoofing_possible": true,
      "verdict": "EXPOSED"
    },
    "urlhaus": { "threat_found": false, "verdict": "CLEAN" },
    "crtsh": { "subdomain_count": 3, "subdomains": [...] },
    "ai_analysis": {
      "threat_indicators": [],
      "exposure_findings": ["Kein SPF-Record konfiguriert", "Kein DMARC-Record vorhanden"],
      "summary": "example.com ist eine IANA-Reservierungsdomain ohne aktive Dienste..."
    }
  }
]
```

---

## Sprint Status

### ✅ Sprint 1 — Base Setup (Complete)

| Feature | Status | Notes |
|---------|--------|-------|
| LangGraph `StateGraph` initialised | ✅ Done | `OrchestratorAgent` + `DomainAgent` as nodes |
| `ArgusState` TypedDict schema | ✅ Done | Full state contract defined |
| WHOIS tool (`run_whois`) | ✅ Done | `python-whois` |
| DNS tool (`run_dns_lookup`) | ✅ Done | `dnspython`, A/MX/NS records |
| SSL certificate check (`run_ssl_check`) | ✅ Done | `ssl` + `certifi`, WAF detection |
| SPF/DMARC/DKIM check (`run_spf_dmarc_check`) | ✅ Done | Spoofing exposure detection |
| URLhaus malware check (`run_urlhaus`) | ✅ Done | abuse.ch API, no key required |
| Subdomain enumeration (`run_crtsh`) | ✅ Done | Certificate Transparency |
| Input Classifier (regex) | ✅ Done | Fast pre-routing |
| OrchestratorAgent (LLM routing) | ✅ Done | Structured output via `RouteDecision` |
| DomainAgent (AgentExecutor) | ✅ Done | 6 tools + LLM JSON report |
| ChromaDB connected | ✅ Done | Persistent collection `argus_memory` |
| Model selection & evaluation | ✅ Done | Mistral Large via SAIA |

---

## Roadmap — Sprint 2

**Goal:** Full multi-agent system — all 3 input scenarios routed and analysed correctly.

### EmailAgent
- VirusTotal API integration for email/IP/URL reputation
- LLM-based phishing detection (header analysis, sender patterns)
- Reputation scoring

### CVEAgent
- NVD NIST API integration (`nvd.nist.gov/rest/json`)
- MITRE ATT&CK technique mapping
- CVSS severity enrichment

### OutputAgent
- Aggregate risk score calculation (0–100) across all findings
- Structured, human-readable report generation
- Markdown/JSON dual output

### System-wide improvements
- End-to-end routing tests for all 3 input types
- Edge case handling (partial inputs, mixed types)
- Active RAG injection from ChromaDB into agent prompts
- Code scalability refactor — shared tool utilities, error handling standardisation

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
