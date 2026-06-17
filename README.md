# 👁️ OSINT-Argus — Multi-Agent OSINT Cybersecurity System

> **Agentic AI system that uses Open-Source Intelligence (OSINT) to analyse domains, emails, phone numbers, files, CVEs and digital identities — protecting users from phishing, malware and infrastructure threats.**

Built with **LangGraph**, **LangChain** and **ChromaDB**. Designed as a fully modular, extensible multi-agent pipeline where each agent handles one specialised analysis task and the orchestrator drives the entire queue adaptively.

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
- [Tech Stack](#tech-stack)

---

## Overview

OSINT-Argus is a **supervisor-pattern multi-agent system** built on LangGraph. It accepts any free-form user input — a domain, raw email, phone number, file path, hash, software version or personal identity — and routes it through a dynamic pipeline of specialised OSINT agents.

The pipeline starts with an **InputAgent** that extracts all scannable targets from the raw input using structured LLM output. A central **OrchestratorAgent** then drives the scan queue adaptively: it prioritises targets by risk, assigns each one to the correct specialist agent, and loops until the queue is empty. Finally the **OutputAgent** aggregates all findings into a structured risk report.

The system outputs a **threat score (0–100)**, a **vulnerability score (0–100)**, a **risk level** (LOW / MEDIUM / HIGH / CRITICAL), a plain-language summary, and step-by-step **incident response guidance** — fully structured and ready to drive any frontend.

---

## Architecture

```
User Input
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│  InputAgent  (LLM-powered triage)                               │
│  • Classifies input type (domain / email / phone / file / ...)  │
│  • Extracts ALL individual targets into to_scan queue           │
└────────────────────────────┬────────────────────────────────────┘
                             │  to_scan: ["evil.com", "+49172...", "nginx 1.18"]
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  OrchestratorAgent  (LLM-powered adaptive supervisor)           │
│  • Selects highest-priority target from queue (current_check)   │
│  • Routes to correct specialist agent via next_agent            │
│  • Rebuilds queue after each scan (relevant_targets_remaining)  │
│  • Routes to OutputAgent when queue is empty                    │
└──┬───────┬───────┬───────┬────────┬───────┬────────────────────┘
   │       │       │       │        │       │
domain   email   cve    phone    file  identity
   │       │       │       │        │       │
   ▼       ▼       ▼       ▼        ▼       ▼
Domain  Email   CVE    Phone    File  Identity
Agent   Agent   Agent  Agent    Agent Agent
   │       │       │       │        │       │
   └───────┴───────┴───────┴────────┴───────┘
                             │
                   (all agents → back to Orchestrator)
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  OutputAgent  (LLM structured output)                           │
│  • Aggregates all Findings objects from state                   │
│  • Produces threat_score, vulnerability_score, risk_level       │
│  • Generates plain-language summary + incident response steps   │
└─────────────────────────────────────────────────────────────────┘
                             │
                             ▼
                          ArgusState
                    (shared LangGraph state)
                             │
                             ▼
                          ChromaDB
                   (persistent vector store)
```

The graph is compiled with **LangGraph `StateGraph`** using conditional edges. Every specialist agent routes back to the orchestrator after completing its scan. The orchestrator fires `output` only when `to_scan` is empty — ensuring nothing is missed.

---

## Project Structure

```
OSINT-Argus/
│
├── app/
│   ├── main.py                     # Entry point — reads input, builds state, invokes graph
│   ├── graph.py                    # LangGraph StateGraph — nodes, edges, entry point
│   ├── state.py                    # ArgusState TypedDict — shared state schema
│   ├── config.py                   # Loads .env — API keys, base URL, model name
│   │
│   ├── agents/
│   │   ├── base_agent.py           # Abstract BaseAgent — defines run(state) interface
│   │   ├── input_agent.py          # Triage — classifies input & extracts all targets
│   │   ├── orchestrator_agent.py   # Adaptive queue supervisor + LLM routing
│   │   ├── domain_agent.py         # Domain OSINT via 6 tools + LLM JSON report
│   │   ├── email_agent.py          # Email phishing analysis
│   │   ├── cve_agent.py            # CVE lookup via NVD NIST API
│   │   ├── phone_agent.py          # Phone number forensics (Vishing/Smishing)
│   │   ├── file_agent.py           # File metadata, hash analysis + identity extraction
│   │   ├── identity_agent.py       # Digital identity profiling (Sherlock + Holehe)
│   │   └── output_agent.py         # Final risk report — scores, level, IR steps
│   │
│   ├── models/
│   │   ├── llm.py                  # ChatOpenAI factory — configured LLM instance
│   │   ├── agent_type.py           # AgentType enum — all registered agent identifiers
│   │   ├── findings.py             # Findings dataclass — shared result object
│   │   ├── file_analysis.py        # FileAnalysis Pydantic model
│   │   └── router.py               # Pydantic models: OrchestratorDecision, OutputReport, ...
│   │
│   ├── memory/
│   │   └── chroma_memory.py        # ChromaDB client — save_analysis() + search_memory()
│   │
│   ├── tools/
│   │   ├── classifier.py           # Regex classifier — fast pre-routing before LLM
│   │   ├── whois_tool.py           # WHOIS lookup — registrar, dates, name servers
│   │   ├── dns_tool.py             # DNS records — A, MX, NS
│   │   ├── domain_tools.py         # SSL, SPF/DMARC/DKIM, URLhaus, crt.sh
│   │   ├── email_tools.py          # URL extraction, header parsing, VirusTotal
│   │   ├── cve_tools.py            # NVD NIST API v2 + local mock database
│   │   ├── phone_tools.py          # phonenumbers library + spam reputation check
│   │   ├── file_tools.py           # pypdf, ExifTool, SHA256, VirusTotal hash check
│   │   └── identity_tools.py       # Holehe (email) + Sherlock (username) wrappers
│   │
│   └── test_mails/
│       ├── email_test.txt          # Generic phishing email
│       ├── crit_mail_test.txt      # CRITICAL-level phishing scenario
│       ├── legit_mail_test.txt     # Legitimate email (LOW risk baseline)
│       ├── low_risk_test.txt       # Low-risk domain input
│       ├── phone_test.txt          # Smishing SMS scenario
│       └── osint_argus_review1.pdf # PDF with embedded metadata for FileAgent testing
│
├── .env                            # Local secrets (not committed)
├── .env.example                    # Template for required environment variables
├── requirements.txt                # Python dependencies
└── README.md                       # This file
```

---

## Agents

### `BaseAgent` — Abstract Interface
**File:** `app/agents/base_agent.py`

Every agent inherits from `BaseAgent` and must implement one method:

```python
def run(self, state: ArgusState) -> ArgusState
```

The agent receives the full shared state, performs its analysis, appends a `Findings` object to `state["findings"]`, and returns the mutated state.

---

### `InputAgent` — Triage & Target Extraction
**File:** `app/agents/input_agent.py`

The entry point of every pipeline run. Uses `with_structured_output(InputExtraction)` to:

1. Classify the global input type: `domain | email | url | text | phone | file | identity | unknown`
2. Extract **all cyber-relevant targets** into `state["to_scan"]` — including embedded IPs, domains, hashes, file paths, software version strings and phone numbers from free text

The InputAgent ensures only clean, isolated values enter the queue — no labels, no descriptions, no duplicate context strings.

---

### `OrchestratorAgent` — Adaptive Queue Supervisor
**File:** `app/agents/orchestrator_agent.py`

The central coordinator. Called after every specialist agent run. Uses `with_structured_output(OrchestratorDecision)` to:

- Select the **highest-priority target** from `to_scan` (considering previous findings and risk context)
- Assign it as `current_check` and set `next_agent` to the appropriate specialist
- Rebuild `relevant_targets_remaining` — the LLM may prune duplicates or junk but must preserve valid hashes, names, and IPs
- Route to `output` when the queue is empty or enough evidence is gathered

**Supported routes:**

| Input type | → Agent |
|------------|---------|
| Domain / IP / URL | `domain` |
| Email address or raw email | `email` |
| Software + version string | `cve` |
| Phone number | `phone` |
| File path or hash (MD5/SHA256) | `file` |
| Person name / username / handle | `identity` |
| Queue empty or analysis sufficient | `output` |

**Key behaviour:** When `FileAgent` discovers an author name in PDF metadata and adds it to `to_scan`, the Orchestrator picks it up and routes it to `IdentityAgent` — demonstrating true cross-agent data flow.

---

### DomainAgent — Domain OSINT & Exposure Analysis

**File:** `app/agents/domain_agent.py`

Built on a LangChain `AgentExecutor` using `create_tool_calling_agent`.

The agent receives the current target from `state["current_check"]` and uses the tools provided through `DOMAIN_TOOLS` to perform OSINT-based domain reconnaissance.

The analysis focuses on:

* Public DNS and domain intelligence
* WHOIS information (if supported by the available tools)
* SSL/TLS certificate assessment
* Email security posture (SPF, DMARC, DKIM)
* Malware and reputation checks (e.g. URLhaus)
* Discovery of subdomains
* Detection of web technologies and software versions

Unlike earlier implementations, tool execution order is **not hard-coded**. The LLM dynamically decides which tools to call through LangChain's tool-calling agent framework.

The agent is instructed to produce a structured JSON result:

```json
{
  "threat_indicators": [
    "Identified malware indicators or malicious infrastructure findings"
  ],
  "exposure_findings": [
    "Misconfigurations, certificate issues, or other security weaknesses"
  ],
  "discovered_subdomains": [
    "Newly identified subdomains"
  ],
  "discovered_technologies": [
    "Detected technologies and versions"
  ],
  "summary": "Short German-language assessment of the domain."
}
```

Detected technologies can be forwarded into the system's scan queue (`state["to_scan"]`) for downstream CVE analysis.

---

### EmailAgent — Email & Phishing Analysis

**File:** `app/agents/email_agent.py`

Built on a LangChain `AgentExecutor` using `create_tool_calling_agent`.

The agent receives the current target from `state["current_check"]` and supports two analysis modes.

#### Reputation Analysis Mode

If the target is an email address or domain, the agent may use tools from `EMAIL_TOOLS` such as:

* VirusTotal reputation checks
* Phishing blacklist checks

#### Content Analysis Mode

If the target contains email message content, the agent performs an LLM-driven phishing assessment focused on:

1. Authority & Scarcity indicators
2. Impersonation quality
3. Call-to-action anomalies
4. Technical artefacts, encoding issues, and language inconsistencies

The agent returns a structured JSON result:

```json
{
  "threat_indicators": [
    "Detected phishing indicators"
  ],
  "exposure_findings": [
    "Technical findings such as blacklist entries or reputation issues"
  ],
  "summary": "Short German-language phishing assessment."
}
```

The current implementation does not explicitly parse email headers, extract URLs, or detect Reply-To mismatches within the agent code itself. Such functionality depends on the tools available through `EMAIL_TOOLS`.


---

### `PhoneAgent` — Telecommunications Forensics
**File:** `app/agents/phone_agent.py`

Analyses phone numbers for Vishing (voice phishing) and Smishing (SMS phishing) indicators using two tools:

1. `parse_and_validate_phone` — validates structure, derives E.164 format, detects line type (MOBILE / VOIP / LANDLINE)
2. `check_phone_reputation` — queries spam/phishing reputation feeds for abuse reports and spam score

VOIP numbers receive elevated risk weighting due to their prevalence in call-ID spoofing attacks.

---

### `FileAgent` — File Metadata & Hash Analysis
**File:** `app/agents/file_agent.py`

Handles both **file paths** (local documents) and **standalone hashes** (MD5 / SHA256).

**Analysis steps:**
1. `extract_universell_document_metadata` — uses `pypdf` for PDFs, falls back to `ExifTool` for all other types. Extracts authors, usernames, company names, internal hostnames, UNC paths, build system artefacts.
2. `check_file_hash_virustotal` — submits any found or passed hashes to VirusTotal v3 for malware detection.
3. LLM analysis via `with_structured_output(FileAnalysis)` — identifies malware indicators and metadata leaks.

**Cross-agent data flow:** If the LLM detects person names (e.g. document authors), the FileAgent appends them to `state["to_scan"]` — the Orchestrator then automatically routes them to `IdentityAgent`.

---

### `IdentityAgent` — Digital Identity Profiling
**File:** `app/agents/identity_agent.py`

Profiles the digital footprint of a person or username for **Spear-Phishing risk assessment**.

**Logic branches:**
- **Email address as input:** runs `check_email_with_holehe` (platform registration check) + `search_username_with_sherlock` on the local part
- **Name or handle as input:** runs `search_username_with_sherlock` directly with a normalised handle

The LLM then assesses:
- Which platforms increase Spear-Phishing exposure (GitHub → reveals tech stack, LinkedIn → reveals employer role)
- Correlation between found profiles
- What pretext lines an attacker could construct

---

### `OutputAgent` — Final Risk Report
**File:** `app/agents/output_agent.py`

The terminal agent. Collects all `Findings` objects from `state["findings"]`, formats them into a structured prompt, and uses `with_structured_output(OutputReport)` to produce a fully typed report.

**Output written to state:**

| Field | Type | Description |
|-------|------|-------------|
| `threat_score` | `int` (0–100) | Active threat level — known malicious actors, exploits, active campaigns |
| `vulnerability_score` | `int` (0–100) | Exposure level — missing SPF, expired certs, public CVEs |
| `risk_level` | `"LOW" \| "MEDIUM" \| "HIGH" \| "CRITICAL"` | Combined risk classification |
| `summary` | `str` | Plain-language summary for end users (no jargon) |
| `explanation` | `str` | Technical explanation for security experts (3–5 sentences) |
| `action_prevent` | `str` | Preventive recommendation — what to do right now |
| `action_incident_response` | `List[str]` | Step-by-step IR checklist if the user already clicked / interacted |
| `indicators` | `List[str]` | Top risk factors (max 10) |

**Traffic-light mapping:**

| Score | Level | Meaning |
|-------|-------|---------|
| 0–33 | LOW | 🟢 No action needed |
| 34–66 | MEDIUM | 🟡 Proceed with caution |
| 67–84 | HIGH | 🔴 Action recommended |
| 85–100 | CRITICAL | 🚨 Act immediately |

---

## Tools

All tools are registered as **LangChain `@tool`** decorated functions and are assigned to agent executors via tool lists.

### `run_whois` — WHOIS Lookup
**File:** `app/tools/whois_tool.py`

Returns registrar, creation date, expiration date, and name servers. Freshly registered domains (< 30 days) are a primary phishing indicator.

---

### `run_dns_lookup` — DNS Records
**File:** `app/tools/dns_tool.py`

Resolves `A`, `MX`, and `NS` records via `dnspython`. Missing MX records on a domain sending email is a spoofing indicator.

---

### `run_ssl_check` — TLS Certificate Analysis
**File:** `app/tools/domain_tools.py`

Direct TLS handshake on port 443 using Python's `ssl` module with `certifi`. Detects expired certs, upcoming expiry (14 / 30 days), self-signed certs, and TLS interception (Cloudflare, Myra WAF).

**Verdicts:** `OK` | `WARNING` | `CRITICAL` | `UNKNOWN`

---

### `run_spf_dmarc_check` — Email Security Posture
**File:** `app/tools/domain_tools.py`

Checks SPF (`TXT` record), DMARC (`_dmarc.<domain>`), and DKIM (probes 7 common selectors). A missing or permissive configuration means the domain can be spoofed in outbound email.

**Verdicts:** `SECURE` | `EXPOSED`

---

### `run_urlhaus` — Malware Database Check
**File:** `app/tools/domain_tools.py`

Queries the **URLhaus API** (abuse.ch) — no API key required. Returns active malicious URL count, malware family tags, and blacklist status.

**Verdicts:** `CLEAN` | `MALICIOUS` | `UNKNOWN`

---

### `run_crtsh` — Subdomain Enumeration
**File:** `app/tools/domain_tools.py`

Queries `crt.sh` Certificate Transparency logs. Returns up to 20 unique subdomains. Domains with more than 15 subdomains are flagged as elevated attack surface.

---

### `search_nvd_cves` — CVE Lookup
**File:** `app/tools/cve_tools.py`

Queries the NVD NIST API v2 with the technology string. Returns top 5 CVEs with CVSS score, severity and description. Includes a local mock database for offline/rate-limited scenarios.

---

### `parse_and_validate_phone` + `check_phone_reputation`
**File:** `app/tools/phone_tools.py`

- `parse_and_validate_phone`: validates via `google-phonenumbers`, returns E.164 format and line type
- `check_phone_reputation`: checks against spam and Smishing reputation feeds; VOIP numbers receive automatic flag

---

### `extract_universell_document_metadata` + `check_file_hash_virustotal`
**File:** `app/tools/file_tools.py`

- `extract_universell_document_metadata`: tries `pypdf` for PDFs, falls back to `ExifTool` subprocess for all other types
- `calculate_sha256`: computes file hash for VirusTotal submission
- `check_file_hash_virustotal`: VirusTotal v3 hash reputation check (requires `VT_API_KEY`)

---

### `check_email_with_holehe` + `search_username_with_sherlock`
**File:** `app/tools/identity_tools.py`

- `check_email_with_holehe`: wraps the Holehe framework to check platform registrations for an email address
- `search_username_with_sherlock`: wraps Sherlock to enumerate social media profiles for a username handle across 400+ platforms

---

## State & Routing

### `ArgusState` — Shared Graph State
**File:** `app/state.py`

```python
class ArgusState(TypedDict):
    user_input:     str                  # Raw input from the user
    input_type:     str                  # Global type — domain / email / phone / file / ...
    current_agent:  str                  # Currently active agent
    next_agent:     str                  # Routing decision by Orchestrator
    findings:       List[Findings]       # All Findings objects from all agents
    memory_context: Optional[str]        # ChromaDB RAG context (future use)
    to_scan:        List[str]            # Remaining targets in the queue
    scanned:        List[str]            # Already completed targets
    current_check:  Optional[str]        # Target currently being analysed
    file_paths:     List[str]            # Extracted file paths (for FileAgent)
    file_hashes:    List[str]            # Extracted hashes (for VirusTotal)
```

### `Findings` — Shared Result Object
**File:** `app/models/findings.py`

```python
@dataclass
class Findings:
    agent:            AgentType      # Which agent produced this finding
    input:            str            # The target that was analysed
    threat_sum:       List[str]      # Active threat indicators
    vulnerability_sum: List[str]     # Exposure / misconfiguration findings
```

### `OrchestratorDecision` — Routing Model
**File:** `app/models/router.py`

```python
class OrchestratorDecision(BaseModel):
    next_agent:                  Literal["domain", "email", "cve", "phone", "file", "identity", "output"]
    current_check:               Optional[str]   # Exact target from to_scan to process now
    relevant_targets_remaining:  List[str]        # Pruned queue for next iteration
    reasoning:                   str              # Strategic justification
```

### `OutputReport` — Final Report Model
**File:** `app/models/router.py`

```python
class OutputReport(BaseModel):
    threat_score:             int                                           # 0–100
    vulnerability_score:      int                                           # 0–100
    risk_level:               Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    explanation:              str                                           # Technical, for experts
    summary:                  str                                           # Plain language, for users
    action_prevent:           str                                           # Preventive recommendation
    action_incident_response: List[str]                                     # Step-by-step IR checklist
    indicators:               List[str]                                     # Top risk factors (max 10)
```

### `AgentType` Enum
**File:** `app/models/agent_type.py`

```python
class AgentType(str, Enum):
    INPUT        = "input"
    ORCHESTRATOR = "orchestrator"
    DOMAIN       = "domain"
    EMAIL        = "email"
    CVE          = "cve"
    PHONE        = "phone"
    FILE         = "file"
    IDENTITY     = "identity"
    OUTPUT       = "output"
```

---

## Memory (ChromaDB)

**File:** `app/memory/chroma_memory.py`

Persistent ChromaDB client stored in `./chroma_db/`. The collection `argus_memory` stores past analysis results as vector documents, enabling **Retrieval-Augmented Generation (RAG)** context injection in future runs.

```python
save_analysis(query="example.com", content="<full analysis JSON>")
results = search_memory(query="example.com")  # top 3 nearest neighbours
```

---

## Setup

### Prerequisites

- Python 3.11+
- Access to an OpenAI-compatible API (e.g. [SAIA / German Academic Cloud](https://chat-ai.academiccloud.de))
- `ExifTool` installed system-wide (required for non-PDF file metadata extraction)
- Optional: VirusTotal API key — required for `FileAgent` hash checks and `EmailAgent` domain reputation

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/OSINT-Argus.git
cd OSINT-Argus

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
# Required — OpenAI-compatible LLM API
OPENAI_API_KEY=your_api_key_here
OPENAI_BASE_URL=https://chat-ai.academiccloud.de/v1
MODEL_NAME=mistral-large-instruct

# Required for FileAgent hash checks and EmailAgent reputation
VT_API_KEY=your_virustotal_key
```

**Notes:**
- `OPENAI_BASE_URL` accepts any OpenAI-compatible endpoint. Developed and tested against the **German Academic Cloud (SAIA)**.
- Compatible with `gpt-4o`, `mistral-large-instruct`, or any local model via LM Studio / Ollama.
- `VT_API_KEY` free tier is sufficient for all current agent use cases.

---

## Running the App

```bash
python -m app.main
```

```
╔══════════════════════════════════════════════╗
║       👁️  OSINT-Argus Multi-Agent            ║
║   Domain · Email · CVE · Phone · File        ║
║      Identity · RAG Memory · LangGraph       ║
╚══════════════════════════════════════════════╝

📝 Eingabe (leere Zeile zum Abschließen):
```

Multi-line input is supported — paste a full email with headers, then press Enter on an empty line to submit. For pipe mode, EOF is handled automatically.

```bash
cat app/test_mails/crit_mail_test.txt | python -m app.main
```

**Supported inputs:**

| Input | Routed to | Notes |
|-------|-----------|-------|
| `example.com` | DomainAgent | Full 6-tool OSINT scan |
| Raw email with headers | EmailAgent | Header parse + domain scans |
| `+49172...` | PhoneAgent | Vishing/Smishing check |
| `/path/to/file.pdf` | FileAgent | Metadata + VirusTotal |
| `e3b0c44...` (hash) | FileAgent | Direct VirusTotal hash lookup |
| `nginx 1.18.0` | CVEAgent | NVD CVE lookup |
| `John Doe` / `johndoe` | IdentityAgent | Sherlock + Holehe profile scan |
| Mixed input (email with embedded domains, hashes, phone numbers) | All relevant agents | InputAgent extracts all targets |

---

## Example Output

### Domain Scan — `example.com`

```
🧠 [Orchestrator] Route → domain | Target: 'example.com'
🔍 [DomainAgent] Starte Analyse für: example.com ...

═══════════════════════════════════════════════════════════
  👁️  OSINT-Argus Risikobericht
═══════════════════════════════════════════════════════════
  Threat-Score      : 5 / 100
  Vulnerability-Score: 22 / 100
  Risiko-Level      : LOW

  Zusammenfassung:
    Diese Domain ist eine IANA-Reservierungsdomain und wird
    ausschließlich für Dokumentationszwecke genutzt.

  🛡️  Prävention:
    Keine Aktion erforderlich. Diese Domain ist unbedenklich.

  ⚠️  Indikatoren:
     • Kein SPF-Record konfiguriert
     • Kein DMARC-Record vorhanden
═══════════════════════════════════════════════════════════
```

### Critical Phishing Email

```
📥 [InputAgent] Typ: EMAIL | 4 Targets extrahiert
🧠 [Orchestrator] Route → email | Target: 'paypa1-verify.ru'
🧠 [Orchestrator] Route → domain | Target: 'paypa1-verify.ru'
🧠 [Orchestrator] Route → identity | Target: 'support@paypa1-verify.ru'

═══════════════════════════════════════════════════════════
  🚨  OSINT-Argus Risikobericht
═══════════════════════════════════════════════════════════
  Threat-Score      : 97 / 100
  Vulnerability-Score: 61 / 100
  Risiko-Level      : CRITICAL

  Zusammenfassung:
    Klassische PayPal-Phishing-Mail. Absender-Domain als
    MALICIOUS (VirusTotal) eingestuft, Reply-To Mismatch,
    Dringlichkeitstaktik und Impersonation erkannt.

  🛡️  Prävention:
    Klicke keine Links. Öffne keine Anhänge. Lösche die Mail.

  🚑  Incident Response:
    1. Netzwerkverbindung unterbrechen
    2. Passwort des betroffenen Accounts sofort ändern
    3. Zwei-Faktor-Authentifizierung aktivieren
    4. IT-Sicherheitsabteilung informieren
    5. Mail als Phishing an den Provider melden

  ⚠️  Indikatoren:
     • paypa1-verify.ru als MALICIOUS klassifiziert (VirusTotal)
     • Reply-To Mismatch: account-helpdesk.xyz ≠ Absender-Domain
     • Dringlichkeitstaktik: Kontosperrung in 24h angedroht
     • Impersonation: PayPal-Sicherheitsteam vorgespiegelt
     • Neu registrierte Domain (< 7 Tage)
═══════════════════════════════════════════════════════════
```

---

## Tech Stack

| Component | Technology | Notes |
|-----------|-----------|-------|
| Agent orchestration | [LangGraph](https://github.com/langchain-ai/langgraph) | `StateGraph` with conditional edges |
| LLM tooling | [LangChain](https://github.com/langchain-ai/langchain) | `AgentExecutor`, `with_structured_output` |
| LLM provider | OpenAI-compatible API | Developed on SAIA / Academic Cloud |
| Default model | `mistral-large-instruct` | Also tested with `gpt-4o` |
| Vector store | [ChromaDB](https://www.trychroma.com/) | Persistent `argus_memory` collection |
| Schema validation | `pydantic` v2 | All routing and output models |
| WHOIS | `python-whois` | Domain registration metadata |
| DNS resolution | `dnspython` | A, MX, NS records |
| Phone analysis | `google-phonenumbers` | E.164 validation + line type |
| PDF metadata | `pypdf` | Native Python, no subprocess |
| Universal metadata | `ExifTool` | CLI subprocess for non-PDF types |
| HTTP client | `httpx` | Async-ready, used across all tools |
| TLS inspection | Python `ssl` + `certifi` | Direct socket handshake |
| Config management | `python-dotenv` | `.env` loading |

---

## License

MIT — see `LICENSE` for details.

---

*OSINT-Argus is an academic project developed as part of an Agentic AI course. It is intended for educational and defensive security research purposes only.*
