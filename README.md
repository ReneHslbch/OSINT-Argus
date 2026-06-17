# 👁️ OSINT-Argus

> Multi-agent OSINT platform for analysing domains, emails, phone numbers, files, software versions and digital identities.

Built with **LangGraph**, **LangChain** and **ChromaDB**, OSINT-Argus combines specialised cybersecurity agents into a single adaptive investigation workflow.

---

## Features

- Domain & infrastructure intelligence
- Email & phishing analysis
- CVE and software vulnerability lookup
- Phone number reputation checks
- File metadata & malware analysis
- Identity footprint profiling
- Data breach detection
- Structured risk scoring and reporting
- Persistent memory with ChromaDB

---

## Architecture

```text
User Input
    │
    ▼
InputAgent
    │
    ▼
OrchestratorAgent
    │
 ┌──┼─────────────────────────┐
 │  │  │  │  │  │  │
 ▼  ▼  ▼  ▼  ▼  ▼  ▼
Domain
Email
CVE
Phone
File
Identity
Leak
Agents
 │
 └───────────────┐
                 ▼
            OutputAgent
                 │
                 ▼
            Risk Report
```

The orchestrator dynamically selects the next target, routes it to the appropriate specialist agent, and continues until all discovered indicators have been analysed.

---

## Agents

| Agent | Purpose |
|---------|---------|
| InputAgent | Extracts and classifies investigation targets |
| OrchestratorAgent | Supervises routing and scan prioritisation |
| DomainAgent | Domain, DNS, SSL and reputation analysis |
| EmailAgent | Email reputation and phishing detection |
| CVEAgent | Software vulnerability assessment |
| PhoneAgent | Smishing and vishing investigations |
| FileAgent | Metadata extraction and malware checks |
| IdentityAgent | Digital footprint profiling |
| LeakAgent | Breach and exposure detection |
| OutputAgent | Final report generation |

---

## Project Structure

```text
app/
├── agents/
├── tools/
├── models/
├── memory/
├── ui/
├── graph.py
├── state.py
└── main.py
```

- **agents/** – investigation logic
- **tools/** – OSINT integrations and utilities
- **models/** – shared schemas and data models
- **memory/** – ChromaDB integration
- **ui/** – Streamlit frontend
- **graph.py** – LangGraph workflow definition

---

## Example Workflow

```text
Input:
"Suspicious email mentioning nginx 1.18.0 and evil-example.com"

InputAgent
    ↓
Extracts:
- evil-example.com
- nginx 1.18.0

Orchestrator
    ↓
DomainAgent
    ↓
CVEAgent
    ↓
OutputAgent
```

Each agent may discover additional indicators which are automatically added back into the investigation queue.

---

## Installation

```bash
git clone https://github.com/<user>/OSINT-Argus.git
cd OSINT-Argus

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

Create a `.env` file:

```env
OPENAI_API_KEY=...
OPENAI_BASE_URL=...
MODEL_NAME=...
VT_API_KEY=...
```

---

## Running

CLI:

```bash
python -m app.main
```

UI:

```bash
streamlit run app/ui_main.py
```

---

## Supported Inputs

| Input | Agent |
|---------|---------|
| Domain / URL | DomainAgent |
| Email Address / Email Content | EmailAgent |
| Software Version | CVEAgent |
| Phone Number | PhoneAgent |
| File Path / Hash | FileAgent |
| Username / Person | IdentityAgent |
| Breach Indicators | LeakAgent |

---

## Tech Stack

- LangGraph
- LangChain
- ChromaDB
- OpenAI-compatible LLMs
- VirusTotal
- NVD API
- Sherlock
- Holehe
- dnspython
- ExifTool

---

## License

MIT License

---

*OSINT-Argus is intended for defensive security research, OSINT investigations, and cybersecurity education.*
