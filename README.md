# 👁️ OSINT-Argus

<p align="center">
  <img src="app/ui/osint-argus-icon.png" alt="OSINT-Argus Logo" width="150"/>
</p>

> **Multi-agent OSINT platform for intelligent threat analysis and digital reconnaissance**

OSINT-Argus combines specialized cybersecurity agents into a single adaptive investigation workflow. Built with **LangGraph**, **LangChain**, and **ChromaDB**, it delivers automated threat intelligence for domains, emails, phone numbers, files, software vulnerabilities, and digital identities.

---

## 📑 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Agents](#-agents)
- [Mailbox Watcher](#-mailbox-watcher)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Supported Inputs](#-supported-inputs)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [License](#-license)

---
## Demo Video 

### Analyse - Tab
[![Videotitel](https://i9.ytimg.com/vi/na7jEPvA9Z8/mqdefault.jpg?sqp=CJjFptMG-oaymwEmCMACELQB8quKqQMa8AEB-AHUBoACyAOKAgwIABABGEYgTChlMA8=&rs=AOn4CLDXFNth0WIGD6QGXhZo59_oa7L_tQ)](https://youtu.be/na7jEPvA9Z8)

### Indentity Check Tab
[![Videotitel](https://i9.ytimg.com/vi/PPycxACuSQI/mqdefault.jpg?sqp=CMTHptMG-oaymwEmCMACELQB8quKqQMa8AEB-AH-CYACtgWKAgwIABABGCsgZShAMA8=&rs=AOn4CLAE6zmu2OSHfS9WSGTyaboKFKmpBw)](https://youtu.be/PPycxACuSQI)

### Mail Tab
[![Videotitel](https://i9.ytimg.com/vi/Z_95A8wVUjg/mqdefault.jpg?sqp=CMTHptMG-oaymwEmCMACELQB8quKqQMa8AEB-AH-CYACnAWKAgwIABABGGUgZShlMA8=&rs=AOn4CLAbwSr-lGNCq6qs0HQSPHunb6tAhQ)](https://youtu.be/Z_95A8wVUjg)
---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Domain Intelligence** | DNS analysis, SSL inspection, reputation checks |
| **Email Analysis** | Phishing detection, sender reputation, header analysis |
| **CVE Assessment** | Software vulnerability lookup via NVD API |
| **Phone Intelligence** | Smishing/vishing investigation, carrier lookup |
| **File Analysis** | Metadata extraction, malware signature detection |
| **Identity Profiling** | Digital footprint mapping across platforms |
| **Breach Detection** | Data leak monitoring via Have I Been Pwned |
| **Risk Scoring** | Automated threat and vulnerability scoring |
| **Persistent Memory** | ChromaDB-powered context retention |
| **Mailbox Watcher** | Automated email monitoring and analysis |

---

## 🏗️ Architecture

```
┌─────────────┐
│  User Input │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ InputAgent  │  → Extracts & classifies targets
└──────┬──────┘
       │
       ▼
┌──────────────────┐
│OrchestratorAgent │  → Routes & prioritizes
└──────┬───────────┘
       │
   ┌───┴───┬───┬───┬───┬───┬───┐
   ▼   ▼   ▼   ▼   ▼   ▼   ▼
Domain Email CVE Phone File Identity Leak
Agent  Agent Agent Agent  Agent    Agent  Agent
   │   │   │   │   │   │   │
   └───┴───┴───┴───┴───┴───┘
               │
               ▼
      ┌─────────────────┐
      │  OutputAgent    │  → Risk report generation
      └────────┬────────┘
               │
               ▼
      ┌─────────────────┐
      │  Structured     │
      │  Risk Report    │
      └─────────────────┘
```

The orchestrator dynamically selects the next target, routes it to the appropriate specialist agent, and continues until all discovered indicators have been analyzed.

---

## 🤖 Agents

| Agent | Purpose |
|-------|---------|
| **InputAgent** | Extracts and classifies investigation targets from raw input |
| **OrchestratorAgent** | Supervises routing, prioritization, and workflow coordination |
| **DomainAgent** | Domain, DNS, SSL certificate, and reputation analysis |
| **EmailAgent** | Email reputation, phishing detection, and header forensics |
| **CVEAgent** | Software vulnerability assessment via NVD API |
| **PhoneAgent** | Smishing/vishing investigations and number reputation |
| **FileAgent** | Metadata extraction and malware signature checks |
| **IdentityAgent** | Digital footprint profiling across social platforms |
| **LeakAgent** | Breach and exposure detection via HIBP integration |
| **OutputAgent** | Final report generation with risk scoring |

---

## 📧 Mailbox Watcher

OSINT-Argus includes an automated mailbox monitoring service that continuously polls a configured email account, analyzes incoming messages, and sends structured threat reports back to senders.

### Capabilities

- **Automatic Email Monitoring** – IMAP-based polling for new messages
- **Attachment Analysis** – PDF and file metadata extraction
- **Registration System** – Users register via email to receive an access key
- **Access Key Authentication** – Secure UI access for viewing analysis results
- **Auto-Analyze Mode** – Toggle automatic vs. manual analysis per mailbox
- **Rate Limiting** – Protection against abuse (configurable per sender)
- **Dual-Language Support** – German and English response templates

### Workflow

```
Incoming Email → IMAP Poll → Content Extraction → Pipeline Analysis → SMTP Response
```

---

## 🛠️ Installation

### Prerequisites

- Python 3.10 or higher
- pip package manager
- Access to an OpenAI-compatible LLM API

### Step-by-Step

```bash
# Clone the repository
git clone https://github.com/<your-username>/OSINT-Argus.git
cd OSINT-Argus

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## ⚙️ Configuration

### 1. Environment Variables

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

### 2. LLM Configuration

```env
OPENAI_API_KEY=your_openai_api_key
OPENAI_BASE_URL=https://chat-ai.academiccloud.de/v1
MODEL_NAME=mistral-large-instruct
```

### 3. OSINT API Keys

```env
VT_API_KEY=your_virustotal_api_key
SHODAN_API_KEY=your_shodan_api_key
HIBP_API_KEY=your_hibp_api_key
GITHUB_TOKEN=your_github_pat
```

### 4. Mailbox Watcher (Optional)

```env
# IMAP Settings
MONITOR_MAILBOX_IMAP_SERVER=imap.gmail.com
MONITOR_MAILBOX_IMAP_PORT=993
MONITOR_MAILBOX_ADDRESS=your-email@gmail.com
MONITOR_MAILBOX_PASSWORD=your_app_password

# SMTP Settings
MONITOR_SMTP_SERVER=smtp.gmail.com
MONITOR_SMTP_PORT=587
MONITOR_SMTP_USE_TLS=true

# Auto-Analyze Mode (true/false)
MAILBOX_AUTO_ANALYZE=true

# Rate Limiting
RATE_LIMIT_MAX_ANALYSES_PER_SENDER=5
RATE_LIMIT_WINDOW_HOURS=24

# Polling Interval (seconds)
MAILBOX_POLL_INTERVAL_SECONDS=60
```

> **Note for Gmail:** Use an [App Password](https://support.google.com/accounts/answer/185833) instead of your regular password.

---

## 🚀 Usage

### Web UI (Streamlit)

```bash
streamlit run app/ui_main.py
```

Open your browser and navigate to `http://localhost:8501`

### Mailbox Watcher (Background Service)

```bash
python -m app.mailbox_watcher
```

### CLI Mode

```bash
python -m app.main
```

---

## 📥 Supported Inputs

| Input Type | Example | Agent |
|------------|---------|-------|
| **Domain / URL** | `evil-example.com` | DomainAgent |
| **Email Address** | `attacker@malicious.net` | EmailAgent |
| **Email Content** | Full email with headers | EmailAgent |
| **Software Version** | `nginx 1.18.0` | CVEAgent |
| **Phone Number** | `+1-555-123-4567` | PhoneAgent |
| **File Path / Hash** | `suspicious.pdf` / `sha256:...` | FileAgent |
| **Username / Person** | `johndoe` | IdentityAgent |
| **Breach Indicators** | `password123@evil.com` | LeakAgent |

---

## 📦 Tech Stack

### Core Framework
- **LangGraph** – Multi-agent orchestration
- **LangChain** – LLM integration and tooling
- **ChromaDB** – Persistent vector memory

### LLM Provider
- OpenAI-compatible APIs (Mistral, GPT, etc.)

### OSINT Integrations
- **VirusTotal** – File and domain reputation
- **Shodan** – Internet-connected device discovery
- **NVD API** – CVE vulnerability database
- **Have I Been Pwned** – Breach data lookup
- **dnspython** – DNS resolution and record analysis
- **ExifTool** – File metadata extraction
- **Sherlock** – Username enumeration
- **Holehe** – Email account enumeration

### UI & Utilities
- **Streamlit** – Web interface
- **imap-tools** – IMAP email access
- **python-dotenv** – Environment variable management
- **pydantic** – Data validation

---

## 📁 Project Structure

```
OSINT-Argus/
├── app/
│   ├── agents/           # Specialist agent implementations
│   │   ├── base_agent.py
│   │   ├── domain_agent.py
│   │   ├── email_agent.py
│   │   ├── cve_agent.py
│   │   ├── phone_agent.py
│   │   ├── file_agent.py
│   │   ├── identity_agent.py
│   │   ├── leak_agent.py
│   │   ├── input_agent.py
│   │   ├── orchestrator_agent.py
│   │   └── output_agent.py
│   ├── tools/            # OSINT integrations and utilities
│   ├── models/           # Pydantic schemas and data models
│   ├── memory/           # ChromaDB integration
│   ├── ui/               # Streamlit frontend components
│   ├── config.py         # Configuration management
│   ├── graph.py          # LangGraph workflow definition
│   ├── state.py          # Shared state schema
│   ├── main.py           # CLI entry point
│   ├── mailbox_watcher.py # Automated email monitoring
│   ├── mailbox_auth.py   # Registration and access key auth
│   ├── mailbox_store.py  # Mailbox data persistence
│   └── utils/            # Helper utilities
├── .env.example          # Environment template
├── requirements.txt      # Python dependencies
├── start.bat             # Windows launch script
└── README.md             # This file
```

---

## 📄 License

MIT License – See [LICENSE](LICENSE) for details.

---

> **Disclaimer:** OSINT-Argus is intended for defensive security research, authorized OSINT investigations, and cybersecurity education. Use responsibly and in compliance with applicable laws and regulations.
