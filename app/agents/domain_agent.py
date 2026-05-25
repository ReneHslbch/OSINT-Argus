import json
from langchain_openai import ChatOpenAI
from langchain_classic.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage

from app.agents.base_agent import BaseAgent
from app.state import ArgusState
from app.tools.whois_tool import run_whois
from app.tools.dns_tool import run_dns_lookup
from app.models.llm import get_llm
from app.tools.domain_tools import run_crtsh, run_urlhaus, run_spf_dmarc_check, run_ssl_check
import os

llm = get_llm()

# ── Tool-Liste ───────────────────────────────────────────────────────────────
DOMAIN_TOOLS = [
    run_whois,
    run_dns_lookup,
    run_crtsh,
    run_urlhaus,
    run_spf_dmarc_check,
    run_ssl_check,
]

# ── System-Prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """Du bist der DomainAgent von OSINT-Argus, einem Cybersecurity-Analyse-System.

Deine Aufgabe: Analysiere eine Domain vollständig und systematisch.

PFLICHTABLAUF — führe IMMER alle diese Tools aus:
1. run_whois          → Domain-Alter, Registrar, Ablauf
2. run_dns_lookup     → DNS-Records (A, MX, NS, TXT)
3. run_crtsh          → Subdomains via Certificate Transparency
4. run_urlhaus        → Malware-Datenbank-Check
5. run_spf_dmarc_check → E-Mail-Sicherheit (SPF, DMARC, DKIM)
6. run_ssl_check      → SSL-Zertifikat-Status

Nach allen Tool-Aufrufen erstelle ein JSON-Objekt mit dieser exakten Struktur:
{{
  "threat_indicators": ["Liste konkreter Bedrohungsindikatoren (z.B. fehlende Records)"],
  "exposure_findings": ["Liste konkreter Schwachstellen oder Risiken"],
  "summary": "2-3 Sätze Gesamtbewertung auf Deutsch"
}}

Antworte AUSSCHLIESSLICH mit dem validen JSON-Objekt. Keine Erklärungen drumherum, kein Text vor oder nach dem JSON."""


class DomainAgent(BaseAgent):

    def __init__(self):
        prompt = ChatPromptTemplate.from_messages([
            ("system", SYSTEM_PROMPT),
            ("human", "{input}"),
            ("placeholder", "{agent_scratchpad}"),
        ])
        agent = create_tool_calling_agent(llm, DOMAIN_TOOLS, prompt)
        self._executor = AgentExecutor(
            agent=agent,
            tools=DOMAIN_TOOLS,
            verbose=True,          # Zeigt Tool-Aufrufe im Terminal
            max_iterations=12,     # Alle 6 Tools + Puffer
            return_intermediate_steps=True,
        )

    def run(self, state: ArgusState) -> ArgusState:
        domain = state.get("current_domain") or state["user_input"]

        # ── Agent ausführen ──────────────────────────────────────────────────
        result = self._executor.invoke({
            "input": (
                f"Analysiere die Domain: {domain}\n"
                f"Führe alle 6 Tools aus und erstelle den JSON-Report."
            )
        })

        # ── Tool-Rohdaten extrahieren ────────────────────────────────────────
        raw_tool_data = {}
        for action, observation in result.get("intermediate_steps", []):
            tool_name = action.tool
            try:
                raw_tool_data[tool_name] = (
                    json.loads(observation)
                    if isinstance(observation, str)
                    else observation
                )
            except (json.JSONDecodeError, TypeError):
                raw_tool_data[tool_name] = {"raw": str(observation)}

        # ── LLM-Analyse robust parsen ────────────────────────────────────────
        llm_output = result.get("output", "").strip()
        analysis = None

        try:
            # Fall 1: LLM hat Markdown-Fences benutzt (```json ... ```)
            if "```" in llm_output:
                content = llm_output.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
                analysis = json.loads(content.strip())
            else:
                # Fall 2: LLM hat das JSON direkt als nackten String ausgegeben
                analysis = json.loads(llm_output)
        except (json.JSONDecodeError, IndexError, ValueError):
            # Fallback, falls das Parsing komplett fehlschlägt
            analysis = {
                "threat_indicators": [],
                "exposure_findings": ["Fehler beim Parsen der LLM-Antwort."],
                "summary": llm_output if llm_output else "Keine Ausgabe vom LLM erhalten."
            }

        # ── State befüllen ───────────────────────────────────────────────────
        state["findings"].append({
            "agent": "DomainAgent",
            "domain": domain,
            # Rohdaten aller Tools
            "whois":   raw_tool_data.get("run_whois", {}),
            "dns":     raw_tool_data.get("run_dns_lookup", {}),
            "crtsh":   raw_tool_data.get("run_crtsh", {}),
            "urlhaus": raw_tool_data.get("run_urlhaus", {}),
            "email_security": raw_tool_data.get("run_spf_dmarc_check", {}),
            "ssl":     raw_tool_data.get("run_ssl_check", {}),
            # Strukturierte KI-Analyse
            "ai_analysis": analysis,
        })

        # Da im Sprint 1 kein globaler Risk-Score gefordert ist,
        # belassen wir ihn einfach unverändert oder auf dem Initialwert.
        
        # visited_agents pflegen
        visited = state.get("visited_agents", [])
        visited.append("domain")
        state["visited_agents"] = visited

        return state