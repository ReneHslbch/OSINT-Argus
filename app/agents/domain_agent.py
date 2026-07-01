import json
import time
from langchain_core.prompts import ChatPromptTemplate
from langchain_classic.agents import AgentExecutor, create_tool_calling_agent

from app.agents.base_agent import BaseAgent
from app.state import ArgusState
from app.models.llm import get_llm
from app.models.findings import Findings
from app.models.agent_type import AgentType
from app.tools.domain_tools import DOMAIN_TOOLS  # Lädt alle deine echten OSINT-Tools

llm = get_llm()

SYSTEM_PROMPT_DOMAIN = """Du bist der DomainAgent von OSINT-Argus.
Deine Aufgabe: Analysiere die übergebene Domain mithilfe der bereitgestellten OSINT-Tools.
Sammle öffentliche Daten über DNS, WHOIS, SSL/TLS, E-Mail-Sicherheit (SPF/DMARC), Malware-Reputation (URLhaus) und Web-Technologien.

Deine Kernaufgabe ist die Triage:
1. Identifiziere Bedrohungen (Threats) wie Malware-Einträge oder bösartige Infrastruktur.
2. Identifiziere Schwachstellen (Vulnerabilities) wie fehlende Mail-Sicherheits-Header, abgelaufene Zertifikate oder veraltete Technologien.
3. Extrahiere Subdomains und genutzte Web-Technologien (z. B. "nginx 1.18.0", "WordPress"), damit sie im System weiterverarbeitet werden können.

Erstelle am Ende ein JSON-Objekt mit exakt dieser Struktur:
{{
  "threat_indicators": ["Liste konkreter Bedrohungen / Malware-Befunde"],
  "exposure_findings": ["Liste von Schwachstellen / Fehlkonfigurationen / SSL-Problemen"],
  "discovered_subdomains": ["Liste von neu entdeckten Subdomains, die weiter untersucht werden sollten"],
  "discovered_technologies": ["Liste identifizierter Technologien mit Version für den CVEAgent, z.B. 'nginx 1.18.0'"],
  "summary": "2-3 Sätze prägnante Gesamtbewertung der Domain auf Deutsch."
}}

WICHTIG: Falls ein Tool wie 'run_crtsh' oder 'run_tech_detection' keine Subdomains oder Technologien findet, lasse die Listen einfach leer [].
Antworte AUSSCHLIESSLICH mit dem validen JSON-Objekt."""

class DomainAgent(BaseAgent):
    def __init__(self):
        prompt = ChatPromptTemplate.from_messages([
            ("system", SYSTEM_PROMPT_DOMAIN),
            ("human", "Analysiere diese Domain auf Sicherheitsrisiken und Technologien: {input}"),
            ("placeholder", "{agent_scratchpad}"),
        ])
        # Erstellt den Agenten mit deinen echten domain_tools
        agent = create_tool_calling_agent(llm, DOMAIN_TOOLS, prompt)
        self._executor = AgentExecutor(
            agent=agent,
            tools=DOMAIN_TOOLS,
            verbose=False,
            max_iterations=6,
            return_intermediate_steps=True
        )

    def run(self, state: ArgusState) -> ArgusState:
        target = state.get("current_check")
        
        if not target:
            print("⚠️ DomainAgent: Kein Target (Domain) zum Prüfen übergeben.")
            return state

        print(f"\n🌐 [DomainAgent] Starte OSINT-Reconnaissance für: {target}...")
        
        t0 = time.time()
        result = self._executor.invoke({"input": target})
        elapsed_ms = (time.time() - t0) * 1000
        
        iteration_count = result.get("intermediate_steps", [])
        print(f"   ↳ DomainAgent abgeschlossen in {elapsed_ms:.0f}ms ({len(iteration_count)} Tool-Aufrufe)")
        llm_output = result.get("output", "").strip()

        # Robustes JSON Parsing der LLM-Ausgabe
        try:
            if "```" in llm_output:
                content = llm_output.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
                analysis = json.loads(content.strip())
            else:
                analysis = json.loads(llm_output)
        except Exception:
            # Fallback bei Parsing-Fehlern
            analysis = {
                "threat_indicators": [],
                "exposure_findings": ["Parsing-Fehler bei LLM-Ausgabe"],
                "discovered_subdomains": [],
                "discovered_technologies": [],
                "summary": llm_output or "Keine strukturierte Ausgabe erhalten."
            }

        # ── VARIANTE 1: STATE DYNAMISCH ERWEITERN ───────────────────────────
        
        # 1. Neue Subdomains in die Queue werfen
        #new_subs = analysis.get("discovered_subdomains", [])
        #if new_subs:
         #   print(f"➕ [DomainAgent] {len(new_subs)} neue Subdomains entdeckt und an 'to_scan' angehängt.")
          #  state["to_scan"].extend(new_subs)

        # 2. Erkannte Technologien für den CVEAgent in die Queue werfen
        new_techs = analysis.get("discovered_technologies", [])
        if new_techs:
            print(f"➕ [DomainAgent] {len(new_techs)} Technologien für CVE-Suche extrahiert ({', '.join(new_techs)}).")
            state["to_scan"].extend(new_techs)
            
        # ───────────────────────────────────────────────────────────────────

        # Dataclass Instanz erzeugen und an findings hängen
        finding = Findings(
            agent=AgentType.DOMAIN,
            input=target,
            threat_sum=analysis.get("threat_indicators", []),
            vulnerability_sum=analysis.get("exposure_findings", [])
        )
        state["findings"].append(finding)
        
        # Speicher die Summary im globalen Kontext ab
        state["memory_context"] = analysis.get("summary", "")

        return state