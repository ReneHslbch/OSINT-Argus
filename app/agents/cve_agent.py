import json
import time
from langchain_classic.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate

from app.agents.base_agent import BaseAgent
from app.state import ArgusState
from app.models.llm import get_llm
from app.models.findings import Findings
from app.models.agent_type import AgentType
from app.tools.cve_tools import CVE_TOOLS

llm = get_llm()

SYSTEM_PROMPT_CVE = """Du bist der CVEAgent von OSINT-Argus.
Deine Aufgabe ist es, Technologie-Stacks, Softwarenamen und Versionsnummern auf bekannte Schwachstellen (CVEs) zu prüfen.

Verwende das Tool 'search_nvd_cves', um die übergebene Technologie ('current_check') in der Schwachstellendatenbank zu recherchieren.

Analysiere die Testergebnisse:
- Welche Schwachstellen sind kritisch (CVSS Score >= 7.0)?
- Welche Auswirkungen (z. B. Remote Code Execution, Denial of Service) drohen dem Host?

Erstelle am Ende ein JSON-Objekt mit exakt dieser Struktur:
{{
  "threat_indicators": ["Konkrete Angriffsvektoren oder Exploits, die für diese CVEs bekannt sind"],
  "exposure_findings": ["Liste der gefundenen CVE-IDs mit CVSS-Score und Schweregrad"],
  "summary": "1-2 Sätze technische Zusammenfassung des Technologierisikos auf Deutsch."
}}
Antworte AUSSCHLIESSLICH mit dem validen JSON-Objekt."""

class CVEAgent(BaseAgent):
    def __init__(self):
        prompt = ChatPromptTemplate.from_messages([
            ("system", SYSTEM_PROMPT_CVE),
            ("human", "Analysierte diese Technologie-Komponente: {input}"),
            ("placeholder", "{agent_scratchpad}"),
        ])
        agent = create_tool_calling_agent(llm, CVE_TOOLS, prompt)
        self._executor = AgentExecutor(
            agent=agent,
            tools=CVE_TOOLS,
            verbose=False,
            max_iterations=3,
            return_intermediate_steps=True
        )

    def run(self, state: ArgusState) -> ArgusState:
        target = state.get("current_check")

        if not target:
            print("⚠️ CVEAgent: Kein Technologie-Target (current_check) zugewiesen.")
            return state

        print(f"\n🔍 [CVEAgent] Starte NVD-Abfrage für: '{target}'...")
        
        t0 = time.time()
        result = self._executor.invoke({"input": target})
        elapsed_ms = (time.time() - t0) * 1000
        
        iteration_count = result.get("intermediate_steps", [])
        print(f"   ↳ CVEAgent abgeschlossen in {elapsed_ms:.0f}ms ({len(iteration_count)} Tool-Aufrufe)")
        llm_output = result.get("output", "").strip()

        # Robustes JSON-Parsing
        try:
            if "```" in llm_output:
                content = llm_output.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
                analysis = json.loads(content.strip())
            else:
                analysis = json.loads(llm_output)
        except Exception:
            analysis = {
                "threat_indicators": ["Parsing-Fehler bei CVE-Analyse"],
                "exposure_findings": [],
                "summary": llm_output or "Keine Ausgabe erhalten."
            }

        # Befunde abspeichern
        finding = Findings(
            agent=AgentType.CVE,
            input=target, 
            threat_sum=analysis.get("threat_indicators", []),
            vulnerability_sum=analysis.get("exposure_findings", [])
        )
        state["findings"].append(finding)
        state["memory_context"] = analysis.get("summary", "")

        return state