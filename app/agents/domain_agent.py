import json
import time
from langchain_core.prompts import ChatPromptTemplate
from langchain_classic.agents import AgentExecutor, create_tool_calling_agent

from app.agents.base_agent import BaseAgent
from app.state import ArgusState
from app.models.llm import get_llm
from app.models.findings import Findings
from app.models.agent_type import AgentType
from app.tools.domain_tools import DOMAIN_TOOLS
from app.prompts import DOMAIN_AGENT_SYSTEM_PROMPT

llm = get_llm()

class DomainAgent(BaseAgent):
    def __init__(self):
        prompt = ChatPromptTemplate.from_messages([
            ("system", DOMAIN_AGENT_SYSTEM_PROMPT),
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
            print("[WARN] DomainAgent: Kein Target (Domain) zum Prufen ubergeben.")

        print(f"\n[DOMAIN] Starte OSINT-Reconnaissance fur: {target}...")
        
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