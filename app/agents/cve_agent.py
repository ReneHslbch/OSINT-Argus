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
from app.prompts import CVE_AGENT_SYSTEM_PROMPT
from app.utils.prompt_cleaner import clean_llm_output

llm = get_llm()

class CVEAgent(BaseAgent):
    def __init__(self):
        prompt = ChatPromptTemplate.from_messages([
            ("system", CVE_AGENT_SYSTEM_PROMPT),
            ("human", "Analysierte diese Technologie-Komponente: {input}"),
            ("placeholder", "{agent_scratchpad}"),
        ])
        agent = create_tool_calling_agent(llm, CVE_TOOLS, prompt)
        self._executor = AgentExecutor(
            agent=agent,
            tools=CVE_TOOLS,
            verbose=False,
            max_iterations=2,
            max_execution_time=15,
            return_intermediate_steps=True
        )

    def run(self, state: ArgusState) -> ArgusState:
        target = state.get("current_check")

        if not target:
            print("[WARN] CVEAgent: Kein Technologie-Target (current_check) zugewiesen.")

        print(f"\n[CVE] Starte NVD-Abfrage fur: '{target}'...")
        
        t0 = time.time()
        try:
            result = self._executor.invoke({"input": target}, config={"callbacks": None})
        except Exception as e:
            print(f"⚠️ [CVE] Fehler oder Timeout bei '{target}': {e}")
            result = {"output": json.dumps({
                "threat_indicators": [],
                "exposure_findings": [],
                "summary": f"Timeout/Fehler bei CVE-Abfrage für {target}"
            })}
        
        elapsed_ms = (time.time() - t0) * 1000
        
        iteration_count = result.get("intermediate_steps", [])
        print(f"   ↳ CVEAgent abgeschlossen in {elapsed_ms:.0f}ms ({len(iteration_count)} Tool-Aufrufe)")
        llm_output = clean_llm_output(result.get("output", ""))

        # Robustes JSON-Parsing
        try:
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
        
        state["memory_context"] = analysis.get("summary", "")

        return {**state, "findings": [finding]}