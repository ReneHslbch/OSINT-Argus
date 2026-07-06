from langchain_classic.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate
import json
import time
from app.agents.base_agent import BaseAgent
from app.state import ArgusState
from app.models.llm import get_llm
from app.models.findings import Findings
from app.models.agent_type import AgentType
from app.tools.email_tools import EMAIL_TOOLS
from app.prompts import EMAIL_AGENT_SYSTEM_PROMPT
from app.utils.prompt_cleaner import clean_llm_output

llm = get_llm()

class EmailAgent(BaseAgent):
    def __init__(self):
        prompt = ChatPromptTemplate.from_messages([
            ("system", EMAIL_AGENT_SYSTEM_PROMPT),
            ("human", "Analysiere dieses spezifische Target: {input}"),
            ("placeholder", "{agent_scratchpad}"),
        ])
        agent = create_tool_calling_agent(llm, EMAIL_TOOLS, prompt)
        self._executor = AgentExecutor(
            agent=agent,
            tools=EMAIL_TOOLS,
            verbose=False,
            max_iterations=4,
            return_intermediate_steps=True
        )

    def run(self, state: ArgusState) -> ArgusState:
        target = state.get("current_check")

        if not target:
            print("[WARN] EmailAgent: Kein Target (current_check) zugewiesen.")

        if len(target) > 150:
            print(f"\n[EMAIL] Analysiere E-Mail-Textinhalt ({len(target)} Zeichen)...")
        else:
            print(f"\n[EMAIL] Analysiere E-Mail-Strukturelement: '{target}'...")
        
        t0 = time.time()
        result = self._executor.invoke({"input": target})
        elapsed_ms = (time.time() - t0) * 1000
        
        iteration_count = result.get("intermediate_steps", [])
        print(f"   ↳ EmailAgent abgeschlossen in {elapsed_ms:.0f}ms ({len(iteration_count)} Tool-Aufrufe)")
        llm_output = clean_llm_output(result.get("output", ""))

        # Robustes JSON-Parsing
        try:
            analysis = json.loads(llm_output)
        except Exception:
            analysis = {
                "threat_indicators": ["Parsing-Fehler bei der strukturierten Textanalyse"],
                "exposure_findings": [],
                "summary": llm_output or "Keine Ausgabe erhalten."
            }

        # Befunde in den State schreiben
        finding = Findings(
            agent=AgentType.EMAIL,
            input=target if len(target) < 60 else (target[:60] + "..."), 
            threat_sum=analysis.get("threat_indicators", []),
            vulnerability_sum=analysis.get("exposure_findings", [])
        )
        
        state["memory_context"] = analysis.get("summary", "")

        return {**state, "findings": [finding]}