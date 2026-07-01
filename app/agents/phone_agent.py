import json
import time
from langchain_classic.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate

from app.agents.base_agent import BaseAgent
from app.state import ArgusState
from app.models.llm import get_llm
from app.models.findings import Findings
from app.models.agent_type import AgentType
from app.tools.phone_tools import PHONE_TOOLS
from app.prompts import PHONE_AGENT_SYSTEM_PROMPT

llm = get_llm()

class PhoneAgent(BaseAgent):
    def __init__(self):
        prompt = ChatPromptTemplate.from_messages([
            ("system", PHONE_AGENT_SYSTEM_PROMPT),
            ("human", "Analysiere diese Telefonnummer: {input}"),
            ("placeholder", "{agent_scratchpad}"),
        ])
        agent = create_tool_calling_agent(llm, PHONE_TOOLS, prompt)
        self._executor = AgentExecutor(
            agent=agent,
            tools=PHONE_TOOLS,
            verbose=False,
            max_iterations=3,
            return_intermediate_steps=True
        )

    def run(self, state: ArgusState) -> ArgusState:
        target = state.get("current_check")

        if not target:
            print("[WARN] PhoneAgent: Kein Telefon-Target (current_check) zugewiesen.")

        print(f"\n[PHONE] Analysiere Rufnummer: '{target}'...")
        
        t0 = time.time()
        result = self._executor.invoke({"input": target})
        elapsed_ms = (time.time() - t0) * 1000
        
        iteration_count = result.get("intermediate_steps", [])
        print(f"   ↳ PhoneAgent abgeschlossen in {elapsed_ms:.0f}ms ({len(iteration_count)} Tool-Aufrufe)")
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
                "threat_indicators": ["Parsing-Fehler bei Telefon-Analyse"],
                "exposure_findings": [],
                "summary": llm_output or "Keine Ausgabe erhalten."
            }

        # Befunde in die globale Liste pushen
        finding = Findings(
            agent=AgentType.PHONE,
            input=target, 
            threat_sum=analysis.get("threat_indicators", []),
            vulnerability_sum=analysis.get("exposure_findings", [])
        )
        state["findings"].append(finding)
        state["memory_context"] = analysis.get("summary", "")

        return state