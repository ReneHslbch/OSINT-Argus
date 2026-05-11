from app.agents.base_agent import BaseAgent
from app.state import ArgusState

from app.models.llm import get_llm
from app.models.router import RouteDecision


class OrchestratorAgent(BaseAgent):

    def __init__(self):
        self.llm = get_llm()

    def run(self, state: ArgusState) -> ArgusState:

        user_input = state["user_input"]

        system_prompt = """
You are the routing supervisor of an OSINT cybersecurity system.

Your task:
1. Classify the user input
2. Decide which agent should run next

Available agents:
- domain
- email
- cve
- output

Rules:
- Domains go to domain
- Emails go to email
- Security vulnerability topics go to cve
- Unknown inputs go to output

Return structured output only.
"""

        decision = self.llm.with_structured_output(
            RouteDecision
        ).invoke([
            {
                "role": "system",
                "content": system_prompt,
            },
            {
                "role": "user",
                "content": user_input,
            },
        ])

        state["input_type"] = decision.input_type
        state["next_agent"] = decision.next_agent

        state["findings"].append({
            "agent": "OrchestratorAgent",
            "decision": decision.model_dump(),
        })

        return state