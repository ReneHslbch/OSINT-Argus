from dataclasses import dataclass

from app.models.agent_type import AgentType


@dataclass
class Findings:
    agent: AgentType
    input: str
    threat_sum: list[str]
    vulnerability_sum: list[str]