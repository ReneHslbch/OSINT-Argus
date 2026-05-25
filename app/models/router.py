from pydantic import BaseModel, Field
from typing import Literal, Optional


# ── Sprint 1: Initiales Routing ──────────────────────────────────────────────
class RouteDecision(BaseModel):
    input_type: Literal["domain", "email", "url", "unknown"] = Field(
        description="Detected input type"
    )
    next_agent: Literal["domain", "email", "cve", "output"] = Field(
        description="Next agent to execute"
    )
    reasoning: str = Field(
        description="Why this route was selected"
    )


# ── Sprint 2: Adaptives Routing innerhalb der Email-Pipeline ─────────────────
class EmailPipelineDecision(BaseModel):
    action: Literal["scan_domain", "proceed_to_judgement", "proceed_to_output"] = Field(
        description="Nächste Aktion in der Email-Pipeline"
    )
    target_domain: Optional[str] = Field(
        default=None,
        description="Nur bei action=scan_domain: welche Domain als nächstes scannen"
    )
    reasoning: str = Field(
        description="Warum diese Entscheidung — wird in findings geloggt"
    )
    confidence: Literal["LOW", "MEDIUM", "HIGH"] = Field(
        description="Wie sicher ist der Orchestrator über diese Entscheidung"
    )