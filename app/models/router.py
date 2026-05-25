from pydantic import BaseModel, Field
from typing import List, Literal, Optional


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
    
# ── Sprint 2 Part 2: Finaler Risikobericht ────────────────────────────────────
class OutputReport(BaseModel):
    risk_score: int = Field(
        description="Gesamtrisiko-Score von 0 (kein Risiko) bis 100 (kritisches Risiko)",
        ge=0,
        le=100,
    )
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(
        description=(
            "Risikostufe abgeleitet vom Score: "
            "LOW=0-33 (grün), MEDIUM=34-66 (gelb), HIGH=67-84 (rot), CRITICAL=85-100 (rot🚨)"
        )
    )
    explanation: str = Field(
        description="Technische Erklärung der Befunde (3–5 Sätze, für Experten)"
    )
    summary: str = Field(
        description="Einfache Zusammenfassung für Laien ohne Fachjargon (2–3 Sätze)"
    )
    action_advice: str = Field(
        description=(
            "Konkreter, handlungsanleitender Ratschlag was der Nutzer jetzt tun soll. "
            "Spezifisch für den Eingabetyp (Domain / E-Mail). "
            "Beispiele: 'Keine Aktion erforderlich.' / 'Klicke den Link nicht direkt an.' / "
            "'Besuche diese Domain nicht und lösche die E-Mail.'"
        )
    )
    indicators: List[str] = Field(
        description="Die 3–5 wichtigsten Risikoindikatoren als kurze Stichpunkte",
        min_length=0,
        max_length=10,
    )