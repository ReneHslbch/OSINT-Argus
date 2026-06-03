from pydantic import BaseModel, Field
from typing import List, Literal, Optional


class OrchestratorDecision(BaseModel):
    next_agent: Literal[
        "domain",
        "email",
        "cve",
        "phone",
        "file",
        "identity",
        "output"
    ] = Field(
        description="""
    Welcher Agent als nächstes ausgeführt werden soll.

    Routing-Regeln:

    - domain:
    Domains, URLs, Hostnamen, IP-Adressen

    - email:
    E-Mail-Adressen oder komplette E-Mail-Inhalte

    - cve:
    Softwareprodukte, Technologien und Versionsangaben (z.B. nginx 1.18)

    - phone:
    Telefon- oder Mobilnummern

    - file:
    Dateien, Datei-URLs oder kryptografische Datei-Hashes (MD5, SHA1, SHA256).

    - identity:
    Klarnamen von Personen (z.B. 'Rene Haselbach'), Benutzernamen, Social-Media-Handles 
    oder Entwickler-IDs, die aus Metadaten oder Texten extrahiert wurden.

    - output:
    Wenn genügend Informationen vorliegen oder nichts Relevantes mehr zu prüfen ist.
    """
    )
    current_check: str | None = Field(
        None,
        description=(
            "Das EXAKTE Element aus der offenen Liste, das JETZT die höchste Priorität hat und geprüft werden soll. "
            "Setze NULL, wenn next_agent='output'."
        )
    )
    relevant_targets_remaining: List[str] = Field(
        description="Die bereinigte Liste der verbleibenden Targets, die NOCH wichtig sind. Du DARFST Duplikate oder echten Müll rauswerfen. WICHTIG: Valide Namen oder Hashes dürfen NICHT gelöscht werden!"
    )
    reasoning: str = Field(
        description="Strategische Begründung, warum dieses spezifische Element Priorität hat oder warum du adaptiv abbrichst."
    )

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
    threat_score: int = Field(
        description="Bedrohungs-Score von 0 (keine aktive Bedrohung) bis 100 (aktive, bösartige Kampagne/Angreifer)",
        ge=0, le=100
    )
    vulnerability_score: int = Field(
        description="Schwachstellen-Score von 0 (perfekt gehärtet) bis 100 (kritische, offen liegende Sicherheitslücken)",
        ge=0, le=100
    )
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(
        description="Gesamteinstufung basierend auf der Kombination von Bedrohung und Schwachstelle."
    )
    explanation: str = Field(
        description="Technische Erklärung der Befunde (3–5 Sätze, für Experten)."
    )
    summary: str = Field(
        description="Einfache Zusammenfassung für Laien ohne Fachjargon (2–3 Sätze)."
    )
    action_prevent: str = Field(
        description="Präventiver Ratschlag, um Schaden zu verhindern (z.B. 'Auf keinen Fall auf die Links klicken, da...')."
    )
    action_incident_response: List[str] = Field(
        description="Schritt-für-Schritt-Anleitung (chronologische Liste), falls der Nutzer bereits geklickt/reagiert hat (z.B. 1. Netzwerk trennen, 2. PW ändern)."
    )
    indicators: List[str] = Field(
        description="Die wichtigsten Risikoindikatoren als kurze Stichpunkte (max 10)",
        max_length=10
    )