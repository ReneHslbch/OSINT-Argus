import json
from pydantic import BaseModel, Field
from typing import Literal, List
from app.agents.base_agent import BaseAgent
from app.state import ArgusState
from app.models.llm import get_llm

class InputExtraction(BaseModel):
    input_type: Literal["domain", "email", "url", "text", "unknown"] = Field(
        description="Der primäre Typ des empfangenen Gesamt-Inputs."
    )
    extracted_targets: List[str] = Field(
        description="Liste aller extrahierten Entitäten, die gescannt werden müssen (E-Mail-Adressen, Domains, IPs, Software-Namen wie 'nginx 1.18')."
    )

class InputAgent(BaseAgent):
    def __init__(self):
        # Wir zwingen das LLM, strukturiert zu antworten
        self.llm = get_llm().with_structured_output(InputExtraction)

    def run(self, state: ArgusState) -> ArgusState:
        user_input = state["user_input"]

        system_prompt = """Du bist der InputAgent (Triage) von OSINT-Argus.
Deine Aufgabe ist es, den rohen Benutzer-Input zu analysieren.
1. Bestimme den globalen Typ des Inputs ('email', 'domain', 'url', 'text').
2. Extrahiere alle cyber-relevanten Targets, die einer tieferen Analyse unterzogen werden könnten:
   - Wenn es eine E-Mail ist: Nimm den kompletten Mail-Inhalt als ein Target auf, extrahiere aber AUCH alle darin vorkommenden Links/Domains und verdächtige Absender-E-Mails.
   - Wenn es ein Text-Snippet ist: Extrahiere IPs, Domains, Mail-Adressen und Software-Zustände (z.B. 'Apache 2.4').

Sei gründlich. Jedes extrahierte Element landet in der 'to_scan'-Liste des Orchestrators."""

        # LLM aufrufen
        extraction: InputExtraction = self.llm.invoke([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Analysiere folgenden Input:\n\n{user_input}"}
        ])

        # State initialisieren und befüllen
        state["input_type"] = extraction.input_type
        state["to_scan"] = extraction.extracted_targets
        state["scanned"] = []
        state["current_check"] = None

        print(f"\n📥 [InputAgent] Globaler Typ erkannt: {extraction.input_type.upper()}")
        print(f"🎯 [InputAgent] {len(extraction.extracted_targets)} Targets extrahiert für den Orchestrator:")
        for target in extraction.extracted_targets:
            print(f"  → {target}")

        return state