import json
from pydantic import BaseModel, Field
from typing import Literal, List
from app.agents.base_agent import BaseAgent
from app.state import ArgusState
from app.models.llm import get_llm

class InputExtraction(BaseModel):
    input_type: Literal["domain", "email", "url", "text", "phone", "file", "identity", "unknown"] = Field(
        description="Der primäre Typ des empfangenen Gesamt-Inputs."
    )
    extracted_targets: List[str] = Field(
        description="Liste aller extrahierten Entitäten, die gescannt werden müssen (E-Mail-Adressen, Domains, IPs, Telefonnummern, Software-Namen, Identitäten, Hashes oder Dateipfade)."
    )

class InputAgent(BaseAgent):
    def __init__(self):
        # Wir zwingen das LLM, strukturiert zu antworten
        self.llm = get_llm().with_structured_output(InputExtraction)

    def run(self, state: ArgusState) -> ArgusState:
        user_input = state["user_input"]

        system_prompt = """Du bist der InputAgent (Triage) von OSINT-Argus.
Deine Aufgabe ist es, den rohen Benutzer-Input zu analysieren und strukturierte Angriffsziele (Targets) zu extrahieren.

1. Bestimme den globalen Typ des Inputs. Nutze strikt einen dieser Werte: 'domain', 'email', 'url', 'text', 'phone', 'file', 'identity', 'unknown'.

2. Extrahiere alle cyber-relevanten Einzel-Targets für die 'to_scan'-Liste des Orchestrators:
   - IPs, Domains, URLs, E-Mail-Adressen und Telefonnummern.
   - Software-Zustände (z.B. 'nginx 1.18', 'Apache 2.4').
   - Krypto-Hashes (MD5, SHA1, SHA256) und vollständige lokale Dateipfade (z.B. 'C:\\Ordner\\datei.pdf' oder '/var/log/syslog').

WICHTIGE EXTRAKTIONS-REGELN:
- Extrahiere NUR den nackten, bereinigten Wert der Entität.
- Füge NIEMALS erklärenden Text, Labels oder Beschreibungen in ein Target ein. 
  * Falsch: "MD5-Hash (Datei-Indikator)" oder "SHA256: e3b0c4..."
  * Richtig: "e3b0c4..." (nur der Hash selbst)
- Wenn der Input eine E-Mail oder ein längerer Text ist, durchsuche den gesamten Text akribisch nach eingebetteten Hashes, IP-Adressen und Dateipfaden und nimm sie alle als separate, isolierte Elemente in die Liste auf."""

        # LLM aufrufen
        extraction: InputExtraction = self.llm.invoke([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Analysiere folgenden Input und extrahiere alle Einzel-Targets sauber:\n\n{user_input}"}
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