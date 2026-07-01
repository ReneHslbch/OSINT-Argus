# app/agents/input_agent.py
import json
from pydantic import BaseModel, Field
from typing import Literal, List, Optional
from app.agents.base_agent import BaseAgent
from app.state import ArgusState
from app.models.llm import get_llm
from app.memory.chroma_memory import get_user_profile, save_user_profile
from app.prompts import INPUT_AGENT_SYSTEM_PROMPT, INPUT_AGENT_PROFILER_PROMPT

class InputExtraction(BaseModel):
    input_type: Literal["domain", "email", "text", "phone", "file", "identity", "unknown"] = Field(
        description="Der primäre Typ des empfangenen Gesamt-Inputs."
    )
    extracted_targets: List[str] = Field(
        description="Liste aller extrahierten Entitäten, die gescannt werden müssen (E-Mail-Adressen, Domains, IPs, Telefonnummern, Software-Namen, Identitäten, Hashes oder Dateipfade)."
    )

# NEU: Pydantic Modell für das Text-Profiling (Schritt 2)
class ProfileUpdate(BaseModel):
    extracted_vorname: Optional[str] = Field(None, description="In der Mail/Text genannter Vorname des Absenders oder Empfängers (falls erkennbar uns zuzuordnen).")
    extracted_nachname: Optional[str] = Field(None, description="In der Mail/Text genannter Nachname (z.B. 'Mustermann' aus 'Hallo Herr Mustermann').")
    extracted_email: Optional[str] = Field(None, description="Die mutmaßliche E-Mail-Adresse des Users, falls im Textkontext als seine identifiziert.")
    extracted_telefon: Optional[str] = Field(None, description="Die Telefonnummer des Users, falls im Textkontext als seine identifiziert.")
    kompetenz_level: Literal["LAIE", "GEBILDET", "EXPERTE", "UNVERÄNDERT"] = Field(
        description="Beweist der Text IT-Fachwissen? 'EXPERTE' bei Begriffen wie SubCAs, RSA, OCSP, etc. 'LAIE' bei trivialem Text."
    )
    neue_fachbegriffe: List[str] = Field([], description="Liste neu gefundener IT-Fachbegriffe im Text (z.B. ['OCSP-Responder', 'RSA'])." )
    begruendung: str = Field(description="Kurze Begründung, warum der User so eingestuft wurde.")


class InputAgent(BaseAgent):
    def __init__(self):
        self.llm = get_llm().with_structured_output(InputExtraction)
        # NEU: Separater strukturierter LLM-Aufruf für das Profiling
        self.profiler_llm = get_llm().with_structured_output(ProfileUpdate)

    def run(self, state: ArgusState) -> ArgusState:
        user_input = state["user_input"]

        # 1. Normale Extraktion ausfuhren
        extraction: InputExtraction = self.llm.invoke([
            {"role": "system", "content": INPUT_AGENT_SYSTEM_PROMPT},
            {"role": "user", "content": f"Analysiere folgenden Input und extrahiere alle Einzel-Targets sauber:\n\n{user_input}"}
        ])

        state["input_type"] = extraction.input_type
        state["to_scan"] = extraction.extracted_targets
        state["scanned"] = []
        state["current_check"] = None

        print(f"\n[INPUT] Globaler Typ erkannt: {extraction.input_type.upper()}")
        print(f"[INPUT] {len(extraction.extracted_targets)} Targets extrahiert.")

        # ==============================================================================
        # NEU: LERNENDES NUTZERPROFIL GENERIEREN (SCHRITT 2)
        # ==============================================================================
        if extraction.input_type in ["text", "email"] or len(user_input) > 40:
            print("[INPUT] Analysiere Textkontext fur Benutzerprofilierung...")
            
            # Bestehendes Profil aus ChromaDB laden
            current_profile = get_user_profile()
            
            try:
                update: ProfileUpdate = self.profiler_llm.invoke([
                    {"role": "system", "content": INPUT_AGENT_PROFILER_PROMPT},
                    {"role": "user", "content": f"Aktuelles Profil: {current_profile}\n\nNeuer Input-Text:\n{user_input}"}
                ])
                
                # Werte intelligent mergen (Überschreiben nur, wenn neue Infos gefunden wurden)
                if update.extracted_vorname: current_profile["vorname"] = update.extracted_vorname
                if update.extracted_nachname: current_profile["nachname"] = update.extracted_nachname
                if update.extracted_email: current_profile["email"] = update.extracted_email
                if update.extracted_telefon: current_profile["telefon"] = update.extracted_telefon
                
                if update.kompetenz_level != "UNVERÄNDERT":
                    current_profile["kompetenz_level"] = update.kompetenz_level
                
                # Fachbegriffe ohne Duplikate anfügen
                for word in update.neue_fachbegriffe:
                    if word not in current_profile["fachbegriffe"]:
                        current_profile["fachbegriffe"].append(word)
                        
                current_profile["charakteristik"] = update.begruendung
                
                # Zurück in die ChromaDB schreiben
                save_user_profile(current_profile)
                print(f"[INPUT] Profil aktualisiert: {current_profile['vorname']} {current_profile['nachname']} ({current_profile['kompetenz_level']})")
                
            except Exception as e:
                print(f"[WARN] [INPUT] Profiling fehlgeschlagen: {e}")

        return state