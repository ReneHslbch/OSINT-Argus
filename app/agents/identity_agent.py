from app.agents.base_agent import BaseAgent
from app.models.llm import get_llm
from app.models.findings import Findings
from app.models.agent_type import AgentType
from app.state import ArgusState
from pydantic import BaseModel, Field
from typing import List, Literal

from app.tools.identity_tools import check_email_with_holehe, search_username_with_sherlock

# Pydantic-Schema für die unvorhersehbare, freie Analyse der KI
class IdentityAnalysis(BaseModel):
    social_engineering_vector: str = Field(description="Wie leicht kann diese Person basierend auf den Funden per Spear-Phishing angegriffen werden?")
    risk_assessment: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(description="Gefahreneinstufung der digitalen Identität")
    tracked_profiles: List[str] = Field(description="Liste aller verifizierten Profile oder Plattform-Registrierungen")
    reasoning: str = Field(description="Detaillierte Begründung des Agenten für seine Bewertung")

class IdentityAgent(BaseAgent):

    def __init__(self):
        # Das LLM liefert uns am Ende strukturierte JSON-Befunde
        self.llm = get_llm().with_structured_output(IdentityAnalysis)

    def run(self, state: ArgusState) -> ArgusState:
        target = state.get("current_check")
        if not target:
            return state

        print(f"\n👤 [IdentityAgent] Analysiere digitale Identität für Target: '{target}'")

        # --- REIN NICHT-DETERMINISTISCHE TOOL-AUSWAHL ---
        # Das LLM entscheidet selbstständig anhand des Inputs, welche Tools gefüttert werden!
        osint_raw_data = []

        # Szenario A: Es sieht aus wie eine E-Mail
        if "@" in target:
            holehe_res = check_email_with_holehe.invoke({"email": target})
            osint_raw_data.append(holehe_res)
            
            # Ein smarter Agent sucht auch direkt nach dem Handle vor dem @ bei Sherlock!
            username_handle = target.split("@")[0]
            sherlock_res = search_username_with_sherlock.invoke({"username": username_handle})
            osint_raw_data.append(sherlock_res)
        
        # Szenario B: Es ist ein Klarname oder Handle (z.B. Rene Haselbach)
        else:
            # Handle-Generierung (Leerzeichen entfernen für Sherlock-Suche)
            username_handle = target.replace(" ", "").lower()
            sherlock_res = search_username_with_sherlock.invoke({"username": username_handle})
            osint_raw_data.append(sherlock_res)

        # 4. Jetzt bewertet das LLM autonom das Profilierungsrisiko
        analysis: IdentityAnalysis = self.llm.invoke([
            {
                "role": "system",
                "content": """
Du bist ein psychologischer Profiler und OSINT-Spezialist für Social Engineering.
Analysiere die zurückgelieferten OSINT-Rohdaten einer Person (Sherlock/Holehe).

Bewerte das Spear-Phishing-Potenzial:
- Welche Accounts machen die Person angreifbar? (z.B. GitHub verrät Tech-Stack, LinkedIn verrät Firmenrolle)
- Gibt es eine Korrelation zwischen den Plattformen?
- Welche Betreffzeilen (Pretexte) könnte ein Angreifer bei dieser Person erfolgreich nutzen?

Achtung: Antworte streng objektiv auf Basis der Daten.
"""
            },
            {
                "role": "user",
                "content": f"""
Target-Eingabe: {target}
Ermittelte OSINT-Rohdaten:
{osint_raw_data}
"""
            }
        ])

        # 5. Befunde in die globalen Findings eintragen
        # (Falls AgentType.IDENTITY im Enum existiert, das nutzen, ansonsten erweitern)
        state["findings"].append(
            Findings(
                agent=AgentType.FILE,  # temporär, falls dein Enum noch kein IDENTITY hat
                input=target,
                threat_sum=[f"Spear-Phishing Vektor: {analysis.social_engineering_vector}"],
                vulnerability_sum=analysis.tracked_profiles,
            )
        )

        print(f"👤 [IdentityAgent] {target} abgeschlossen.")
        print(f"⚠️ Profil-Risiko: {analysis.risk_assessment}")
        print(f"🧠 {analysis.reasoning}")

        return state