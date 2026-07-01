from langchain_classic.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate
import json
import time
from app.agents.base_agent import BaseAgent
from app.state import ArgusState
from app.models.llm import get_llm
from app.models.findings import Findings
from app.models.agent_type import AgentType
from app.tools.email_tools import EMAIL_TOOLS

llm = get_llm()

SYSTEM_PROMPT_EMAIL = """Du bist der EmailAgent von OSINT-Argus, spezialisiert auf die Erkennung von Social Engineering und technischem Betrug.

Deine Aufgabe ist es, das zugewiesene Target ('current_check') tiefenanalytisch zu prüfen.

FALL 1: Das Target ist eine E-Mail-Adresse oder reine Domain:
- Nutze 'check_virustotal_email_domain' und 'check_phishing_blacklist', um die technische Reputation zu ermitteln.

FALL 2: Das Target ist ein E-Mail-Inhalt / Textkörper (Message Content):
- Analysiere den Text direkt (ohne Tools) auf Phishing-Muster. Du musst den Text auf folgende 4 linguistische Vektoren prüfen:
  1. Authority & Scarcity (Erzeugt der Text künstlichen Zeitdruck, Angst vor Kontosperrung oder droht mit Konsequenzen?)
  2. Impersonation-Qualität (Wie gut imitiert der Text ein echtes Unternehmen? Gibt es Widersprüche zwischen dem Inhalt und bekannten Markenstandards?)
  3. Call-to-Action Anomalien (Werden sensible Daten verlangt oder soll der Nutzer unüberlegt auf Links/Anhänge klicken?)
  4. Technische Artefakte (Gibt es fehlerhafte Zeichenkodierungen wie '???', auffällige Grammatikfehler oder Übersetzungs-Glitches?)

Erstelle am Ende ein JSON-Objekt mit exakt dieser Struktur:
{{
  "threat_indicators": ["Konkrete textuelle, psychologische oder inhaltliche Phishing-Indikatoren"],
  "exposure_findings": ["Technische Funde, z.B. Blacklist-Einträge, VT-Reputation oder kritische Header-Mismatches"],
  "summary": "Prägnante, 2-3 Sätze lange cyber-forensische Gesamtbewertung des Inhalts auf Deutsch."
}}
Antworte AUSSCHLIESSLICH mit dem validen JSON-Objekt. Verwende kein Markdown um das JSON herum, außer den reinen Text."""

class EmailAgent(BaseAgent):
    def __init__(self):
        prompt = ChatPromptTemplate.from_messages([
            ("system", SYSTEM_PROMPT_EMAIL),
            ("human", "Analysiere dieses spezifische Target: {input}"),
            ("placeholder", "{agent_scratchpad}"),
        ])
        agent = create_tool_calling_agent(llm, EMAIL_TOOLS, prompt)
        self._executor = AgentExecutor(
            agent=agent,
            tools=EMAIL_TOOLS,
            verbose=False,
            max_iterations=4,
            return_intermediate_steps=True
        )

    def run(self, state: ArgusState) -> ArgusState:
        target = state.get("current_check")

        if not target:
            print("⚠️ EmailAgent: Kein Target (current_check) zugewiesen.")
            return state

        if len(target) > 150:
            print(f"\n📬 [EmailAgent] Analysiere E-Mail-Textinhalt ({len(target)} Zeichen)...")
        else:
            print(f"\n📬 [EmailAgent] Analysiere E-Mail-Strukturelement: '{target}'...")
        
        t0 = time.time()
        result = self._executor.invoke({"input": target})
        elapsed_ms = (time.time() - t0) * 1000
        
        iteration_count = result.get("intermediate_steps", [])
        print(f"   ↳ EmailAgent abgeschlossen in {elapsed_ms:.0f}ms ({len(iteration_count)} Tool-Aufrufe)")
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
                "threat_indicators": ["Parsing-Fehler bei der strukturierten Textanalyse"],
                "exposure_findings": [],
                "summary": llm_output or "Keine Ausgabe erhalten."
            }

        # Befunde in den State schreiben
        finding = Findings(
            agent=AgentType.EMAIL,
            input=target if len(target) < 60 else (target[:60] + "..."), 
            threat_sum=analysis.get("threat_indicators", []),
            vulnerability_sum=analysis.get("exposure_findings", [])
        )
        state["findings"].append(finding)
        state["memory_context"] = analysis.get("summary", "")

        return state