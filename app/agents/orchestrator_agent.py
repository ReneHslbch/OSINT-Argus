from app.agents.base_agent import BaseAgent
from app.models.router import OrchestratorDecision
from app.state import ArgusState
from app.models.llm import get_llm
from app.models.findings import Findings
from app.models.agent_type import AgentType

class OrchestratorAgent(BaseAgent):

    def __init__(self):
        # Wir nutzen das LLM mit erzwungener Struktur
        self.llm = get_llm().with_structured_output(OrchestratorDecision)

    def _log_decision(self, state: ArgusState, decision: OrchestratorDecision):
        """Erstellt ein echtes Findings-Objekt für den State."""
        log_finding = Findings(
            agent=AgentType.ORCHESTRATOR,
            input=decision.current_check or "Orchestration",
            threat_sum=[f"Routing -> {decision.next_agent}"],
            vulnerability_sum=[decision.reasoning]
        )
        state["findings"].append(log_finding)

    def run(self, state: ArgusState) -> ArgusState:
        if state.get("scanned") is None:
            state["scanned"] = []
        if state.get("findings") is None:
            state["findings"] = []

        last_checked = state.get("current_check")
        if last_checked and last_checked not in state["scanned"]:
            state["scanned"].append(last_checked)
            state["current_check"] = None

        remaining = [item for item in state["to_scan"] if item not in state["scanned"]]

        if not remaining and not state["to_scan"]:
            state["next_agent"] = "output"
            state["current_check"] = None
            return state

        # Überarbeiteter, präziser Prompt:
        system_prompt = """Du bist der zentrale Orchestrator von OSINT-Argus.
Deine Aufgabe ist es, die Liste der Targets ('to_scan') ADAPTIV und INTELLIGENT abzuarbeiten.
Priorisiere nach Risiko und leite die Targets an die richtigen Spezialagenten weiter.

VERFÜGBARE AGENTEN & ZIEL-ZUORDNUNG:
- 'domain': Für Domainnamen, URLs oder IP-Adressen.
- 'email': Für E-Mail-Adressen.
- 'cve': Für Software-Technologien und Versionen (z.B. 'nginx 1.18.0').
- 'phone': Für Handy-/Telefonnummern.
- 'file': Für lokale Dateipfade, Dokumente, PDFs sowie Datei-Hashes (MD5, SHA256).
- 'identity': Für extrahierte Klarnamen von Personen (z.B. 'Rene Haselbach'), Usernames oder Social-Media-Handles.
- 'output': Für den finalen Bericht (wenn die Queue leer ist oder adaptiv abgebrochen wird).

STRATEGISCHE QUEUE-REGELN:
1. Wenn ein vorheriger Agent ein neues Target (wie z.B. einen Autorennahmen aus einer PDF) in die Target-Liste gelegt hat, musst du diesen zwingend beachten!
2. Ein Personenname ist KEIN Müll. Setze ihn als 'current_check' und übergebe ihn an den 'identity'-Agenten.
3. Behalte alle anderen noch nicht gescannten Targets unbedingt in der Liste 'relevant_targets_remaining' bei!
"""
        
        user_content = f"""
        Gesamt-Input-Typ: {state.get('input_type')}
        Aktuelle Target-Liste (to_scan): {state['to_scan']}
        Bereits gescannt (scanned): {state['scanned']}
        Noch offen: {remaining}

        Bisherige Findings im System:
        {self._format_findings_for_llm(state)}

        Bestimme das nächste Ziel, filtere die verbleibende Queue und wähle den Agenten.
        """

        decision: OrchestratorDecision = self.llm.invoke([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content}
        ])

        state["next_agent"] = decision.next_agent
        state["current_check"] = decision.current_check

        new_queue = decision.relevant_targets_remaining
        if decision.current_check in new_queue:
            new_queue.remove(decision.current_check)
            
        state["to_scan"] = new_queue
        self._log_decision(state, decision)

        print(f"\n🧠 [Orchestrator KI] Route zu: → {decision.next_agent} | Target: '{decision.current_check}'")
        print(f"   ↳ Begründung: {decision.reasoning}")
        print(f"   ↳ Queue-Größe angepasst auf: {len(state['to_scan'])} verbleibende Targets.")

        return state

    def _format_findings_for_llm(self, state: ArgusState) -> str:
        """Formatiert die bisherigen Findings-Objekte kompakt für das LLM."""
        if not state["findings"]:
            return "- Keine bisherigen Befunde."
        
        lines = []
        for f in state["findings"]:
            # Da f eine Dataclass ist, greifen wir per Attribut zu, nicht per .get()
            lines.append(
                f"[{f.agent.value if hasattr(f.agent, 'value') else f.agent}] "
                f"Target: {f.input} | Threats: {f.threat_sum} | Vulns: {f.vulnerability_sum}"
            )
        return "\n".join(lines)