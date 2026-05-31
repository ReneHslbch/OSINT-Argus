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
        # Listen initialisieren falls nötig
        if state.get("scanned") is None:
            state["scanned"] = []
        if state.get("findings") is None:
            state["findings"] = []

        # ── 1. Update nach dem letzten Sub-Agenten-Lauf ──────────────────────
        last_checked = state.get("current_check")
        if last_checked and last_checked not in state["scanned"]:
            state["scanned"].append(last_checked)
            state["current_check"] = None

        # Berechne die noch offenen Ziele als Hilfestellung für die Logs
        remaining = [item for item in state["to_scan"] if item not in state["scanned"]]

        # Wenn absolut nichts mehr zu tun ist, direkt zum Output
        if not remaining and not state["to_scan"]:
            state["next_agent"] = "output"
            state["current_check"] = None
            return state

        # ── 2. Adaptiver System Prompt für echtes Risiko-Priorisieren ────────
        system_prompt = """Du bist der zentrale Orchestrator von OSINT-Argus.
        Deine Aufgabe ist es, die Liste der Targets ('to_scan') ADAPTIV und INTELLIGENT abzuarbeiten.
        Du musst NICHT alles stumpf scannen. Priorisiere nach Risiko!

        DEINE MÄCHTE:
        1. Filtere Müll: Wenn im Input Textphrasen wie '][**Korrektur**...' oder Erklärungen stehen, wirf sie komplett raus, indem du sie NICHT in 'relevant_targets_remaining' aufnimmst.
        2. Priorisiere Gefahr: Scanne eine verdächtige Typosquatting-Domain (z.B. mailchimp-delivery.com) IMMER vor bekannten, sauberen Cloud-Infrastrukturen (z.B. aws.amazon.com).
        3. Adaptiver Abbruch: Wenn die bisherigen 'Findings' bereits kritisch genug sind (z.B. Domain existiert nicht, extrem hoher Phishing-Verdacht), darfst du den Scan sofort abbrechen! Wähle dann direkt 'output', um zum OutputAgent zu springen.

        Verfügbare Agenten:
        - 'domain': Für Domainnamen, URLs oder IP-Adressen.
        - 'email': Für E-Mail-Adressen oder rohe Mail-Inhalte.
        - 'cve': Für Software-Technologien und Versionen (z.B. 'nginx 1.18.0').
        - 'output': Für den finalen Bericht."""

        user_content = f"""
        Gesamt-Input-Typ: {state.get('input_type')}
        Aktuelle Target-Liste (to_scan): {state['to_scan']}
        Bereits gescannt (scanned): {state['scanned']}
        Noch offen: {remaining}

        Bisherige Findings im System:
        {self._format_findings_for_llm(state)}

        Bestimme das nächste Ziel, filtere die verbleibende Queue und wähle den Agenten.
        """

        # ── 3. LLM Entscheidung anfordern ─────────────────────────────────────
        decision: OrchestratorDecision = self.llm.invoke([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content}
        ])

        # ── 4. State ADAPTIV updaten ──────────────────────────────────────────
        state["next_agent"] = decision.next_agent
        state["current_check"] = decision.current_check

        # Hier passiert die Magie: Die Queue wird durch den KI-Filter ersetzt!
        new_queue = decision.relevant_targets_remaining
        if decision.current_check in new_queue:
            new_queue.remove(decision.current_check)
            
        state["to_scan"] = new_queue

        # Logge die Entscheidung in die Findings-Liste
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