from app.agents.base_agent import BaseAgent
from app.models.router import OrchestratorDecision
from app.state import ArgusState
from app.models.llm import get_llm
from app.models.findings import Findings
from app.models.agent_type import AgentType
from app.tools.classifier import classify_input
from app.prompts import ORCHESTRATOR_SYSTEM_PROMPT
from app.utils.prompt_cleaner import clean_llm_output

AGENT_MAPPING = {
    "email": "email",
    "domain": "domain",
    "unknown": None,
}

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

        # Filtere Duplikate aus der Queue (behalte nur erste Vorkommnis)
        seen = set()
        unique_remaining = []
        for item in remaining:
            if item not in seen:
                seen.add(item)
                unique_remaining.append(item)
        remaining = unique_remaining

        if not remaining and not state["to_scan"]:
            state["next_agent"] = "output"
            state["current_check"] = None
            return state

        current_target = remaining[0] if remaining else state["to_scan"][0] if state["to_scan"] else None
        
        if current_target:
            classification = classify_input(current_target)
            mapped_agent = AGENT_MAPPING.get(classification)
            
            if mapped_agent:
                state["next_agent"] = mapped_agent
                state["current_check"] = current_target
                
                new_queue = list(remaining)
                if current_target in new_queue:
                    new_queue.remove(current_target)
                state["to_scan"] = new_queue
                
                print(f"\n[ORCH] Klassifikation: {classification} -> Route zu: {mapped_agent} | Target: '{current_target}'")
                print(f"   Queue-GrOBe: {len(state['to_scan'])} verbleibende Targets.")
                
                log_finding = Findings(
                    agent=AgentType.ORCHESTRATOR,
                    input=current_target,
                    threat_sum=[f"Routing (Regex) -> {mapped_agent}"],
                    vulnerability_sum=[f"Deterministisches Routing via Regex-Klassifikation: {classification}"]
                )
                state["findings"].append(log_finding)
                
                return state

        user_content = f"""
        Gesamt-Input-Typ: {state.get('input_type')}
        Aktuelle Target-Liste (to_scan): {state['to_scan']}
        Bereits gescannt (scanned): {state['scanned']}
        Noch offen: {remaining}

        Bisherige Findings im System:
        {self._format_findings_for_llm(state)}

        Bestimme das nächste Ziel, filtere die verbleibende Queue und wähle den Agenten.
        """

        decision_raw = self.llm.invoke([
            {"role": "system", "content": ORCHESTRATOR_SYSTEM_PROMPT},
            {"role": "user", "content": user_content}
        ])
        
        # Structured output sollte bereits sauber sein
        if hasattr(decision_raw, 'model_dump'):
            decision = decision_raw
        else:
            cleaned = clean_llm_output(str(decision_raw))
            decision = OrchestratorDecision(**json.loads(cleaned))

        state["next_agent"] = decision.next_agent
        state["current_check"] = decision.current_check

        new_queue = decision.relevant_targets_remaining
        if decision.current_check in new_queue:
            new_queue.remove(decision.current_check)
            
        state["to_scan"] = new_queue
        self._log_decision(state, decision)

        print(f"\n[ORCH] Route zu: {decision.next_agent} | Target: '{decision.current_check}'")
        print(f"   Begrundung: {decision.reasoning}")
        print(f"   Queue-GrOBe angepasst auf: {len(state['to_scan'])} verbleibende Targets.")

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