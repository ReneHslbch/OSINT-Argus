from app.agents.base_agent import BaseAgent
from app.state import ArgusState
from app.models.llm import get_llm
from app.models.router import RouteDecision, EmailPipelineDecision


class OrchestratorAgent(BaseAgent):

    def __init__(self):
        self.llm = get_llm()

    # ── Email-Pipeline: LLM entscheidet adaptiv ─────────────────────────────
    def _route_email_pipeline(self, state: ArgusState) -> ArgusState:

        # Nach Pass 2 (Judgement) → immer zu Output
        if state.get("email_pass") == 2:
            state["next_agent"] = "output"
            self._log(state, "Email-Analyse abgeschlossen → OutputAgent")
            return state

        # ── Kontext für das LLM aufbauen ─────────────────────────────────────
        extraction      = state.get("email_extraction", {})
        domains_to_scan = state.get("domains_to_scan", [])
        domains_scanned = state.get("domains_scanned", [])
        remaining       = [d for d in domains_to_scan if d not in domains_scanned]

        # Bisherige Domain-Findings als kompakte Summaries
        domain_findings_text = self._format_domain_findings(state)

        # Letzten DomainAgent-Lauf in scanned registrieren
        current = state.get("current_domain")
        if current and current not in domains_scanned:
            domains_scanned.append(current)
            state["domains_scanned"] = domains_scanned
            state["current_domain"]  = None
            remaining = [d for d in domains_to_scan if d not in domains_scanned]

        system_prompt = """Du bist der Orchestrator eines OSINT-Cybersecurity-Systems.

Du analysierst gerade eine E-Mail auf Phishing/Bedrohungen.
Nach jeder Domain-Analyse entscheidest DU ob weitere Analysen nötig sind.

Dein Ziel: So wenig Analysen wie nötig, aber so viele wie für ein sicheres Urteil nötig.

Entscheide dich für eine dieser Aktionen:

1. scan_domain      → Eine weitere Domain analysieren (target_domain angeben)
2. proceed_to_judgement → Genug Daten — EmailAgent soll jetzt das Urteil fällen
3. proceed_to_output → Befund ist so eindeutig (CRITICAL) dass kein weiteres Urteil nötig ist

Wann direkt zu proceed_to_judgement / proceed_to_output:
- Ein klares MALICIOUS / CRITICAL Signal wurde gefunden
- Der Absender ist bereits eindeutig böswillig
- Weitere Analysen würden das Urteil nicht mehr ändern

Wann weitere Domain scannen:
- Absender ist clean aber verdächtige Links noch ungeprüft
- Noch keine klaren Signale, mehr Kontext nötig
"""

        user_content = f"""
E-Mail Metadaten:
- Absender: {extraction.get('headers', {}).get('from', '—')}
- Reply-To Mismatch: {extraction.get('reply_to_check', {}).get('mismatch_detected', False)}
- Gefundene URLs: {len(extraction.get('urls_found', []))}

Bereits gescannte Domains: {domains_scanned or 'keine'}
Noch nicht gescannte Domains: {remaining or 'keine'}

Bisherige Domain-Findings:
{domain_findings_text or 'Noch keine Domain-Analysen durchgeführt.'}

Entscheide was als nächstes passiert.
"""

        decision: EmailPipelineDecision = (
            self.llm
            .with_structured_output(EmailPipelineDecision)
            .invoke([
                {"role": "system",  "content": system_prompt},
                {"role": "user",    "content": user_content},
            ])
        )

        # ── Entscheidung umsetzen ─────────────────────────────────────────────
        if decision.action == "scan_domain" and decision.target_domain:
            state["current_domain"] = decision.target_domain
            state["next_agent"]     = "domain"

        elif decision.action == "proceed_to_judgement":
            state["email_pass"]  = 2
            state["next_agent"]  = "email"

        elif decision.action == "proceed_to_output":
            # So eindeutig — direkt zu Output ohne Pass 2
            state["next_agent"] = "output"
            # Minimale Summary setzen damit OutputAgent etwas hat
            state["summary"] = self._extract_critical_summary(state)

        self._log(
            state,
            f"action={decision.action} | "
            f"confidence={decision.confidence} | "
            f"{decision.reasoning}"
        )

        return state

    # ── Domain-Findings für LLM-Kontext formatieren ─────────────────────────
    def _format_domain_findings(self, state: ArgusState) -> str:
        lines = []
        for f in state["findings"]:
            if f.get("agent") != "DomainAgent":
                continue
            ai = f.get("ai_analysis", {})
            lines.append(
                f"• {f.get('domain')}:\n"
                f"    Bedrohungen:   {ai.get('threat_indicators', [])}\n"
                f"    Schwachstellen:{ai.get('exposure_findings', [])}\n"
                f"    Bewertung:     {ai.get('summary', '—')}"
            )
        return "\n".join(lines)

    def _extract_critical_summary(self, state: ArgusState) -> str:
        """Notfall-Summary wenn direkt zu Output gesprungen wird."""
        for f in reversed(state["findings"]):
            if f.get("agent") == "DomainAgent":
                return f.get("ai_analysis", {}).get("summary", "Kritischer Befund erkannt.")
        return "Kritischer Befund erkannt — Analyse abgebrochen."

    def _log(self, state: ArgusState, reasoning: str):
        state["findings"].append({
            "agent": "OrchestratorAgent",
            "decision": {
                "next_agent": state.get("next_agent"),
                "reasoning":  reasoning,
            }
        })

    # ── Haupt-Run ────────────────────────────────────────────────────────────
    def run(self, state: ArgusState) -> ArgusState:

        # Bereits in Email-Pipeline → adaptives LLM-Routing
        if state.get("input_type") == "email":
            return self._route_email_pipeline(state)

        # ── Erster Aufruf: initiales Routing per LLM ─────────────────────────
        system_prompt = """
You are the routing supervisor of an OSINT cybersecurity system.
Classify the user input and decide which agent should run next.

Available agents:
- domain  → domain names (e.g. example.com)
- email   → email content / phishing analysis  
- cve     → CVE IDs or vulnerability topics
- output  → unknown or unclassifiable input

Return structured output only.
"""
        decision = (
            self.llm
            .with_structured_output(RouteDecision)
            .invoke([
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": state["user_input"]},
            ])
        )

        state["input_type"] = decision.input_type
        state["next_agent"] = decision.next_agent
        state["findings"].append({
            "agent":    "OrchestratorAgent",
            "decision": decision.model_dump(),
        })

        # Email-Pipeline-Felder initialisieren
        if decision.next_agent == "email":
            state["email_pass"]       = 1
            state["domains_to_scan"]  = []
            state["domains_scanned"]  = []
            state["current_domain"]   = None
            state["email_extraction"] = None

        return state