import json
from langchain_core.prompts import ChatPromptTemplate
from app.agents.base_agent import BaseAgent
from app.models.router import OutputReport
from app.state import ArgusState
from app.models.llm import get_llm
from app.models.findings import Findings
from app.models.agent_type import AgentType
from app.memory.chroma_memory import save_analysis
from app.prompts import OUTPUT_AGENT_SYSTEM_PROMPT

llm = get_llm().with_config(request_timeout=60)

OUTPUT_AGENT_SYSTEM_PROMPT_DE = """Du bist der OutputAgent von OSINT-Argus. Deine Aufgabe ist es, aus allen gesammelten Agenten-Findings einen finalen Cybersecurity-Risikobericht zu generieren.

Analysiere die Findings aus zwei Perspektiven:
1. Threat Score (0-100): Gibt es Anzeichen für aktive Angreifer, Phishing, Malware oder böswillige Absichten?
2. Vulnerability Score (0-100): Gibt es offene Schwachstellen? (Fehlendes SPF/DMARC, abgelaufenes SSL, CVEs)

WICHTIG: Generiere den gesamten Bericht AUF DEUTSCH.
"""

def _get_output_prompt(lang: str = "en"):
    """Returns the appropriate prompt based on language."""
    if lang == "de":
        return OUTPUT_AGENT_SYSTEM_PROMPT_DE
    return OUTPUT_AGENT_SYSTEM_PROMPT

def _format_findings_for_llm(state: ArgusState, lang: str = "en") -> str:
    """Extrahiert Daten direkt aus den Attributen der neuen Findings-Dataclass."""
    if not state.get("findings"):
        return "Keine Findings vorhanden." if lang == "de" else "No findings available."
        
    lines = []
    for f in state["findings"]:
        agent_name = f.agent.value if hasattr(f.agent, "value") else str(f.agent)
        if lang == "de":
            lines.append(
                f"=== Finding von Agent: {agent_name} ===\n"
                f"Prüfobjekt (Input): {f.input}\n"
                f"Bedrohungen (Threats): {f.threat_sum}\n"
                f"Schwachstellen (Vulnerabilities): {f.vulnerability_sum}\n"
            )
        else:
            lines.append(
                f"=== Finding from Agent: {agent_name} ===\n"
                f"Check Object (Input): {f.input}\n"
                f"Threats: {f.threat_sum}\n"
                f"Vulnerabilities: {f.vulnerability_sum}\n"
            )
    return "\n".join(lines)


class OutputAgent(BaseAgent):

    def __init__(self):
        # Nutzen des erweiterten Pydantic-Modells
        self._llm = llm.with_structured_output(OutputReport)

    def run(self, state: ArgusState) -> ArgusState:
        lang = state.get("language", "en")
        input_type = state.get("input_type", "unknown")
        findings_text = _format_findings_for_llm(state, lang)
        system_prompt = _get_output_prompt(lang)

        if lang == "de":
            prompt_input = (
                f"Eingabetyp des Systems: {input_type}\n\n"
                f"=== ALLE AGENTEN FINDINGS ===\n{findings_text}\n\n"
                f"Erstelle den finalen Risikobericht inklusive Vorbeugung und Incident-Response-Schritten."
            )
        else:
            prompt_input = (
                f"System Input Type: {input_type}\n\n"
                f"=== ALL AGENT FINDINGS ===\n{findings_text}\n\n"
                f"Create the final risk report including prevention and incident response steps."
            )

        try:
            report: OutputReport = self._llm.invoke([
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": prompt_input},
            ])
        except Exception as e:
            print(f"[WARN] OutputAgent: Structured output fehlgeschlagen - {e}")
            # Fallback bei unerwarteten API- oder Parsingfehlern
            report = OutputReport(
                threat_score=50,
                vulnerability_score=50,
                risk_level="MEDIUM",
                explanation="Der Bericht konnte aufgrund eines technischen Fehlers nicht generiert werden.",
                summary="Automatische Berichterstellung fehlgeschlagen.",
                action_prevent="Interagiere nicht mit den Objekten, bis eine manuelle Prüfung stattfand.",
                action_incident_response=["1. System isolieren", "2. IT-Sicherheit kontaktieren"],
                indicators=["Parsing-Fehler im OutputAgent"]
            )

        # ── State befüllen ───────────────────────────────────────────────────
        state["risk_score"] = max(report.threat_score, report.vulnerability_score) 
        state["risk_level"] = report.risk_level
        state["summary"] = report.summary
        if lang == "de":
            state["action_advice"] = f"PRÄVENTION:\n{report.action_prevent}\n\nFALLS BEREITS GEKLICKT:\n" + "\n".join(report.action_incident_response)
        else:
            state["action_advice"] = f"PREVENTION:\n{report.action_prevent}\n\nIF ALREADY CLICKED:\n" + "\n".join(report.action_incident_response)

        # Hänge den finalen Report als echtes Findings-Objekt an die Liste an
        final_finding = Findings(
            agent=AgentType.ORCHESTRATOR, 
            input="Zusammenfassung aller Findings" if lang == "de" else "Summary of all findings",
            threat_sum=[f"Threat Score: {report.threat_score}", f"Level: {report.risk_level}"],
            vulnerability_sum=[f"Vulnerability Score: {report.vulnerability_score}"] + report.indicators
        )
        state["findings"].append(final_finding)

        # ── NEU: Strukturiertes JSON für ChromaDB bauen ──────────────────────
        # Wir packen alle wichtigen Metadaten direkt in das Dokument, damit 
        # die Sidebar darauf zugreifen kann.
        chroma_payload = {
            "risk_level": report.risk_level,
            "score": max(report.threat_score, report.vulnerability_score),
            "summary": report.summary,
            "indicators": report.indicators,
            "action_prevent": report.action_prevent,
            "action_incident_response": report.action_incident_response
        }

        # Als JSON-String serialisiert in die ChromaDB wegschreiben
        save_analysis(
            query=state.get("user_input", ""),
            content=json.dumps(chroma_payload, ensure_ascii=False)
        )

        # ── Ausgabe im Terminal ──────────────────────────────────────────────
        self._print_custom_report(report)

        return state
    
    def _print_custom_report(self, report: OutputReport) -> None:
        """Ubersichtliche und detaillierte Konsolenausgabe des neuen Reports."""
        level_icons = {"LOW": "[LOW]", "MEDIUM": "[MED]", "HIGH": "[HIGH]", "CRITICAL": "[CRIT]"}
        icon = level_icons.get(report.risk_level, "[???]")

        print("\n" + "=" * 60)
        print(f"  {icon}  OSINT-ARGUS FINALER RISIKOBERICHT  {icon}")
        print("=" * 60)
        print(f"  Bedrohungs-Score (Threat)      : {report.threat_score}/100")
        print(f"  Schwachstellen-Score (Vuln)    : {report.vulnerability_score}/100")
        print(f"  Gesamteinstufung                : [{report.risk_level}]")
        print("-" * 60)
        print(f"  Zusammenfassung (Laie):\n  {report.summary}")
        print("-" * 60)
        print(f"  [WARN] WICHTIG - UNBEDINGT VERMEIDEN:\n  {report.action_prevent}")
        print("-" * 60)
        print(f"  [ALERT] FALLS DU BEREITS GEKLICKT HAST:")
        for i, step in enumerate(report.action_incident_response, 1):
            print(f"    {step}")
        print("-" * 60)
        print(f"  [INFO] Haupt-Risikoindikatoren:")
        for ind in report.indicators:
            print(f"     - {ind}")
        print("=" * 60 + "\n")
        