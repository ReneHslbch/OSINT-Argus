import json
from langchain_core.prompts import ChatPromptTemplate
from app.agents.base_agent import BaseAgent
from app.state import ArgusState
from app.models.llm import get_llm
from app.models.router import OutputReport


llm = get_llm()


# ── Risiko-Schwellen für den Prompt ─────────────────────────────────────────
RISK_THRESHOLDS = """
Risiko-Score-Skala (0–100):
  0–33   → LOW      (grün)   — kein unmittelbares Risiko erkennbar
  34–66  → MEDIUM   (gelb)   — Vorsicht geboten, aber keine akute Gefahr
  67–84  → HIGH     (rot)    — klare Bedrohungssignale, Handlung empfohlen
  85–100 → CRITICAL (rot🔴)  — aktive Bedrohung, sofort handeln
"""

SYSTEM_PROMPT = f"""Du bist der OutputAgent von OSINT-Argus, einem Cybersecurity-Analyse-System.
Du erhältst alle gesammelten Findings aus der Analyse und erstellst daraus einen 
abschließenden Risikobericht.

{RISK_THRESHOLDS}

Deine Aufgaben:
1. Bewerte alle Findings zusammen und vergib einen risk_score (0–100)
2. Leite daraus das risk_level ab (LOW / MEDIUM / HIGH / CRITICAL)
3. Schreibe eine technische explanation (3–5 Sätze, für Experten)
4. Schreibe eine einfache summary (2–3 Sätze, für Laien — kein Fachjargon)
5. Formuliere einen konkreten action_advice je nach Risikostufe:
   - LOW:      "Keine Aktion erforderlich. [optionale Empfehlung]"
   - MEDIUM:   "Vorsicht. [was konkret vermeiden/prüfen]"
   - HIGH:     "Nicht empfohlen. [was konkret tun / nicht tun]"
   - CRITICAL: "Sofort handeln. [klare, direkte Anweisung]"
6. Liste die 3–5 wichtigsten indicators auf (kurze Stichpunkte)

Wichtig:
- Der action_advice soll handlungsanleitend und spezifisch sein, nicht generisch.
- Beispiele für guten action_advice:
  * LOW:      "Diese Domain ist unbedenklich. Du kannst sie besuchen."
  * MEDIUM:   "Öffne den Link nicht direkt. Gehe stattdessen manuell auf die offizielle Website."
  * HIGH:     "Besuche diese Domain nicht. Lösche die E-Mail und melde sie als Spam."
  * CRITICAL: "Sofort handeln: Klicke nicht auf Links, öffne keine Anhänge. Melde die E-Mail 
               an deine IT-Abteilung oder leite sie an abuse@[deine-firma].de weiter."
- Passe den advice an den Eingabetyp an (Domain-Analyse vs. E-Mail-Analyse).

Antworte AUSSCHLIESSLICH mit einem validen JSON-Objekt ohne Markdown-Fences.
"""


def _format_findings_for_llm(state: ArgusState) -> str:
    """Alle relevanten Findings kompakt für den LLM-Prompt aufbereiten."""
    lines = []

    for finding in state["findings"]:
        agent = finding.get("agent", "Unknown")

        # ── OrchestratorAgent: nur Routing-Entscheidungen ──────────────────
        if agent == "OrchestratorAgent":
            decision = finding.get("decision", {})
            lines.append(
                f"[Orchestrator] input_type={decision.get('input_type', '—')} | "
                f"next_agent={decision.get('next_agent', '—')}"
            )

        # ── DomainAgent ─────────────────────────────────────────────────────
        elif agent == "DomainAgent":
            ai = finding.get("ai_analysis", {})
            lines.append(
                f"[DomainAgent] Domain: {finding.get('domain', '—')}\n"
                f"  Threat Indicators:  {ai.get('threat_indicators', [])}\n"
                f"  Exposure Findings:  {ai.get('exposure_findings', [])}\n"
                f"  Summary:            {ai.get('summary', '—')}\n"
                f"  URLhaus:            {finding.get('urlhaus', {}).get('verdict', '—')}\n"
                f"  SSL:                {finding.get('ssl', {}).get('verdict', '—')}\n"
                f"  Email Security:     {finding.get('email_security', {}).get('verdict', '—')}"
            )

        # ── EmailAgent Pass 1 ───────────────────────────────────────────────
        elif agent == "EmailAgent" and finding.get("pass") == 1:
            lines.append(
                f"[EmailAgent Pass 1]\n"
                f"  Von:              {finding.get('from', '—')}\n"
                f"  Betreff:          {finding.get('subject', '—')}\n"
                f"  Reply-To Mismatch:{finding.get('reply_to_mismatch', False)}\n"
                f"  URLs gefunden:    {finding.get('urls_found', 0)}\n"
                f"  Domains to scan:  {finding.get('domains_to_scan', [])}"
            )

        # ── EmailAgent Pass 2 ───────────────────────────────────────────────
        elif agent == "EmailAgent" and finding.get("pass") == 2:
            ai = finding.get("ai_analysis", {})
            vt = finding.get("virustotal_sender", {})
            lines.append(
                f"[EmailAgent Pass 2]\n"
                f"  Phishing Indicators: {ai.get('phishing_indicators', [])}\n"
                f"  Content Risk:        {ai.get('content_risk', '—')}\n"
                f"  Sender Assessment:   {ai.get('sender_assessment', '—')}\n"
                f"  VT Sender Verdict:   {vt.get('verdict', '—')} "
                f"(malicious={vt.get('malicious', '—')})\n"
                f"  Summary:             {ai.get('summary', '—')}"
            )

    return "\n\n".join(lines) if lines else "Keine Findings vorhanden."


class OutputAgent(BaseAgent):

    def __init__(self):
        self._llm = llm.with_structured_output(OutputReport)

    def run(self, state: ArgusState) -> ArgusState:
        input_type = state.get("input_type", "unknown")
        findings_text = _format_findings_for_llm(state)

        prompt_input = (
            f"Eingabetyp: {input_type}\n\n"
            f"=== GESAMMELTE FINDINGS ===\n{findings_text}\n\n"
            f"Erstelle jetzt den finalen Risikobericht."
        )

        try:
            report: OutputReport = self._llm.invoke([
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt_input},
            ])
        except Exception as e:
            # Fallback falls structured output scheitert
            print(f"⚠️  OutputAgent: Structured output fehlgeschlagen — {e}")
            report = OutputReport(
                risk_score=50,
                risk_level="MEDIUM",
                explanation="Analyse konnte nicht vollständig ausgewertet werden.",
                summary="Die Bewertung ist unvollständig. Vorsicht empfohlen.",
                action_advice="Bitte manuell prüfen — automatische Bewertung fehlgeschlagen.",
                indicators=["Parsing-Fehler im OutputAgent"],
            )

        # ── State befüllen ───────────────────────────────────────────────────
        state["risk_score"]    = report.risk_score
        state["risk_level"]    = report.risk_level
        state["summary"]       = report.summary
        state["action_advice"] = report.action_advice

        state["findings"].append({
            "agent":       "OutputAgent",
            "risk_score":  report.risk_score,
            "risk_level":  report.risk_level,
            "explanation": report.explanation,
            "summary":     report.summary,
            "action_advice": report.action_advice,
            "indicators":  report.indicators,
        })

        # ── Konsolenausgabe ──────────────────────────────────────────────────
        _print_report(report)

        return state


def _print_report(report: OutputReport) -> None:
    """Übersichtliche Konsolenausgabe des finalen Reports."""
    level_icons = {
        "LOW":      "🟢",
        "MEDIUM":   "🟡",
        "HIGH":     "🔴",
        "CRITICAL": "🚨",
    }
    icon = level_icons.get(report.risk_level, "⚪")

    print("\n" + "═" * 60)
    print(f"  {icon}  OSINT-Argus Risikobericht")
    print("═" * 60)
    print(f"  Risiko-Score : {report.risk_score}/100  [{report.risk_level}]")
    print(f"  Zusammenfassung:\n    {report.summary}")
    print(f"\n  🎯 Empfehlung:\n    {report.action_advice}")
    print(f"\n  ⚠️  Indikatoren:")
    for ind in report.indicators:
        print(f"     • {ind}")
    print("═" * 60 + "\n")