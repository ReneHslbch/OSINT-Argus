import json
from langchain_core.prompts import ChatPromptTemplate
from langchain_classic.agents import AgentExecutor, create_tool_calling_agent

from app.agents.base_agent import BaseAgent
from app.state import ArgusState
from app.models.llm import get_llm
from app.tools.email_tools import (
    extract_urls,
    extract_domain_from_url,
    extract_sender_domain,
    parse_email_headers,
    check_reply_to_mismatch,
    check_virustotal_domain,
)

llm = get_llm()

EMAIL_TOOLS = [check_virustotal_domain]

# ── Pass 2 System-Prompt ────────────────────────────────────────────────────
PASS2_SYSTEM_PROMPT = """Du bist der EmailAgent von OSINT-Argus, einem Cybersecurity-Analyse-System.

Du hast bereits in Pass 1 alle Domains und Metadaten extrahiert.
Die Domain-Analysen wurden vom DomainAgent durchgeführt und liegen in den Findings vor.

Deine Aufgabe in Pass 2:
1. Rufe check_virustotal_domain für die Absender-Domain auf
2. Analysiere danach den E-Mail-Inhalt und erstelle einen JSON-Report

Bewerte folgende Phishing-Indikatoren im Email-Inhalt:
- Dringlichkeit / Drohungen ("Ihr Konto wird gesperrt", "Sofort handeln")
- Impersonation (gibt sich als Bank, IT, Chef aus)
- Ungewöhnliche Anfragen (Passwort, Überweisung, Zugangsdaten)
- Grammatik-/Rechtschreibfehler (oft in Phishing-Mails)
- Verdächtige Links (Domain passt nicht zum angeblichen Absender)
- Reply-To Mismatch (Reply geht an andere Domain als Absender)

Erstelle am Ende ein JSON-Objekt mit exakt dieser Struktur:
{{
  "phishing_indicators": ["Liste konkreter Phishing-Merkmale die du gefunden hast"],
  "content_risk": "LOW | MEDIUM | HIGH | CRITICAL",
  "sender_assessment": "Kurze Bewertung des Absenders",
  "summary": "2-3 Sätze Gesamtbewertung ob dieser Email vertraut werden sollte"
}}

Antworte AUSSCHLIESSLICH mit dem validen JSON-Objekt."""


class EmailAgent(BaseAgent):

    def __init__(self):
        prompt = ChatPromptTemplate.from_messages([
            ("system", PASS2_SYSTEM_PROMPT),
            ("human", "{input}"),
            ("placeholder", "{agent_scratchpad}"),
        ])
        agent = create_tool_calling_agent(llm, EMAIL_TOOLS, prompt)
        self._executor = AgentExecutor(
            agent=agent,
            tools=EMAIL_TOOLS,
            verbose=True,
            max_iterations=5,
            return_intermediate_steps=True,
        )

    # ── Pass 1: Extraktion ──────────────────────────────────────────────────
    def _run_pass1(self, state: ArgusState) -> ArgusState:
        email_text = state["user_input"]

        # Header-Parsing
        headers      = parse_email_headers(email_text)
        sender_domain = extract_sender_domain(headers.get("from"))
        reply_check  = check_reply_to_mismatch(headers)

        # URL + Domain-Extraktion
        urls              = extract_urls(email_text)
        link_domains      = [
            d for u in urls
            if (d := extract_domain_from_url(u)) is not None
        ]

        # Absender-Domain auch scannen (immer an erster Stelle)
        domains_to_scan = []
        if sender_domain:
            domains_to_scan.append(sender_domain)
        for d in link_domains:
            if d not in domains_to_scan:
                domains_to_scan.append(d)

        extraction = {
            "headers":            headers,
            "sender_domain":      sender_domain,
            "reply_to_check":     reply_check,
            "urls_found":         urls,
            "link_domains":       link_domains,
            "domains_to_scan":    domains_to_scan,
            "domain_scan_count":  len(domains_to_scan),
        }

        state["email_extraction"]  = extraction
        state["domains_to_scan"]   = domains_to_scan

        state["findings"].append({
            "agent":    "EmailAgent",
            "pass":     1,
            "subject":  headers.get("subject", "—"),
            "from":     headers.get("from", "—"),
            "reply_to_mismatch": reply_check["mismatch_detected"],
            "urls_found":        len(urls),
            "domains_to_scan":   domains_to_scan,
        })

        print(f"\n📧 EmailAgent Pass 1 — {len(domains_to_scan)} Domains zum Scannen erkannt")
        for d in domains_to_scan:
            print(f"   → {d}")

        return state

    # ── Pass 2: Inhaltsbewertung ────────────────────────────────────────────
    def _run_pass2(self, state: ArgusState) -> ArgusState:
        extraction    = state.get("email_extraction", {})
        sender_domain = extraction.get("sender_domain", "unbekannt")
        email_text    = state["user_input"]

        # Alle Domain-Findings aus dem State sammeln
        domain_findings = [
            f for f in state["findings"]
            if f.get("agent") == "DomainAgent"
        ]

        # Domain-Findings kompakt für den Prompt zusammenfassen
        domain_summary_lines = []
        for df in domain_findings:
            ai = df.get("ai_analysis", {})
            domain_summary_lines.append(
                f"Domain: {df.get('domain')}\n"
                f"  Bedrohungen: {ai.get('threat_indicators', [])}\n"
                f"  Schwachstellen: {ai.get('exposure_findings', [])}\n"
                f"  Bewertung: {ai.get('summary', '—')}"
            )

        domain_context = "\n\n".join(domain_summary_lines) or "Keine Domain-Findings vorhanden."

        prompt_input = (
            f"Absender-Domain für VirusTotal-Check: {sender_domain}\n\n"
            f"=== EMAIL-INHALT ===\n{email_text}\n\n"
            f"=== DOMAIN-ANALYSEN (vom DomainAgent) ===\n{domain_context}\n\n"
            f"=== EXTRAHIERTE METADATEN ===\n"
            f"Absender: {extraction.get('headers', {}).get('from', '—')}\n"
            f"Reply-To Mismatch: {extraction.get('reply_to_check', {}).get('mismatch_detected', False)}\n"
            f"Gefundene URLs: {len(extraction.get('urls_found', []))}\n\n"
            f"Erstelle jetzt den JSON-Report."
        )

        result = self._executor.invoke({"input": prompt_input})

        # VT-Rohdaten aus intermediate_steps holen
        vt_data = {}
        for action, observation in result.get("intermediate_steps", []):
            if action.tool == "check_virustotal_domain":
                try:
                    vt_data = (
                        json.loads(observation)
                        if isinstance(observation, str)
                        else observation
                    )
                except (json.JSONDecodeError, TypeError):
                    vt_data = {"raw": str(observation)}

        # LLM-Output parsen
        llm_output = result.get("output", "").strip()
        analysis   = None
        try:
            if "```" in llm_output:
                content = llm_output.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
                analysis = json.loads(content.strip())
            else:
                analysis = json.loads(llm_output)
        except (json.JSONDecodeError, IndexError, ValueError):
            analysis = {
                "phishing_indicators": [],
                "content_risk":        "UNKNOWN",
                "sender_assessment":   "Parsing-Fehler",
                "summary":             llm_output or "Keine LLM-Ausgabe erhalten.",
            }

        # Summary in State schreiben
        state["summary"] = analysis.get("summary", "")

        state["findings"].append({
            "agent":              "EmailAgent",
            "pass":               2,
            "virustotal_sender":  vt_data,
            "ai_analysis":        analysis,
        })

        print(f"\n📧 EmailAgent Pass 2 — Risiko: {analysis.get('content_risk', '?')}")
        print(f"   {analysis.get('summary', '')}")

        return state

    # ── Haupt-Run ───────────────────────────────────────────────────────────
    def run(self, state: ArgusState) -> ArgusState:
        email_pass = state.get("email_pass", 1)

        if email_pass == 1:
            return self._run_pass1(state)
        elif email_pass == 2:
            return self._run_pass2(state)
        else:
            print(f"⚠️  EmailAgent: Unbekannter Pass {email_pass}")
            return state