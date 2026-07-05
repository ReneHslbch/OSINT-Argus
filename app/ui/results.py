"""
app/ui/results.py
Extrahiert und rendert die Ergebnisse der Analyse-Pipeline.
"""

import re
import streamlit as st

from app.utils.mail_branding import render_shell
from app.ui.styles import LEVEL_COLOR, LEVEL_ICON, AGENT_ICON, level_badge, score_bar
from app.ui.strings import t
from app.utils.prompt_cleaner import clean_llm_output


def render_results(result: dict, lang: str = "en") -> None:
    findings = result.get("findings") or []
    report   = extract_output_report(findings)

    threat_score = report["threat_score"] or 0
    vuln_score   = report["vuln_score"]   or 0
    risk_level   = report["risk_level"]   or result.get("risk_level") or "UNKNOWN"
    indicators   = report["indicators"]

    summary    = result.get("summary")      or ""
    action_adv = result.get("action_advice") or ""

    auto_expand = risk_level in ("CRITICAL", "HIGH")

    st.markdown("---")
    _render_scores(threat_score, vuln_score, risk_level, auto_expand, lang)

    if indicators:
        _render_indicators(indicators, lang)

    if summary:
        st.markdown("---")
        with st.expander(t("expander_summary", lang), expanded=False):
            st.info(summary)

    if action_adv:
        st.markdown("---")
        with st.expander(t("expander_recommendations", lang), expanded=auto_expand):
            _render_action_advice(action_adv, lang)

    _render_agent_findings(findings, lang)


# ── Daten-Extraktion ─────────────────────────────────────────────────────────

def extract_output_report(findings: list) -> dict:
    """
    Liest Threat- und Vulnerability-Scores sowie Indikatoren aus den
    OutputAgent-Findings heraus (stream_mode='updates' überträgt risk_level
    und risk_score nicht direkt im State).
    """
    threat_score = vuln_score = risk_level = None
    indicators: list[str] = []

    for f in findings:
        agent_val = None
        threat_sum = []
        vuln_sum = []
        
        # Handle both dataclass objects and dicts (LangGraph serialization)
        if isinstance(f, dict):
            agent_raw = f.get("agent", "")
            if isinstance(agent_raw, dict):
                agent_val = str(agent_raw.get("value", ""))
            elif hasattr(agent_raw, 'value'):
                agent_val = str(agent_raw.value)
            else:
                agent_val = str(agent_raw)
            threat_sum = f.get("threat_sum", [])
            vuln_sum = f.get("vulnerability_sum", [])
        elif hasattr(f, 'agent'):
            agent_val = str(f.agent.value if hasattr(f.agent, 'value') else f.agent)
            threat_sum = getattr(f, 'threat_sum', [])
            vuln_sum = getattr(f, 'vulnerability_sum', [])
        else:
            continue

        if agent_val != "orchestrator":
            continue
        if not any("Threat Score" in str(item) for item in threat_sum):
            continue

        for item in threat_sum:
            s = str(item)
            if "Threat Score" in s:
                try:
                    threat_score = int(s.split(":")[-1].strip())
                except ValueError:
                    pass
            if "Level" in s:
                try:
                    risk_level = s.split(":")[-1].strip()
                except ValueError:
                    pass

        for item in vuln_sum:
            s = str(item)
            if "Vulnerability Score" in s:
                try:
                    vuln_score = int(s.split(":")[-1].strip())
                except ValueError:
                    pass
            else:
                indicators.append(s)

    return {
        "threat_score": threat_score,
        "vuln_score":   vuln_score,
        "risk_level":   risk_level,
        "indicators":   indicators,
    }


# ── private Hilfsfunktionen ──────────────────────────────────────────────────

def _render_scores(threat_score: int, vuln_score: int, risk_level: str, auto_expand: bool = False, lang: str = "en") -> None:
    col_ts, col_vs, col_lvl = st.columns([1, 1, 1])
    color_t = LEVEL_COLOR.get(risk_level, "#9ca3af")

    with col_ts:
        st.markdown(t("label_threat_score", lang))
        st.markdown(
            f'<span style="font-size:2.2rem;font-weight:700">{threat_score}</span>'
            f'<span style="opacity:.4;font-size:1rem"> / 100</span>'
            f'{score_bar(threat_score, color_t)}',
            unsafe_allow_html=True,
        )
    with col_vs:
        st.markdown(t("label_vulnerability_score", lang))
        st.markdown(
            f'<span style="font-size:2.2rem;font-weight:700">{vuln_score}</span>'
            f'<span style="opacity:.4;font-size:1rem"> / 100</span>'
            f'{score_bar(vuln_score, "#f59e0b")}',
            unsafe_allow_html=True,
        )
    with col_lvl:
        st.markdown(t("label_risk_level", lang))
        st.markdown(level_badge(risk_level), unsafe_allow_html=True)
        
        if risk_level == "CRITICAL":
            st.error(t("risk_critical", lang))
        elif risk_level == "HIGH":
            st.warning(t("risk_high", lang))
        elif risk_level == "MEDIUM":
            st.info(t("risk_medium", lang))
        else:
            st.success(t("risk_low", lang))


def _render_indicators(indicators: list[str], lang: str) -> None:
    with st.expander(t("expander_indicators", lang), expanded=False):
        st.markdown(t("header_indicators", lang))
        cols = st.columns(3)
        for i, ind in enumerate(indicators[:9]):
            clean = ind.replace("**", "").replace("`", "").strip("- ").strip()
            if not clean:
                continue
            with cols[i % 3]:
                st.markdown(f'<div class="indicator-pill">⚠️ {clean}</div>', unsafe_allow_html=True)


def _render_action_advice(action_adv: str, lang: str) -> None:
    split_marker = "FALLS BEREITS GEKLICKT:"
    if split_marker in action_adv:
        parts         = action_adv.split(split_marker, 1)
        prevent_text  = parts[0].replace("PRÄVENTION:", "").strip()
        incident_text = parts[1].strip()
    else:
        prevent_text  = action_adv.strip()
        incident_text = ""

    col_p, col_i = st.columns(2)
    with col_p:
        st.markdown(t("header_prevention", lang))
        st.markdown(
            f'<div class="action-box action-prevent">{prevent_text}</div>',
            unsafe_allow_html=True,
        )
    with col_i:
        st.markdown(t("header_incident", lang))
        if incident_text:
            body = incident_text
        else:
            body_en = (
                "1. Disconnect device from network immediately.<br>"
                "2. Change passwords from a secure device.<br>"
                "3. Contact bank / IT security.<br>"
                "4. Scan device for malware."
            )
            body_de = (
                "1. Gerät sofort vom Netzwerk trennen.<br>"
                "2. Passwörter von einem sicheren Gerät ändern.<br>"
                "3. Bank / IT-Sicherheit kontaktieren.<br>"
                "4. Gerät auf Malware scannen."
            )
            body = body_en if lang == "en" else body_de
        st.markdown(
            f'<div class="action-box action-incident">{body}</div>',
            unsafe_allow_html=True,
        )


def _render_agent_findings(findings: list, lang: str) -> None:
    st.markdown("---")
    st.markdown(t("expander_agent_findings", lang))

    display_findings = []
    seen: set[tuple] = set()
    for f in findings:
        agent_val = None
        inp = ""
        
        # Handle both dataclass objects and dicts (LangGraph serialization)
        if isinstance(f, dict):
            agent_raw = f.get("agent", "")
            if isinstance(agent_raw, dict):
                agent_val = str(agent_raw.get("value", "?"))
            elif hasattr(agent_raw, 'value'):
                agent_val = str(agent_raw.value)
            else:
                agent_val = str(agent_raw) if agent_raw else "?"
            inp = f.get("input", "")
        elif hasattr(f, 'agent'):
            agent_val = str(f.agent.value if hasattr(f.agent, 'value') else f.agent)
            inp = getattr(f, 'input', "")
        else:
            continue
        key = (agent_val, inp)
        if agent_val == "orchestrator" or key in seen:
            continue
        seen.add(key)
        display_findings.append(f)

    if not display_findings:
        st.caption(t("msg_no_findings", lang))
        return

    for f in display_findings:
        if isinstance(f, dict):
            agent_raw = f.get("agent", "")
            if isinstance(agent_raw, dict):
                agent_val = str(agent_raw.get("value", "?"))
            elif hasattr(agent_raw, 'value'):
                agent_val = str(agent_raw.value)
            else:
                agent_val = str(agent_raw) if agent_raw else "?"
            inp = f.get("input", "")
            threats = f.get("threat_sum", [])
            vulns = f.get("vulnerability_sum", [])
        elif hasattr(f, 'agent'):
            agent_val = str(f.agent.value if hasattr(f.agent, 'value') else f.agent)
            inp = getattr(f, 'input', "")
            threats = getattr(f, 'threat_sum', [])
            vulns = getattr(f, 'vulnerability_sum', [])
        else:
            continue
        icon = AGENT_ICON.get(agent_val, "⚙️")

        with st.expander(f"{icon} {agent_val.upper()} — {inp[:60]}", expanded=False):
            if threats:
                st.markdown(t("header_threats", lang))
                for threat in threats:
                    if str(threat).strip():
                        st.markdown(f"- {threat}")
            if vulns:
                st.markdown(t("header_vulnerabilities", lang))
                for vuln in vulns:
                    if str(vuln).strip():
                        st.markdown(f"- {vuln}")
            if not threats and not vulns:
                st.caption(t("msg_no_vulns", lang))


# ── Mail-Content-Generator ────────────────────────────────────────────────────


AGENT_LABEL = {
    "domain":   {"en": "Domain Analysis",         "de": "Domain-Analyse"},
    "email":    {"en": "Email Analysis",          "de": "E-Mail-Analyse"},
    "cve":      {"en": "Vulnerability Scan (CVE)", "de": "Schwachstellen-Scan (CVE)"},
    "phone":    {"en": "Phone Number Analysis",   "de": "Telefonnummer-Analyse"},
    "file":     {"en": "File Analysis",           "de": "Datei-Analyse"},
    "identity": {"en": "Identity / OSINT",        "de": "Identität / OSINT"},
    "leak":     {"en": "Data Breach Check",       "de": "Datenleck-Prüfung"},
}


def _collect_agent_findings(findings: list) -> list[dict]:
    """Sammelt ALLE Agent-Detail-Findings (ohne Orchestrator-Summary), dedupliziert."""
    collected = []
    seen = set()
    for f in findings:
        if isinstance(f, dict):
            agent_raw = f.get("agent", "")
            agent_val = (
                agent_raw.get("value") if isinstance(agent_raw, dict)
                else agent_raw.value if hasattr(agent_raw, "value")
                else str(agent_raw)
            )
            inp = f.get("input", "")
            threats = f.get("threat_sum", []) or []
            vulns = f.get("vulnerability_sum", []) or []
        elif hasattr(f, "agent"):
            agent_val = f.agent.value if hasattr(f.agent, "value") else str(f.agent)
            inp = getattr(f, "input", "")
            threats = getattr(f, "threat_sum", []) or []
            vulns = getattr(f, "vulnerability_sum", []) or []
        else:
            continue

        if agent_val == "orchestrator":
            continue
        key = (agent_val, inp)
        if key in seen:
            continue
        seen.add(key)

        collected.append({
            "agent": agent_val,
            "input": clean_llm_output(str(inp)),
            "threats": [
                clean_llm_output(str(t)) for t in threats
                if str(t).strip() and "<environment_details>" not in str(t)
            ],
            "vulns": [
                clean_llm_output(str(v)) for v in vulns
                if str(v).strip() and "<environment_details>" not in str(v)
            ],
        })
    return collected


def map_result_to_mail(result: dict, lang: str = "en") -> tuple:
    """
    Erstellt Subject, Text- und HTML-Body aus dem Analyse-Ergebnis.
    Enthält jetzt zusätzlich ALLE Detail-Findings der Einzel-Agenten
    (Domain, Email, CVE, Phone, File, Identity, Leak) — nicht nur die
    finale Zusammenfassung des OutputAgent.
    """
    findings = result.get("findings", [])
    report = extract_output_report(findings)

    threat_score  = report.get("threat_score") or result.get("risk_score") or 0
    vuln_score    = report.get("vuln_score") or 0
    risk_level    = report.get("risk_level") or result.get("risk_level") or "UNKNOWN"
    overall_score = max(threat_score, vuln_score)

    summary = clean_llm_output(str(
        result.get("summary")
        or ("No summary available." if lang == "en" else "Keine Zusammenfassung verfügbar.")
    ))
    action_advice = clean_llm_output(str(result.get("action_advice") or ""))
    indicators = report.get("indicators") or []

    split_marker = "IF ALREADY CLICKED:" if lang == "en" else "FALLS BEREITS GEKLICKT:"
    if split_marker in action_advice:
        parts = action_advice.split(split_marker, 1)
        prevent_text = parts[0].strip()
        prefix = "PREVENTION:" if lang == "en" else "PRÄVENTION:"
        if prevent_text.startswith(prefix):
            prevent_text = prevent_text.split(":", 1)[1].strip()
        incident_text = parts[1].strip()
    else:
        prevent_text = action_advice.strip()
        incident_text = ""

    incident_lines = [
        line.strip() for line in incident_text.split("\n")
        if line.strip() and "<environment_details>" not in line
    ]

    agent_findings = _collect_agent_findings(findings)

    subject = (
        f"[OSINT-Argus] Analysis Result — {risk_level}" if lang == "en"
        else f"[OSINT-Argus] Analyseergebnis — {risk_level}"
    )

    # ── TEXT-VERSION ──────────────────────────────────────────────────────
    if lang == "en":
        text_lines = [
            "OSINT-ARGUS ANALYSIS REPORT", "=" * 60,
            f"Risk Level:   {risk_level}",
            f"Risk Score:   {overall_score}/100", "",
            "SUMMARY", "-" * 60, summary, "",
            "PREVENTION", "-" * 60, prevent_text, "",
        ]
        if indicators:
            text_lines += ["KEY RISK INDICATORS", "-" * 60]
            text_lines += [f"- {clean_llm_output(str(i))}" for i in indicators if clean_llm_output(str(i))]
            text_lines.append("")
        if incident_lines:
            text_lines += ["IF ALREADY INTERACTED", "-" * 60]
            text_lines += [f"{i}. {line}" for i, line in enumerate(incident_lines, 1)]
            text_lines.append("")
        if agent_findings:
            text_lines += ["DETAILED AGENT FINDINGS", "=" * 60]
            for af in agent_findings:
                label = AGENT_LABEL.get(af["agent"], {}).get("en", af["agent"].upper())
                text_lines.append(f"\n[{label}] — {af['input'][:80]}")
                if af["threats"]:
                    text_lines.append("  Threats:")
                    text_lines += [f"    - {t}" for t in af["threats"]]
                if af["vulns"]:
                    text_lines.append("  Vulnerabilities / Findings:")
                    text_lines += [f"    - {v}" for v in af["vulns"]]
        text_lines += ["", "=" * 60, "This is an automated message from OSINT-Argus."]
    else:
        text_lines = [
            "OSINT-ARGUS ANALYSEBERICHT", "=" * 60,
            f"Risiko-Level:  {risk_level}",
            f"Risiko-Score:  {overall_score}/100", "",
            "ZUSAMMENFASSUNG", "-" * 60, summary, "",
            "PRÄVENTION", "-" * 60, prevent_text, "",
        ]
        if indicators:
            text_lines += ["HAUPT-RISIKOINDIKATOREN", "-" * 60]
            text_lines += [f"- {clean_llm_output(str(i))}" for i in indicators if clean_llm_output(str(i))]
            text_lines.append("")
        if incident_lines:
            text_lines += ["FALLS BEREITS INTERAGIERT", "-" * 60]
            text_lines += [f"{i}. {line}" for i, line in enumerate(incident_lines, 1)]
            text_lines.append("")
        if agent_findings:
            text_lines += ["DETAILLIERTE AGENT-BEFUNDE", "=" * 60]
            for af in agent_findings:
                label = AGENT_LABEL.get(af["agent"], {}).get("de", af["agent"].upper())
                text_lines.append(f"\n[{label}] — {af['input'][:80]}")
                if af["threats"]:
                    text_lines.append("  Bedrohungen:")
                    text_lines += [f"    - {t}" for t in af["threats"]]
                if af["vulns"]:
                    text_lines.append("  Schwachstellen / Befunde:")
                    text_lines += [f"    - {v}" for v in af["vulns"]]
        text_lines += ["", "=" * 60, "Dies ist eine automatisierte Nachricht von OSINT-Argus."]

    text_body = "\n".join(text_lines)

    # ── HTML-VERSION ──────────────────────────────────────────────────────
    summary_html = summary.replace("\n", "<br>")
    prevent_html = prevent_text.replace("\n", "<br>")

    indicators_html = ""
    if indicators:
        items = "".join(f"<li>{clean_llm_output(str(i))}</li>" for i in indicators if clean_llm_output(str(i)))
        title = "Key Risk Indicators" if lang == "en" else "Haupt-Risikoindikatoren"
        indicators_html = f'<h3 class="section">💡 {title}</h3><div class="card"><ul>{items}</ul></div>'

    incident_html = ""
    if incident_lines:
        items = "".join(f"<li>{line}</li>" for line in incident_lines)
        title = "If Already Interacted" if lang == "en" else "Falls bereits interagiert"
        incident_html = f'<h3 class="section">🚨 {title}</h3><div class="card danger"><ol class="incident">{items}</ol></div>'

    agent_html = ""
    if agent_findings:
        title = "Detailed Agent Findings" if lang == "en" else "Detaillierte Agent-Befunde"
        cards = ""
        for af in agent_findings:
            label = AGENT_LABEL.get(af["agent"], {}).get(lang, af["agent"].upper())
            icon = AGENT_ICON.get(af["agent"], "⚙️")
            threats_html = "".join(f"<li>{t}</li>" for t in af["threats"])
            vulns_html = "".join(f"<li>{v}</li>" for v in af["vulns"])
            threat_label = "Threats" if lang == "en" else "Bedrohungen"
            vuln_label = "Vulnerabilities / Findings" if lang == "en" else "Schwachstellen / Befunde"
            cards += f"""
            <div class="agent-card">
              <div class="agent-title">{icon} {label}</div>
              <div class="agent-target">{af['input'][:100]}</div>
              {f'<strong>{threat_label}:</strong><ul>{threats_html}</ul>' if af['threats'] else ''}
              {f'<strong>{vuln_label}:</strong><ul>{vulns_html}</ul>' if af['vulns'] else ''}
            </div>
            """
        agent_html = f'<h3 class="section">🔍 {title}</h3>{cards}'

    score_label_threat = "Threat Score" if lang == "en" else "Bedrohungs-Score"
    score_label_vuln = "Vulnerability Score" if lang == "en" else "Schwachstellen-Score"
    summary_title = "Summary" if lang == "en" else "Zusammenfassung"
    prevent_title = "Prevention" if lang == "en" else "Prävention"

    body_html = f"""
    <div class="score-row">
      <div class="score-item"><div class="label">{score_label_threat}</div><div class="value">{threat_score}/100</div></div>
      <div class="score-item"><div class="label">{score_label_vuln}</div><div class="value">{vuln_score}/100</div></div>
      <div class="score-item"><div class="label">{"Risk Level" if lang == "en" else "Risiko-Level"}</div>
        <div><span class="badge badge-{risk_level}">{risk_level}</span></div></div>
    </div>

    <h3 class="section">📄 {summary_title}</h3>
    <div class="card">{summary_html}</div>

    <h3 class="section">⚠️ {prevent_title}</h3>
    <div class="card warn">{prevent_html}</div>

    {indicators_html}
    {incident_html}
    {agent_html}
    """

    html_body = render_shell(
        "👁️", "OSINT-Argus",
        "Analysis Report" if lang == "en" else "Analysebericht",
        body_html,
    )

    return subject, text_body.strip(), html_body.strip()