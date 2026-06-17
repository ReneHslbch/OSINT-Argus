"""
app/ui/results.py
Extrahiert und rendert die Ergebnisse der Analyse-Pipeline.
"""

import streamlit as st

from app.ui.styles import LEVEL_COLOR, LEVEL_ICON, AGENT_ICON, level_badge, score_bar


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
        agent_val  = str(getattr(getattr(f, "agent", ""), "value", ""))
        threat_sum = getattr(f, "threat_sum", [])
        vuln_sum   = getattr(f, "vulnerability_sum", [])

        if agent_val != "orchestrator":
            continue
        if not any("Threat Score" in str(t) for t in threat_sum):
            continue

        for t in threat_sum:
            s = str(t)
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

        for v in vuln_sum:
            s = str(v)
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


# ── Haupt-Render-Funktion ────────────────────────────────────────────────────

def render_results(result: dict) -> None:
    findings = result.get("findings") or []
    report   = extract_output_report(findings)

    threat_score = report["threat_score"] or 0
    vuln_score   = report["vuln_score"]   or 0
    risk_level   = report["risk_level"]   or result.get("risk_level") or "UNKNOWN"
    indicators   = report["indicators"]

    summary    = result.get("summary")      or ""
    action_adv = result.get("action_advice") or ""

    st.markdown("---")
    _render_scores(threat_score, vuln_score, risk_level)

    if summary:
        st.markdown("---")
        st.markdown("#### Zusammenfassung")
        st.info(summary)

    if indicators:
        _render_indicators(indicators)

    if action_adv:
        _render_action_advice(action_adv)

    _render_agent_findings(findings)


# ── private Hilfsfunktionen ──────────────────────────────────────────────────

def _render_scores(threat_score: int, vuln_score: int, risk_level: str) -> None:
    col_ts, col_vs, col_lvl = st.columns([1, 1, 1])
    color_t = LEVEL_COLOR.get(risk_level, "#9ca3af")

    with col_ts:
        st.markdown("**Bedrohungs-Score**")
        st.markdown(
            f'<span style="font-size:2.2rem;font-weight:700">{threat_score}</span>'
            f'<span style="opacity:.4;font-size:1rem"> / 100</span>'
            f'{score_bar(threat_score, color_t)}',
            unsafe_allow_html=True,
        )
    with col_vs:
        st.markdown("**Schwachstellen-Score**")
        st.markdown(
            f'<span style="font-size:2.2rem;font-weight:700">{vuln_score}</span>'
            f'<span style="opacity:.4;font-size:1rem"> / 100</span>'
            f'{score_bar(vuln_score, "#f59e0b")}',
            unsafe_allow_html=True,
        )
    with col_lvl:
        st.markdown("**Gesamteinstufung**")
        st.markdown(level_badge(risk_level), unsafe_allow_html=True)
        if risk_level == "CRITICAL":
            st.error("Sofortiger Handlungsbedarf!")
        elif risk_level == "HIGH":
            st.warning("Erhöhtes Risiko — Vorsicht geboten.")
        elif risk_level == "MEDIUM":
            st.info("Moderates Risiko — aufmerksam bleiben.")
        else:
            st.success("Kein akutes Risiko erkannt.")


def _render_indicators(indicators: list[str]) -> None:
    st.markdown("#### 💡 Haupt-Risikoindikatoren")
    cols = st.columns(3)
    for i, ind in enumerate(indicators[:9]):
        clean = ind.replace("**", "").replace("`", "").strip("- ").strip()
        if not clean:
            continue
        with cols[i % 3]:
            st.markdown(f'<div class="indicator-pill">⚠️ {clean}</div>', unsafe_allow_html=True)


def _render_action_advice(action_adv: str) -> None:
    st.markdown("---")
    st.markdown("#### Handlungsempfehlungen")

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
        st.markdown("🚫 **Unbedingt vermeiden**")
        st.markdown(
            f'<div class="action-box action-prevent">{prevent_text}</div>',
            unsafe_allow_html=True,
        )
    with col_i:
        st.markdown("🔥 **Falls bereits geklickt**")
        if incident_text:
            body = incident_text
        else:
            body = (
                "1. Gerät sofort vom Netzwerk trennen.<br>"
                "2. Passwörter von einem sicheren Gerät ändern.<br>"
                "3. Bank / IT-Sicherheit kontaktieren.<br>"
                "4. Gerät auf Malware scannen."
            )
        st.markdown(
            f'<div class="action-box action-incident">{body}</div>',
            unsafe_allow_html=True,
        )


def _render_agent_findings(findings: list) -> None:
    st.markdown("---")
    st.markdown("#### Agent-Findings (Detail)")

    display_findings = []
    seen: set[tuple] = set()
    for f in findings:
        agent_val = str(getattr(getattr(f, "agent", ""), "value", ""))
        inp       = getattr(f, "input", "")
        key       = (agent_val, inp)
        if agent_val == "orchestrator" or key in seen:
            continue
        seen.add(key)
        display_findings.append(f)

    if not display_findings:
        st.caption("Keine Detail-Findings vorhanden.")
        return

    for f in display_findings:
        agent_val = str(getattr(getattr(f, "agent", ""), "value", "?"))
        inp       = getattr(f, "input", "")
        threats   = getattr(f, "threat_sum", [])
        vulns     = getattr(f, "vulnerability_sum", [])
        icon      = AGENT_ICON.get(agent_val, "⚙️")

        with st.expander(f"{icon} {agent_val.upper()} — {inp[:60]}", expanded=False):
            if threats:
                st.markdown("**🎯 Bedrohungen**")
                for t in threats:
                    if str(t).strip():
                        st.markdown(f"- {t}")
            if vulns:
                st.markdown("**🔍 Schwachstellen / Befunde**")
                for v in vulns:
                    if str(v).strip():
                        st.markdown(f"- {v}")
            if not threats and not vulns:
                st.caption("Keine Befunde.")