"""
app/ui/results.py
Extrahiert und rendert die Ergebnisse der Analyse-Pipeline.
"""

import streamlit as st

from app.ui.styles import LEVEL_COLOR, LEVEL_ICON, AGENT_ICON, level_badge, score_bar
from app.ui.strings import t


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