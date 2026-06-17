import streamlit as st
import time
from app.graph import graph

st.set_page_config(
    page_title="OSINT-Argus",
    page_icon="👁️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
.argus-header {
    display: flex; align-items: center; gap: 12px;
    padding: 0.5rem 0 1.5rem 0;
    border-bottom: 1px solid rgba(128,128,128,0.2);
    margin-bottom: 1.5rem;
}
.argus-title { font-size: 1.6rem; font-weight: 700; letter-spacing: -0.02em; margin: 0; }
.argus-sub   { font-size: 0.75rem; opacity: 0.45; margin: 0; letter-spacing: 0.05em; text-transform: uppercase; }

.risk-badge { display: inline-block; padding: 5px 16px; border-radius: 999px; font-weight: 700; font-size: 0.9rem; letter-spacing: 0.05em; }
.risk-LOW      { background: #d1fae5; color: #065f46; }
.risk-MEDIUM   { background: #fef3c7; color: #92400e; }
.risk-HIGH     { background: #fee2e2; color: #991b1b; }
.risk-CRITICAL { background: #991b1b; color: #fff; animation: pulse 1.4s infinite; }
.risk-UNKNOWN  { background: #e5e7eb; color: #374151; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.65} }

.action-box { border-radius: 8px; padding: 1rem 1.2rem; font-size: 0.88rem; line-height: 1.75; }
.action-prevent  { background: #fffbeb; border-left: 4px solid #f59e0b; color: #78350f; }
.action-incident { background: #fff1f2; border-left: 4px solid #ef4444; color: #7f1d1d; }

.live-row {
    display: flex; align-items: center; gap: 10px;
    padding: 5px 0; font-size: 0.83rem;
    border-bottom: 1px solid rgba(128,128,128,0.1);
}
.live-agent  { font-weight: 600; min-width: 110px; }
.live-target { font-family: monospace; opacity: 0.7; font-size: 0.78rem; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.live-status { margin-left: auto; font-size: 0.85rem; }

.memory-card {
    background: rgba(128,128,128,0.06); border: 1px solid rgba(128,128,128,0.12);
    border-radius: 8px; padding: 0.55rem 0.85rem; margin-bottom: 0.45rem; font-size: 0.8rem;
}
.memory-q   { font-weight: 600; margin-bottom: 2px; }
.memory-lvl { font-size: 0.7rem; opacity: 0.45; }

.score-bar-wrap { height: 8px; border-radius: 4px; background: rgba(128,128,128,0.15); margin-top: 6px; }
.score-bar-fill { height: 8px; border-radius: 4px; }

.indicator-pill {
    background: rgba(239,68,68,0.07); border: 1px solid rgba(239,68,68,0.2);
    border-radius: 6px; padding: 6px 10px; font-size: 0.8rem; margin-bottom: 6px;
}
</style>
""", unsafe_allow_html=True)

LEVEL_ICON  = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "CRITICAL": "🚨", "UNKNOWN": "⚪"}
LEVEL_COLOR = {"LOW": "#10b981", "MEDIUM": "#f59e0b", "HIGH": "#ef4444", "CRITICAL": "#dc2626", "UNKNOWN": "#9ca3af"}
AGENT_ICON  = {
    "input": "📥", "orchestrator": "🧠", "domain": "🌐",
    "email": "📧", "cve": "🛡️", "phone": "📞",
    "file": "📄", "identity": "👤", "output": "📊",
}

def level_badge(level: str) -> str:
    return f'<span class="risk-badge risk-{level}">{LEVEL_ICON.get(level,"⚪")} {level}</span>'

def score_bar(score: int, color: str) -> str:
    pct = max(4, min(100, int(score)))
    return (
        f'<div class="score-bar-wrap">'
        f'<div class="score-bar-fill" style="width:{pct}%;background:{color}"></div>'
        f'</div>'
    )


# ── Sidebar ───────────────────────────────────────────────────────────────────
def render_sidebar():
    with st.sidebar:
        st.markdown("## 👁️ OSINT-Argus")
        st.caption("Multi-Agent Cybersecurity Analyzer")
        st.divider()
        history = st.session_state.get("history", [])
        if history:
            st.markdown("**Letzte Analysen**")
            for entry in reversed(history[-8:]):
                lvl  = entry.get("risk_level", "?")
                icon = LEVEL_ICON.get(lvl, "⚪")
                q    = entry.get("query", "–")[:38]
                st.markdown(
                    f'<div class="memory-card">'
                    f'<div class="memory-q">{icon} {q}</div>'
                    f'<div class="memory-lvl">{lvl} · Score {entry.get("score","?")}/100</div>'
                    f'</div>', unsafe_allow_html=True,
                )
        else:
            st.caption("Noch keine Analysen in dieser Sitzung.")
        st.divider()
        st.caption("Agents: Input · Orchestrator · Domain · Email · CVE · Phone · File · Identity · Output")


# ── State builder ─────────────────────────────────────────────────────────────
def build_initial_state(user_input: str) -> dict:
    return {
        "user_input": user_input, "input_type": "unknown",
        "current_agent": "input", "next_agent": "",
        "findings": [], "risk_score": None, "summary": None,
        "memory_context": None, "to_scan": [], "scanned": [],
        "current_check": None, "file_paths": [], "file_hashes": [],
    }


# ── Live pipeline runner ──────────────────────────────────────────────────────
def run_with_live_log(user_input: str):
    state    = build_initial_state(user_input)
    log_slot = st.empty()
    log_rows = []   # (agent, target, done)
    t0       = time.time()

    def render_log():
        rows_html = ""
        for agent, target, done in log_rows[-14:]:
            icon   = AGENT_ICON.get(agent, "⚙️")
            status = "✅" if done else "⏳"
            tgt    = target[:60] if target else ""
            rows_html += (
                f'<div class="live-row">'
                f'<span style="font-size:1rem">{icon}</span>'
                f'<span class="live-agent">{agent.upper()}</span>'
                f'<span class="live-target">{tgt}</span>'
                f'<span class="live-status">{status}</span>'
                f'</div>'
            )
        elapsed = round(time.time() - t0, 1)
        log_slot.markdown(
            f'<div style="border:1px solid rgba(128,128,128,0.15);border-radius:10px;padding:1rem 1.2rem;margin:0.5rem 0">'
            f'<div style="font-size:0.7rem;opacity:0.4;margin-bottom:0.6rem;letter-spacing:0.08em">AGENT PIPELINE · {elapsed}s</div>'
            f'{rows_html}'
            f'</div>', unsafe_allow_html=True,
        )

    # We accumulate ALL findings across stream chunks into one list
    all_findings = []
    final_state  = state.copy()

    for chunk in graph.stream(state, stream_mode="updates"):
        for node_name, node_state in chunk.items():
            # Mark previous step done
            if log_rows:
                prev = log_rows[-1]
                log_rows[-1] = (prev[0], prev[1], True)

            target = node_state.get("current_check") or ""
            log_rows.append((node_name, target, False))
            render_log()

            # DEBUG — print what each node actually returns
            if node_name == "output":
                print(f"\n🔍 DEBUG output node keys: {list(node_state.keys())}")
                print(f"🔍 DEBUG risk_level = {node_state.get('risk_level')!r}")
                print(f"🔍 DEBUG risk_score = {node_state.get('risk_score')!r}")
                print(f"🔍 DEBUG summary    = {str(node_state.get('summary',''))[:80]!r}")
                print(f"🔍 DEBUG action_adv = {str(node_state.get('action_advice',''))[:80]!r}")

            # Merge scalars
            for key in ("risk_score", "risk_level", "summary", "action_advice",
                        "input_type", "memory_context", "next_agent", "current_check"):
                if node_state.get(key) is not None:
                    final_state[key] = node_state[key]

            # Accumulate findings (never overwrite, only extend)
            if node_state.get("findings"):
                all_findings.extend(node_state["findings"])

            # Keep latest queue state
            for key in ("to_scan", "scanned"):
                if key in node_state:
                    final_state[key] = node_state[key]

    # Mark last step done
    if log_rows:
        prev = log_rows[-1]
        log_rows[-1] = (prev[0], prev[1], True)
    render_log()

    final_state["findings"] = all_findings
    return final_state


# ── Helpers for extracting OutputAgent report from findings ───────────────────
def extract_output_report(findings: list) -> dict:
    """
    Pull threat_score, vuln_score, and indicators out of the ORCHESTRATOR
    summary finding that OutputAgent appends.
    """
    threat_score = vuln_score = None
    indicators = []

    for f in findings:
        agent_val = str(getattr(getattr(f, "agent", ""), "value", ""))
        if agent_val != "orchestrator":
            continue
        threat_sum = getattr(f, "threat_sum", [])
        vuln_sum   = getattr(f, "vulnerability_sum", [])
        # Only the OutputAgent summary has "Threat Score:" in threat_sum
        if not any("Threat Score" in str(t) for t in threat_sum):
            continue
        for t in threat_sum:
            s = str(t)
            if "Threat Score" in s:
                try: threat_score = int(s.split(":")[-1].strip())
                except: pass
        for v in vuln_sum:
            s = str(v)
            if "Vulnerability Score" in s:
                try: vuln_score = int(s.split(":")[-1].strip())
                except: pass
            else:
                indicators.append(s)

    return {"threat_score": threat_score, "vuln_score": vuln_score, "indicators": indicators}


# ── Render results ────────────────────────────────────────────────────────────
def render_results(result: dict):
    risk_level = result.get("risk_level") or "UNKNOWN"
    risk_score = int(result.get("risk_score") or 0)
    summary    = result.get("summary") or ""
    action_adv = result.get("action_advice") or ""
    findings   = result.get("findings") or []

    report = extract_output_report(findings)
    threat_score = report["threat_score"] if report["threat_score"] is not None else risk_score
    vuln_score   = report["vuln_score"]   if report["vuln_score"]   is not None else risk_score
    indicators   = report["indicators"]

    st.markdown("---")

    # ── Score row — use the REAL scores from OutputAgent ─────────────────────
    col_ts, col_vs, col_lvl = st.columns([1, 1, 1])

    with col_ts:
        st.markdown("**Bedrohungs-Score**")
        color_t = LEVEL_COLOR.get(risk_level, "#9ca3af")
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

    # ── Summary ───────────────────────────────────────────────────────────────
    if summary:
        st.markdown("---")
        st.markdown("#### Zusammenfassung")
        st.info(summary)

    # ── Indicators ────────────────────────────────────────────────────────────
    if indicators:
        st.markdown("#### 💡 Haupt-Risikoindikatoren")
        cols = st.columns(3)
        for i, ind in enumerate(indicators[:9]):
            clean = ind.replace("**", "").replace("`", "").strip("- ").strip()
            if not clean:
                continue
            with cols[i % 3]:
                st.markdown(f'<div class="indicator-pill">⚠️ {clean}</div>', unsafe_allow_html=True)

    # ── Action advice ─────────────────────────────────────────────────────────
    if action_adv:
        st.markdown("---")
        st.markdown("#### Handlungsempfehlungen")

        # Split on the marker the OutputAgent uses
        split_marker = "FALLS BEREITS GEKLICKT:"
        if split_marker in action_adv:
            parts = action_adv.split(split_marker, 1)
            prevent_text  = parts[0].replace("PRÄVENTION:", "").strip()
            incident_text = parts[1].strip()
        else:
            # OutputAgent sometimes uses newline-separated numbered lists without the marker
            prevent_text  = action_adv.strip()
            incident_text = ""

        col_p, col_i = st.columns(2)
        with col_p:
            st.markdown("🚫 **Unbedingt vermeiden**")
            # Render as markdown so bold/lists work
            st.markdown(
                f'<div class="action-box action-prevent">{prevent_text}</div>',
                unsafe_allow_html=True,
            )
        with col_i:
            if incident_text:
                st.markdown("🔥 **Falls bereits geklickt**")
                st.markdown(
                    f'<div class="action-box action-incident">{incident_text}</div>',
                    unsafe_allow_html=True,
                )
            else:
                st.markdown("🔥 **Falls bereits geklickt**")
                st.markdown(
                    '<div class="action-box action-incident">'
                    '1. Gerät sofort vom Netzwerk trennen.<br>'
                    '2. Passwörter von einem sicheren Gerät ändern.<br>'
                    '3. Bank / IT-Sicherheit kontaktieren.<br>'
                    '4. Gerät auf Malware scannen.'
                    '</div>',
                    unsafe_allow_html=True,
                )

    # ── Agent findings detail ─────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("#### Agent-Findings (Detail)")

    # Show only real agent findings — skip orchestrator routing logs and the output summary
    display_findings = []
    seen = set()
    for f in findings:
        agent_val = str(getattr(getattr(f, "agent", ""), "value", ""))
        inp       = getattr(f, "input", "")
        key       = (agent_val, inp)
        if agent_val == "orchestrator":
            continue
        if key in seen:
            continue
        seen.add(key)
        display_findings.append(f)

    if not display_findings:
        st.caption("Keine Detail-Findings vorhanden.")
    else:
        for f in display_findings:
            agent_val  = str(getattr(getattr(f, "agent", ""), "value", "?"))
            inp        = getattr(f, "input", "")
            threats    = getattr(f, "threat_sum", [])
            vulns      = getattr(f, "vulnerability_sum", [])
            icon       = AGENT_ICON.get(agent_val, "⚙️")

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


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    render_sidebar()

    st.markdown(
        '<div class="argus-header">'
        '<span style="font-size:2.2rem">👁️</span>'
        '<div><p class="argus-title">OSINT-Argus</p>'
        '<p class="argus-sub">Multi-Agent Cybersecurity Analyzer</p></div>'
        '</div>', unsafe_allow_html=True,
    )

    col_input, col_help = st.columns([3, 1])
    with col_input:
        user_input = st.text_area(
            "Input",
            placeholder=(
                "Domain          →  example.com\n"
                "E-Mail-Adresse  →  user@domain.com\n"
                "E-Mail-Inhalt   →  komplette Mail hier reinkopieren\n"
                "Telefonnummer   →  +49 151 12345678\n"
                "Dateipfad/Hash  →  /pfad/zur/datei.pdf"
            ),
            height=190,
            label_visibility="collapsed",
        )
    with col_help:
        st.markdown("**Unterstützte Inputs**")
        for line in ["🌐 Domain / URL", "📧 E-Mail-Adresse", "📨 E-Mail-Inhalt",
                     "📞 Telefonnummer", "📄 Datei / Hash", "🔎 Software + Version"]:
            st.caption(line)

    run_col, clear_col, _ = st.columns([1, 1, 4])
    with run_col:
        run_btn = st.button("🔍 Analysieren", type="primary", use_container_width=True)
    with clear_col:
        if st.button("✕ Leeren", use_container_width=True):
            st.session_state.pop("last_result", None)
            st.rerun()

    if run_btn:
        if not user_input or not user_input.strip():
            st.warning("Bitte einen Input eingeben.")
        else:
            t0 = time.time()
            try:
                result  = run_with_live_log(user_input.strip())
                elapsed = round(time.time() - t0, 1)
                st.success(f"✅ Analyse abgeschlossen in {elapsed}s")
            except Exception as e:
                st.error(f"❌ Pipeline-Fehler: {type(e).__name__}: {e}")
                st.stop()

            if "history" not in st.session_state:
                st.session_state["history"] = []
            st.session_state["history"].append({
                "query":      user_input.strip()[:60],
                "risk_level": result.get("risk_level", "UNKNOWN"),
                "score":      result.get("risk_score", 0),
            })
            st.session_state["last_result"] = result

    if "last_result" in st.session_state:
        render_results(st.session_state["last_result"])


if __name__ == "__main__":
    main()