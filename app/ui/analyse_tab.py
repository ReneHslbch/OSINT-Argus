"""
app/ui/analyse_tab.py
Tab 1: Analyse-Pipeline mit Live-Agent-Log und Ergebnisdarstellung.
"""

import time
import streamlit as st

from app.graph import graph
from app.ui.styles import AGENT_ICON
from app.ui.results import render_results


# ── State-Builder ─────────────────────────────────────────────────────────────

def build_initial_state(user_input: str) -> dict:
    return {
        "user_input":     user_input,
        "input_type":     "unknown",
        "current_agent":  "input",
        "next_agent":     "",
        "findings":       [],
        "risk_score":     None,
        "summary":        None,
        "memory_context": None,
        "to_scan":        [],
        "scanned":        [],
        "current_check":  None,
        "file_paths":     [],
        "file_hashes":    [],
    }


# ── Live-Pipeline ─────────────────────────────────────────────────────────────

def run_with_live_log(user_input: str) -> dict:
    """Streamt die Graph-Pipeline und zeigt den Agent-Fortschritt live an."""
    state    = build_initial_state(user_input)
    log_slot = st.empty()
    log_rows: list[tuple] = []   # (agent, target, done)
    t0 = time.time()

    def render_log() -> None:
        from app.ui.styles import CSS # 💡 Wir holen deine globale CSS-Konstante
        
        rows_html = ""
        for agent, target, done in log_rows[-14:]:
            icon   = AGENT_ICON.get(agent, "⚙️")
            status = "✅" if done else "⏳"
            tgt    = target[:60] if target else ""
            
            # Hier greifen jetzt wieder deine Klassen .live-row, .live-agent, etc.
            rows_html += (
                f'<div class="live-row">'
                f'<span style="font-size:1rem;">{icon}</span>'
                f'<span class="live-agent">{agent.upper()}</span>'
                f'<span class="live-target">{tgt}</span>'
                f'<span class="live-status">{status}</span>'
                f'</div>'
            )
            
        elapsed = round(time.time() - t0, 1)
        log_slot.markdown(
            f'{CSS}' # 💡 Wir betten das CSS direkt ein, damit der Browser die Klassen kennt!
            f'<div style="border:1px solid rgba(128,128,128,0.15);border-radius:10px;'
            f'padding:1rem 1.2rem;margin:0.5rem 0">'
            f'<div style="font-size:0.7rem;opacity:0.4;margin-bottom:0.6rem;'
            f'letter-spacing:0.08em">AGENT PIPELINE · {elapsed}s</div>'
            f'{rows_html}'
            f'</div>',
            unsafe_allow_html=True,
        )

    all_findings: list = []
    final_state = state.copy()

    for chunk in graph.stream(state, stream_mode="updates"):
        for node_name, node_state in chunk.items():
            if log_rows:
                prev = log_rows[-1]
                log_rows[-1] = (prev[0], prev[1], True)

            target = node_state.get("current_check") or ""
            log_rows.append((node_name, target, False))
            render_log()

            for key in ("risk_score", "risk_level", "summary", "action_advice",
                        "input_type", "memory_context", "next_agent", "current_check"):
                if node_state.get(key) is not None:
                    final_state[key] = node_state[key]

            if node_state.get("findings"):
                all_findings.extend(node_state["findings"])

            for key in ("to_scan", "scanned"):
                if key in node_state:
                    final_state[key] = node_state[key]

    if log_rows:
        prev = log_rows[-1]
        log_rows[-1] = (prev[0], prev[1], True)
    render_log()

    final_state["findings"] = all_findings
    return final_state


# ── Tab-Render ────────────────────────────────────────────────────────────────

def render_analyse_tab() -> None:
    """Rendert den kompletten Analyse-Pipeline Tab."""
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
        for line in [
            "🌐 Domain / URL", "📧 E-Mail-Adresse", "📨 E-Mail-Inhalt",
            "📞 Telefonnummer", "📄 Datei / Hash", "🔎 Software + Version",
        ]:
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