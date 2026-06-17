
import streamlit as st
import time
from app.ui.analyse_tab import run_with_live_log
from app.ui.archive import check_archiv
from app.ui.leak_tab import render_leak_tab
from app.ui.results import render_results
from app.ui.sidebar import render_sidebar

st.set_page_config(
    page_title="OSINT-Argus",
    page_icon="👁️",
    layout="wide",
    initial_sidebar_state="expanded",
)
# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    render_sidebar()

    if check_archiv(): return

    st.markdown(
        '<div class="argus-header">'
        '<span style="font-size:2.2rem">👁️</span>'
        '<div><p class="argus-title">OSINT-Argus</p>'
        '<p class="argus-sub">Multi-Agent Cybersecurity Analyzer</p></div>'
        '</div>', unsafe_allow_html=True,
    )

    # ==============================================================================
    # SCHRITT 3: TABS FÜR DIE SEKTIONEN (Standardmäßig ist Tab 1 aktiv)
    # ==============================================================================
    tab1, tab2 = st.tabs(["🔍 Analyse-Pipeline", "👤 Profil & Leak-Check"])

    # --- TAB 1: ANALYSE-PIPELINE (STANDARD) ---
    with tab1:
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

    # --- TAB 2: PROFIL & LEAK SCAN ---
    with tab2:
        render_leak_tab()


if __name__ == "__main__":
    main()