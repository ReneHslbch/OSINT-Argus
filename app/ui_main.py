import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import time
from app.ui.analyse_tab import run_with_live_log
from app.ui.archive import check_archiv
from app.ui.leak_tab import render_leak_tab
from app.ui.results import render_results
from app.ui.sidebar import render_sidebar
from app.ui.strings import t
from app.utils.prompt_cleaner import clean_llm_output

st.set_page_config(
    page_title="OSINT-Argus",
    page_icon="👁️",
    layout="wide",
    initial_sidebar_state="expanded",
)

if "ui_language" not in st.session_state:
    st.session_state.ui_language = "en"

def main():
    render_sidebar()

    if check_archiv(): return

    # Sync analysis language with UI language
    st.session_state.language = st.session_state.get("ui_language", "en") or "en"

    # Prüfen ob Input aus Mail-Tab kommt und Textarea befüllen
    if "user_input" in st.session_state and st.session_state.get("from_mail_tab"):
        st.session_state.pop("from_mail_tab", None)
        # Automatisch zum Analyse-Tab wechseln und Analyse starten
        st.session_state["switch_to_analyze"] = True
    
    # Automatisch Analyse starten wenn Flag gesetzt
    if st.session_state.get("switch_to_analyze"):
        st.session_state.pop("switch_to_analyze", None)
        # Trigger Analyse-Button programmatisch
        st.session_state["auto_run_analyze"] = True

    ui_lang = st.session_state.get("ui_language", "en") or "en"
    st.markdown(
        '<div class="argus-header">'
        '<span style="font-size:2.2rem">👁️</span>'
        '<div><p class="argus-title">OSINT-Argus</p>'
        f'<p class="argus-sub">{t("header_subtitle", ui_lang)}</p></div>'
        '</div>', unsafe_allow_html=True,
    )

    tab1, tab2, tab3 = st.tabs([
        t("tab_analyze", ui_lang),
        t("tab_profile", ui_lang),
        "📧 Mail",
    ])
    
    auto_analyze_mode = os.getenv("MAILBOX_AUTO_ANALYZE", "true").lower() == "true"

    # --- TAB 1: ANALYSE-PIPELINE (STANDARD) ---
    with tab1:
        col_input, col_help = st.columns([3, 1])
        with col_input:
            # Nur user_input poppen wenn NICHT gerade Mail-Analyse läuft
            # (sonst wird der Input fuer render_analysis_execution() entfernt)
            if not st.session_state.get("analyzing_mail_uid"):
                pre_filled = st.session_state.pop("user_input", None)
            else:
                pre_filled = None
            
            # Debug: Zeige Input-Länge vor Bereinigung
            if pre_filled:
                print(f"[DEBUG] Input vor Bereinigung: {len(pre_filled)} Zeichen")
                print(f"[DEBUG] Input Preview (erste 300 Zeichen): {pre_filled[:300]}")
                print(f"[DEBUG] Input Preview (letzte 300 Zeichen): {pre_filled[-300:] if len(pre_filled) > 300 else pre_filled}")
                
                # Zentrale Bereinigung von Editor-Markierungen
                input_clean = clean_llm_output(pre_filled)
                print(f"[DEBUG] Input nach Bereinigung: {len(input_clean)} Zeichen")
                print(f"[DEBUG] Input Preview nach Bereinigung (letzte 100 Zeichen): {input_clean[-100:] if len(input_clean) > 100 else input_clean}")
                pre_filled = input_clean
            
            user_input = st.text_area(
                t("input_label", ui_lang),
                placeholder=t("input_placeholder", ui_lang),
                height=190,
                label_visibility="collapsed",
                value=pre_filled or "",
                key="main_input"
            )
        with col_help:
            st.markdown(t("supported_inputs_title", ui_lang))
            for line in t("supported_inputs", ui_lang):
                st.caption(line)

        run_col, clear_col, _ = st.columns([1, 1, 4])
        with run_col:
            run_btn = st.button(t("btn_analyze", ui_lang), type="primary", use_container_width=True)
        with clear_col:
            if st.button(t("btn_clear", ui_lang), use_container_width=True):
                st.session_state.pop("last_result", None)
                st.rerun()

        # Automatische Analyse starten wenn Flag gesetzt
        if st.session_state.get("auto_run_analyze"):
            st.session_state.pop("auto_run_analyze", None)
            if not user_input or not user_input.strip():
                st.warning(t("msg_input_required", ui_lang))
            else:
                t0 = time.time()
                try:
                    result = run_with_live_log(user_input.strip(), lang=st.session_state.language)
                    elapsed = round(time.time() - t0, 1)
                    st.success(t("msg_analysis_complete", ui_lang, elapsed=elapsed))
                except Exception as e:
                    st.error(t("msg_pipeline_error", ui_lang, type=type(e).__name__, error=e))

            if "history" not in st.session_state:
                st.session_state["history"] = []
            st.session_state["history"].append({
                "query": user_input.strip()[:60],
                "risk_level": result.get("risk_level", "UNKNOWN"),
                "score": result.get("risk_score", 0),
            })
            st.session_state["last_result"] = result
        elif run_btn:
            if not user_input or not user_input.strip():
                st.warning(t("msg_input_required", ui_lang))
            else:
                t0 = time.time()
                try:
                    result = run_with_live_log(user_input.strip(), lang=st.session_state.language)
                    elapsed = round(time.time() - t0, 1)
                    st.success(t("msg_analysis_complete", ui_lang, elapsed=elapsed))
                except Exception as e:
                    st.error(t("msg_pipeline_error", ui_lang, type=type(e).__name__, error=e))
                    st.stop()

                if "history" not in st.session_state:
                    st.session_state["history"] = []
                st.session_state["history"].append({
                    "query": user_input.strip()[:60],
                    "risk_level": result.get("risk_level", "UNKNOWN"),
                    "score": result.get("risk_score", 0),
                })
                st.session_state["last_result"] = result

        if "last_result" in st.session_state:
            render_results(st.session_state["last_result"], st.session_state.ui_language)

    # --- TAB 2: PROFIL & LEAK SCAN ---
    with tab2:
        render_leak_tab()

    # --- TAB 3: MAIL ACCESS ---
    with tab3:
        from app.ui.mail_access import render_mail_access_tab
        render_mail_access_tab()


if __name__ == "__main__":
    main()
