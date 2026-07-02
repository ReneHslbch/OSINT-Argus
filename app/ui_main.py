
import streamlit as st
import time
from app.ui.analyse_tab import run_with_live_log
from app.ui.archive import check_archiv
from app.ui.leak_tab import render_leak_tab
from app.ui.results import render_results
from app.ui.sidebar import render_sidebar
from app.ui.strings import t

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
    st.session_state.language = st.session_state.ui_language

    st.markdown(
        '<div class="argus-header">'
        '<span style="font-size:2.2rem">👁️</span>'
        '<div><p class="argus-title">OSINT-Argus</p>'
        f'<p class="argus-sub">{t("header_subtitle", st.session_state.ui_language)}</p></div>'
        '</div>', unsafe_allow_html=True,
    )

    tab1, tab2 = st.tabs([
        t("tab_analyze", st.session_state.ui_language),
        t("tab_profile", st.session_state.ui_language),
    ])

    # --- TAB 1: ANALYSE-PIPELINE (STANDARD) ---
    with tab1:
        col_input, col_help = st.columns([3, 1])
        with col_input:
            user_input = st.text_area(
                t("input_label", st.session_state.ui_language),
                placeholder=t("input_placeholder", st.session_state.ui_language),
                height=190,
                label_visibility="collapsed",
            )
        with col_help:
            st.markdown(t("supported_inputs_title", st.session_state.ui_language))
            for line in t("supported_inputs", st.session_state.ui_language):
                st.caption(line)

        run_col, clear_col, _ = st.columns([1, 1, 4])
        with run_col:
            run_btn = st.button(t("btn_analyze", st.session_state.ui_language), type="primary", use_container_width=True)
        with clear_col:
            if st.button(t("btn_clear", st.session_state.ui_language), use_container_width=True):
                st.session_state.pop("last_result", None)
                st.rerun()

        if run_btn:
            if not user_input or not user_input.strip():
                st.warning(t("msg_input_required", st.session_state.ui_language))
            else:
                t0 = time.time()
                try:
                    result  = run_with_live_log(user_input.strip(), lang=st.session_state.language)
                    elapsed = round(time.time() - t0, 1)
                    st.success(t("msg_analysis_complete", st.session_state.ui_language, elapsed=elapsed))
                except Exception as e:
                    st.error(t("msg_pipeline_error", st.session_state.ui_language, type=type(e).__name__, error=e))
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
            render_results(st.session_state["last_result"], st.session_state.ui_language)

    # --- TAB 2: PROFIL & LEAK SCAN ---
    with tab2:
        render_leak_tab()


if __name__ == "__main__":
    main()