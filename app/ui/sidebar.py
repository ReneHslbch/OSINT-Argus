"""
app/ui/sidebar.py
Rendert die linke Seitenleiste mit Analyse-Historie aus ChromaDB + Sprachselector.
"""

import json
import streamlit as st

from app.memory.chroma_memory import get_last_analyses
from app.ui.styles import LEVEL_ICON
from app.ui.strings import t, get_language_options


def render_sidebar() -> None:
    """Seitenleiste mit den letzten 8 Analysen aus der ChromaDB."""
    with st.sidebar:
        if "ui_language" not in st.session_state:
            st.session_state.ui_language = "en"
        
        lang_options = get_language_options()
        lang_labels = [f"{code} - {name}" for code, name in lang_options]
        selected_idx = st.selectbox(
            t("label_language", "en"),
            options=range(len(lang_labels)),
            format_func=lambda i: lang_labels[i],
            index=0 if st.session_state.ui_language == "en" else 1,
            help="Switch UI language (does not affect analysis language)"
        )
        st.session_state.ui_language = lang_options[selected_idx][0]
        
        st.markdown(t("sidebar_title", st.session_state.ui_language))
        st.caption(t("header_subtitle", st.session_state.ui_language))
        st.divider()

        st.markdown(t("sidebar_history", st.session_state.ui_language))

        try:
            db_entries = get_last_analyses(limit=8)
        except Exception:
            st.error(t("msg_history_error", st.session_state.ui_language))
            db_entries = []

        if db_entries:
            for entry in reversed(db_entries):
                try:
                    content_data = json.loads(entry["content"])
                    lvl   = content_data.get("risk_level", "UNKNOWN")
                    score = content_data.get("score", "?")
                except Exception:
                    lvl   = "?"
                    score = "?"

                icon        = LEVEL_ICON.get(lvl, "⚪")
                query_text  = entry["query"][:35]
                ts          = entry.get("timestamp", "")
                timestamp   = ts.split(" ")[1] if " " in ts else ""
                button_label = f"{icon} {query_text}\n{lvl} · Score {score}/100 · {timestamp}"

                if st.button(button_label, key=f"hist_{entry['id']}", use_container_width=True):
                    st.session_state["active_report_query"]   = entry["query"]
                    st.session_state["active_report_content"] = entry["content"]
                    st.rerun()
        else:
            st.caption(t("msg_no_history", st.session_state.ui_language))

        st.divider()
        st.caption(t("caption_agents", st.session_state.ui_language))