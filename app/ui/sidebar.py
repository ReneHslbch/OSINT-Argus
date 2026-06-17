"""
app/ui/sidebar.py
Rendert die linke Seitenleiste mit Analyse-Historie aus ChromaDB.
"""

import json
import streamlit as st

from app.memory.chroma_memory import get_last_analyses
from app.ui.styles import LEVEL_ICON


def render_sidebar() -> None:
    """Seitenleiste mit den letzten 8 Analysen aus der ChromaDB."""
    with st.sidebar:
        st.markdown("## 👁️ OSINT-Argus")
        st.caption("Multi-Agent Cybersecurity Analyzer")
        st.divider()

        st.markdown("**Letzte Analysen (ChromaDB)**")

        try:
            db_entries = get_last_analyses(limit=8)
        except Exception:
            st.error("Fehler beim Laden der Historie")
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
            st.caption("Noch keine Analysen in der Datenbank vorhanden.")

        st.divider()
        st.caption(
            "Agents: Input · Orchestrator · Domain · Email · CVE · Phone · File · Identity · Output"
        )