"""
app/ui/archive.py
Prüft, ob ein archivierter ChromaDB-Report geladen ist, und zeigt ihn an.
Gibt True zurück, wenn ein Archiv-Report angezeigt wurde (main() soll dann abbrechen).
"""

import json
import streamlit as st

from app.ui.styles import LEVEL_ICON, LEVEL_COLOR, level_badge, score_bar
from app.ui.strings import t


def check_archiv() -> bool:
    """
    Zeigt einen archivierten Report aus dem Session-State an.
    Gibt True zurück wenn ein Report gerendert wurde, sonst False.
    """
    if "active_report_content" not in st.session_state:
        return False
    
    lang = st.session_state.get("ui_language", "en")

    st.markdown(
        '<div class="argus-header">'
        '<span style="font-size:2.2rem">📜</span>'
        '<div><p class="argus-title">Archivierter Befund</p>'
        f'<p class="argus-sub">Eingabe: {st.session_state["active_report_query"][:80]}...</p></div>'
        '</div>',
        unsafe_allow_html=True,
    )
    st.info(t("archive_info", lang))

    try:
        data = json.loads(st.session_state["active_report_content"])
        _render_archive_body(data, lang)
    except Exception:
        st.warning(t("archive_unstructured", lang))
        st.text_area(t("label_raw_data", lang), st.session_state["active_report_content"], height=350)

    st.markdown("---")
    if st.button(t("btn_new_analysis", lang), type="primary"):
        del st.session_state["active_report_content"]
        del st.session_state["active_report_query"]
        st.rerun()

    return True


# ── private Hilfsfunktion ────────────────────────────────────────────────────

def _render_archive_body(data: dict, lang: str) -> None:
    lvl            = data.get("risk_level", "UNKNOWN")
    score          = data.get("score", 0)
    summary        = data.get("summary", "")
    indicators     = data.get("indicators", [])
    prevent_text   = data.get("action_prevent", "")
    incident_steps = data.get("action_incident_response", [])

    col_ts, col_vs, col_lvl = st.columns([1, 1, 1])
    color_t = LEVEL_COLOR.get(lvl, "#9ca3af")

    with col_ts:
        st.markdown(t("label_risk_score", lang))
        st.markdown(
            f'<span style="font-size:2.2rem;font-weight:700">{score}</span>'
            f'<span style="opacity:.4;font-size:1rem"> / 100</span>'
            f'{score_bar(score, color_t)}',
            unsafe_allow_html=True,
        )
    with col_vs:
        st.markdown(t("label_data_source", lang))
        st.markdown(
            '<span style="font-size:1.5rem;font-weight:600;display:block;margin-top:8px;">'
            'ChromaDB Persistent</span>',
            unsafe_allow_html=True,
        )
    with col_lvl:
        st.markdown(t("label_risk_level", lang))
        st.markdown(level_badge(lvl), unsafe_allow_html=True)

    if summary:
        st.markdown("---")
        st.markdown("#### Zusammenfassung")
        st.info(summary)

    if indicators:
        st.markdown("#### 💡 Haupt-Risikoindikatoren")
        cols = st.columns(3)
        for i, ind in enumerate(indicators[:9]):
            clean = ind.replace("**", "").replace("`", "").strip("- ").strip()
            if not clean:
                continue
            with cols[i % 3]:
                st.markdown(f'<div class="indicator-pill">⚠️ {clean}</div>', unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### Handlungsempfehlungen")
    col_p, col_i = st.columns(2)

    with col_p:
        st.markdown(t("header_prevention", lang))
        st.markdown(
            f'<div class="action-box action-prevent">{prevent_text}</div>',
            unsafe_allow_html=True,
        )
    with col_i:
        st.markdown(t("header_incident", lang))
        if incident_steps:
            incident_text = "<br>".join(
                step if step.startswith(("1.", "2.", "3.", "4.")) else f"{idx + 1}. {step}"
                for idx, step in enumerate(incident_steps)
            )
        else:
            incident_text = t("msg_no_incident_steps", lang)
        st.markdown(
            f'<div class="action-box action-incident">{incident_text}</div>',
            unsafe_allow_html=True,
        )