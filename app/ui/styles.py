"""
app/ui/styles.py
Globale CSS-Styles, Konstanten und kleine HTML-Hilfsfunktionen.
"""

CSS = """
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
"""

LEVEL_ICON = {
    "LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴",
    "CRITICAL": "🚨", "UNKNOWN": "⚪",
}

LEVEL_COLOR = {
    "LOW": "#10b981", "MEDIUM": "#f59e0b", "HIGH": "#ef4444",
    "CRITICAL": "#dc2626", "UNKNOWN": "#9ca3af",
}

AGENT_ICON = {
    "input": "📥", "orchestrator": "🧠", "domain": "🌐",
    "email": "📧", "cve": "🛡️", "phone": "📞",
    "file": "📄", "identity": "👤", "output": "📊",
}


def level_badge(level: str) -> str:
    """Gibt ein farbiges HTML-Badge für das Risiko-Level zurück."""
    icon = LEVEL_ICON.get(level, "⚪")
    return f'<span class="risk-badge risk-{level}">{icon} {level}</span>'


def score_bar(score: int, color: str) -> str:
    """Gibt einen farbigen HTML-Fortschrittsbalken zurück."""
    pct = max(4, min(100, int(score)))
    return (
        f'<div class="score-bar-wrap">'
        f'<div class="score-bar-fill" style="width:{pct}%;background:{color}"></div>'
        f'</div>'
    )