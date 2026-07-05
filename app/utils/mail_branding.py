"""
app/utils/mail_branding.py

Zentrales, wiederverwendbares Email-Branding für OSINT-Argus.
Wird sowohl von der Registrierungs- als auch der Analyse-Mail genutzt,
damit beide optisch konsistent sind.
"""

BRAND_CSS = """
<style>
  body { font-family: 'Segoe UI', Arial, sans-serif; background:#f1f5f9; margin:0; padding:0; }
  .wrapper { max-width:640px; margin:30px auto; background:#ffffff; border-radius:14px; overflow:hidden;
             box-shadow:0 6px 20px rgba(15,23,42,0.08); }
  .header { background:linear-gradient(135deg,#0f172a,#1a1a2e 60%,#16213e); color:#fff; padding:30px 34px; }
  .header .brand { display:flex; align-items:center; gap:10px; }
  .header .brand span.icon { font-size:1.8rem; }
  .header h1 { margin:0; font-size:1.3rem; font-weight:700; letter-spacing:-0.01em; }
  .header p.sub { margin:6px 0 0; opacity:.6; font-size:.72rem; letter-spacing:.12em; text-transform:uppercase; }
  .body { padding:30px 34px; color:#1e293b; line-height:1.65; font-size:.95rem; }
  .card { background:#f8fafc; border:1px solid #e2e8f0; border-radius:10px; padding:18px 20px; margin:18px 0; }
  .card.accent { border-left:4px solid #3b82f6; }
  .card.warn   { background:#fffbeb; border:1px solid #fde68a; border-left:4px solid #f59e0b; color:#78350f; }
  .card.danger { background:#fef2f2; border:1px solid #fecaca; border-left:4px solid #ef4444; color:#7f1d1d; }
  .key-box { background:#0f172a; color:#22c55e; font-family:'Courier New',monospace; font-size:1.3rem;
             font-weight:700; letter-spacing:.15em; text-align:center; padding:18px; border-radius:10px; margin:20px 0; }
  .badge { display:inline-block; padding:5px 16px; border-radius:999px; font-weight:700; font-size:.82rem; letter-spacing:.04em; }
  .badge-LOW      { background:#d1fae5; color:#065f46; }
  .badge-MEDIUM   { background:#fef3c7; color:#92400e; }
  .badge-HIGH     { background:#fee2e2; color:#991b1b; }
  .badge-CRITICAL { background:#991b1b; color:#fff; }
  .badge-UNKNOWN  { background:#e5e7eb; color:#374151; }
  .score-row { display:flex; gap:24px; margin:14px 0 6px; flex-wrap:wrap; }
  .score-item .label { font-size:.72rem; opacity:.55; text-transform:uppercase; letter-spacing:.06em; }
  .score-item .value { font-size:1.6rem; font-weight:700; }
  h3.section { font-size:.95rem; color:#0f172a; margin:26px 0 10px; padding-bottom:6px; border-bottom:2px solid #e2e8f0; }
  .agent-card { border:1px solid #e2e8f0; border-radius:8px; padding:14px 16px; margin-bottom:10px; }
  .agent-card .agent-title { font-weight:700; font-size:.88rem; color:#1e3a8a; margin-bottom:6px; }
  .agent-card .agent-target { font-family:'Courier New',monospace; font-size:.78rem; color:#64748b; margin-bottom:8px; word-break:break-all; }
  .agent-card ul { margin:4px 0 8px 18px; padding:0; }
  .agent-card li { margin-bottom:4px; font-size:.85rem; }
  ol.incident { margin:6px 0 0 18px; padding:0; }
  ol.incident li { margin-bottom:6px; }
  .footer { text-align:center; font-size:.72rem; color:#94a3b8; padding:20px; border-top:1px solid #e2e8f0; }
</style>
"""


def render_shell(icon: str, brand: str, subtitle: str, body_html: str) -> str:
    """Wraps arbitrary body HTML in the shared OSINT-Argus email shell."""
    return f"""
<html>
<head>{BRAND_CSS}</head>
<body>
<div class="wrapper">
  <div class="header">
    <div class="brand"><span class="icon">{icon}</span><h1>{brand}</h1></div>
    <p class="sub">{subtitle}</p>
  </div>
  <div class="body">
    {body_html}
  </div>
  <div class="footer">OSINT-Argus Team · Automatisierte Nachricht</div>
</div>
</body>
</html>
"""