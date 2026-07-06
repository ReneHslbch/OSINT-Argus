"""
app/config_manager.py

Verwaltung der Mailbox-Konfiguration (Auto-Analyze Toggle).
"""

import os
from pathlib import Path


def get_auto_analyze() -> bool:
    """Liest den Auto-Analyze Status aus .env."""
    return os.getenv("MAILBOX_AUTO_ANALYZE", "true").lower() == "true"


def set_auto_analyze(enabled: bool) -> bool:
    """Setzt den Auto-Analyze Status in .env."""
    env_path = Path(".env")
    
    if not env_path.exists():
        return False
    
    content = env_path.read_text(encoding="utf-8")
    lines = content.split("\n")
    
    found = False
    for i, line in enumerate(lines):
        if line.startswith("MAILBOX_AUTO_ANALYZE="):
            lines[i] = f"MAILBOX_AUTO_ANALYZE={'true' if enabled else 'false'}"
            found = True
            break
    
    if not found:
        lines.append(f"MAILBOX_AUTO_ANALYZE={'true' if enabled else 'false'}")
    
    env_path.write_text("\n".join(lines), encoding="utf-8")
    return True
