from typing import TypedDict, List, Dict, Any, Optional

class ArgusState(TypedDict):
    # ── Sprint 1 (unverändert) ─────────────────────────────
    user_input: str
    input_type: str
    current_agent: str
    next_agent: str
    findings: List[Dict[str, Any]]
    risk_score: Optional[int]
    summary: Optional[str]
    memory_context: Optional[str]
    # ── Sprint 2 — Email-Pipeline ──────────────────────────
    email_pass: int                        # 0=init | 1=extraction done | 2=judgement done
    domains_to_scan: List[str]             # Von EmailAgent Pass 1 befüllt
    domains_scanned: List[str]             # Vom Orchestrator nach jedem DomainAgent-Lauf befüllt
    current_domain: Optional[str]          # Aktuelle Domain die DomainAgent gerade analysiert
    email_extraction: Optional[Dict[str, Any]]  # Ergebnis von Pass 1