import operator  # <-- 1. WICHTIG: Oben importieren!
from typing import TypedDict, List, Dict, Any, Optional, Annotated  # <-- 2. Annotated hinzufügen

from app.models.findings import Findings


class ArgusState(TypedDict, total=False):
    user_input: str
    input_type: str
    current_agent: str
    next_agent: str
    
    # 3. WICHTIG: Hier mit Annotated und operator.add definieren:
    findings: Annotated[List[Findings], operator.add]
    
    memory_context: Optional[str]
    to_scan: List[str]
    scanned: List[str]
    current_check: Optional[str]
    file_paths: List[str]
    file_hashes: List[str]
    node_timings: Dict[str, List[Dict[str, Any]]]
    language: str
    risk_score: Optional[int]        # NEU
    risk_level: Optional[str]        # NEU
    summary: Optional[str]           # NEU
    action_advice: Optional[str]     # NEU