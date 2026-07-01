from typing import TypedDict, List, Dict, Any, Optional

from app.models.findings import Findings


class ArgusState(TypedDict, total=False):
    user_input: str
    input_type: str
    current_agent: str
    next_agent: str
    findings: List[Findings]
    memory_context: Optional[str]
    to_scan: List[str]
    scanned: List[str]
    current_check: Optional[str]
    file_paths: List[str]
    file_hashes: List[str]
    node_timings: Dict[str, List[Dict[str, Any]]]      