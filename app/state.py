from typing import TypedDict, List, Dict, Any, Optional


class ArgusState(TypedDict):
    user_input: str
    input_type: str

    current_agent: str
    next_agent: str

    findings: List[Dict[str, Any]]

    risk_score: Optional[int]
    summary: Optional[str]

    memory_context: Optional[str]