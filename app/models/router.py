from pydantic import BaseModel, Field
from typing import Literal


class RouteDecision(BaseModel):

    input_type: Literal[
        "domain",
        "email",
        "url",
        "unknown"
    ] = Field(
        description="Detected input type"
    )

    next_agent: Literal[
        "domain",
        "email",
        "cve",
        "output"
    ] = Field(
        description="Next agent to execute"
    )

    reasoning: str = Field(
        description="Why this route was selected"
    )