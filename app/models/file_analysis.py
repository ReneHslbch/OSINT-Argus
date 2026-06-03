from pydantic import BaseModel, Field
from typing import List, Literal


class FileAnalysis(BaseModel):

    threat_indicators: List[str] = Field(
        description="Malware-Indikatoren oder verdächtige Merkmale."
    )

    metadata_leaks: List[str] = Field(
        description="Informationen aus Metadaten die OSINT-relevant oder vertraulich sind."
    )

    risk_level: Literal[
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ] = Field(
        description="Gesamtrisiko der Datei."
    )

    reasoning: str = Field(
        description="Analystische Begründung."
    )