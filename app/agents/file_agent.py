import json

from app.agents.base_agent import BaseAgent
from app.models.llm import get_llm
from app.models.file_analysis import FileAnalysis
from app.models.findings import Findings
from app.models.agent_type import AgentType
from app.state import ArgusState
from app.utils.prompt_cleaner import clean_llm_output
import os
from app.tools.file_tools import (
    extract_universell_document_metadata,
    check_file_hash_virustotal,
)
from app.prompts import FILE_AGENT_SYSTEM_PROMPT

class FileAgent(BaseAgent):

    def __init__(self):
        self.llm = get_llm().with_structured_output(
            FileAnalysis
        )

    def run(self, state: ArgusState) -> ArgusState:
        target = state.get("current_check")

        if not target:
            return state
        
        # Saubere Extraktion des Pfads aus Mustern wie file_path(pfad) oder file_path::pfad
        clean_path = target
        if "file_path(" in target and target.endswith(")"):
            clean_path = target.split("file_path(")[-1][:-1]
        elif "::" in target:
            clean_path = target.split("::")[-1]
            
        # Eventuelle Slashes für Windows vereinheitlichen (Sicherheitsnetz)
        clean_path = os.path.normpath(clean_path)

        # 1. Universelle Metadaten extrahieren (HIER JETZT MIT clean_path!)
        metadata_result = extract_universell_document_metadata.invoke({"file_path": clean_path})

        # 2. Hashes für den VirusTotal-Scan vorbereiten
        vt_results = []
        hashes_to_check = list(state.get("file_hashes", []))
        
        # Falls das aktuelle Target selbst ein Hash ist (Länge 32, 40 oder 64 Zeichen)
        if len(target) in [32, 40, 64] and target not in hashes_to_check:
            hashes_to_check.append(target)

        # 3. VirusTotal für jeden gefundenen Hash aufrufen
        for file_hash in hashes_to_check:
            result = check_file_hash_virustotal.invoke({"file_hash": file_hash})
            vt_results.append(result)

        # 4. Analyse durch das LLM auswerten lassen
        analysis_raw = self.llm.invoke([
            {
                "role": "system",
                "content": FILE_AGENT_SYSTEM_PROMPT
            },
            {
                "role": "user",
                "content": f"""
Datei/Target:
{clean_path}

Metadaten-Ergebnisse:
{metadata_result}

VirusTotal-Ergebnisse:
{vt_results}
"""
            }
        ])
        
        # Structured output sollte bereits sauber sein, aber zur Sicherheit
        if hasattr(analysis_raw, 'model_dump'):
            analysis = analysis_raw
        else:
            cleaned = clean_llm_output(str(analysis_raw))
            try:
                analysis = FileAnalysis(**json.loads(cleaned))
            except Exception:
                analysis = FileAnalysis(
                    threat_indicators=[],
                    metadata_leaks=["Parsing-Fehler bei Datei-Analyse"],
                    risk_level="UNKNOWN",
                    reasoning="Konnte Analyse-Ergebnis nicht parsen.",
                    extracted_identities=[]
                )

        # 5. Befunde im globalen State speichern
        finding = Findings(
                agent=AgentType.FILE,
                input=target,
                threat_sum=analysis.threat_indicators,
                vulnerability_sum=analysis.metadata_leaks,
            )
        
        # NEU: Wenn das LLM Identitäten (wie Autoren) extrahiert hat, füttern wir sie zurück in den State
        if hasattr(analysis, "extracted_identities") and analysis.extracted_identities:
            for identity in analysis.extracted_identities:
                if identity not in state["to_scan"]:
                    state["to_scan"].append(identity)
                    print(f"[FILE] Neues Identitats-Target entdeckt und registriert: {identity}")
            
        print(f"\n[FILE] {clean_path}")
        print(f"[WARN] Risiko: {analysis.risk_level}")
        print(f"[INFO] {analysis.reasoning}")


        return {**state, "findings": [finding]}