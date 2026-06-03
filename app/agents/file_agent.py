from app.agents.base_agent import BaseAgent
from app.models.llm import get_llm
from app.models.file_analysis import FileAnalysis
from app.models.findings import Findings
from app.models.agent_type import AgentType
from app.state import ArgusState
import os
from app.tools.file_tools import (
    extract_universell_document_metadata,
    check_file_hash_virustotal,
)

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
        analysis: FileAnalysis = self.llm.invoke([
            {
                "role": "system",
                "content": """
Du bist ein erfahrener Malware-Analyst und OSINT-Experte.

Analysiere Dateimetadaten und VirusTotal-Ergebnisse.

Achte besonders auf:
- Personenbezug
- Autoren
- Benutzernamen
- Firmennamen
- interne Hostnamen
- interne Netzwerkinformationen
- UNC-Pfade
- Sharepoint Hinweise
- Build-Systeme
- Entwicklungsumgebungen
- Office-Metadaten
- PDF-Metadaten
- Malware-Indikatoren
- verdächtige Dateieigenschaften

Bewerte ausschließlich auf Basis der vorliegenden Daten.

Wenn keine Hinweise vorliegen, liefere leere Listen zurück.
"""
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

        # 5. Befunde im globalen State speichern
        state["findings"].append(
            Findings(
                agent=AgentType.FILE,
                input=target,
                threat_sum=analysis.threat_indicators,
                vulnerability_sum=analysis.metadata_leaks,
            )
        )
        # NEU: Wenn das LLM Identitäten (wie Autoren) extrahiert hat, füttern wir sie zurück in den State
        if hasattr(analysis, "extracted_identities") and analysis.extracted_identities:
            for identity in analysis.extracted_identities:
                if identity not in state["to_scan"]:
                    state["to_scan"].append(identity)
                    print(f"🎯 [FileAgent] Neues Identitäts-Target entdeckt und registriert: {identity}")
                    
        print(f"\n📄 [FileAgent] {clean_path}")
        print(f"⚠️ Risiko: {analysis.risk_level}")
        print(f"🧠 {analysis.reasoning}")


        return state