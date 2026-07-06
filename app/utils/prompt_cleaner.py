"""
app/utils/prompt_cleaner.py
Zentrale Bereinigung von LLM-Antworten und User-Inputs.

Entfernt <environment_details> Blöcke und Code-Block-Markierungen,
die von manchen LLMs oder Editoren in den Text eingefügt werden.
"""

import re
from typing import Optional


def clean_llm_output(text: str) -> str:
    """
    Bereinigt LLM-Antworten von Editor-Markierungen.
    
    Entfernt:
    - <environment_details> Blöcke (Complete block including tags)
    - Markdown Code blocks (```json ... ``` or ``` ... ```)
    - Leading/trailing whitespace
    
    Args:
        text: Roh-Text aus LLM-Antwort oder User-Input
        
    Returns:
        Bereinigter Text ohne Editor-Markierungen
    """
    if not text:
        return text
    
    result = text
    
    # 1. <environment_details> Block entfernen (kann am Anfang oder Mitte sein)
    env_start = "<environment_details>"
    env_end = "</environment_details>"
    
    while env_start in result:
        start_idx = result.find(env_start)
        end_idx = result.find(env_end, start_idx)
        
        if end_idx >= 0:
            # Block komplett entfernen (inklusive Tags)
            result = result[:start_idx] + result[end_idx + len(env_end):]
        else:
            # Kein schließendes Tag - restlichen Text ab hier entfernen
            result = result[:start_idx]
    
    # 2. Code-Blöcke entfernen (```json ... ``` oder ``` ... ```)
    # Pattern: ``` followed by optional language tag, then content, then ```
    code_block_pattern = r"```(?:json|python|javascript|text)?\s*(.*?)```"
    matches = re.findall(code_block_pattern, result, re.DOTALL)
    
    if len(matches) == 1:
        # Nur ein Code-Block - das ist wahrscheinlich die eigentliche Antwort
        result = matches[0].strip()
    elif len(matches) > 1:
        # Mehrere Code-Blöcke - ersten nehmen
        result = matches[0].strip()
    else:
        # Kein Code-Block gefunden - einfach ``` entfernen
        result = result.replace("```", "")
    
    # 3. Mehrfache Leerzeichen/Zeilenbrechen normalisieren
    result = re.sub(r'\s+', ' ', result).strip()
    
    # 4. Leere Zeilen entfernen und Text normalisieren
    result = '\n'.join(line.strip() for line in result.split('\n') if line.strip())
    
    return result


def extract_json_from_llm_response(text: str) -> Optional[str]:
    """
    Extrahiert JSON-Inhalt aus LLM-Antwort.
    
    Versuche zuerst, einen Code-Block mit JSON zu finden,
    sonst den gesamten Text als JSON zurückgeben.
    
    Args:
        text: LLM-Antwort (bereits durch clean_llm_output)
        
    Returns:
        JSON-String oder None bei Fehler
    """
    text = clean_llm_output(text)
    
    # Suche nach JSON-Objekt auch ohne Code-Block
    json_start = text.find("{")
    json_end = text.rfind("}")
    
    if json_start >= 0 and json_end > json_start:
        return text[json_start:json_end + 1]
    
    return text if text.strip() else None
