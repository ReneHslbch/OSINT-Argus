"""
app/tools/result_cache.py
Caching-System für OSINT-Scan-Ergebnisse.
- Speichert Ergebnisse hash-basiert (Input-Hash → Ergebnis)
- Lädt Ergebnisse bei gleichen Inputs
- Unterstützt automatisches Löschen nach Scan
"""

import os
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any

CACHE_DIR = Path(__file__).parent.parent / "results_cache"
CACHE_DIR.mkdir(exist_ok=True)


def _compute_hash(data: str) -> str:
    """Berechnet SHA256-Hash für Input-Daten."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]


def _get_cache_path(input_hash: str) -> Path:
    """Gibt den Cache-Dateipfad für einen Hash zurück."""
    return CACHE_DIR / f"{input_hash}.json"


def cache_exists(input_data: str) -> bool:
    """Prüft, ob ein gecachtes Ergebnis für den Input existiert."""
    input_hash = _compute_hash(input_data)
    cache_path = _get_cache_path(input_hash)
    return cache_path.exists()


def load_cached_result(input_data: str) -> dict | None:
    """
    Lädt ein gecachtes Ergebnis, falls vorhanden.
    Gibt None zurück, wenn kein Cache existiert oder Fehler auftritt.
    """
    try:
        input_hash = _compute_hash(input_data)
        cache_path = _get_cache_path(input_hash)
        
        if not cache_path.exists():
            return None
        
        with open(cache_path, "r", encoding="utf-8") as f:
            cached = json.load(f)
        
        # Optional: Cache-Age-Check (älter als 7 Tage → veralten)
        cache_time = datetime.fromisoformat(cached.get("cached_at", "1970-01-01"))
        age_days = (datetime.now() - cache_time).days
        if age_days > 7:
            return None
        
        return cached.get("result")
    except Exception:
        return None


def save_result(input_data: str, result: dict, delete_after: bool = False) -> None:
    """
    Speichert ein Scan-Ergebnis im Cache.
    
    Args:
        input_data: Der Original-Input (für Hash-Berechnung)
        result: Das Scan-Ergebnis (Findings, Scores, etc.)
        delete_after: Wenn True, wird die Cache-Datei nach 1 Stunde gelöscht
    """
    try:
        input_hash = _compute_hash(input_data)
        cache_path = _get_cache_path(input_hash)
        
        cache_entry = {
            "input_hash": input_hash,
            "cached_at": datetime.now().isoformat(),
            "input_preview": input_data[:100] + "..." if len(input_data) > 100 else input_data,
            "result": result,
            "delete_after": delete_after
        }
        
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cache_entry, f, ensure_ascii=False, indent=2)
        
        print(f"💾 [Cache] Ergebnis gespeichert: {cache_path.name}")
        
        if delete_after:
            # Löschen nach 1 Stunde (60 Minuten)
            import threading
            def delayed_delete():
                import time
                time.sleep(3600)
                if cache_path.exists():
                    cache_path.unlink()
                    print(f"🗑️ [Cache] Auto-Delete: {cache_path.name}")
            
            threading.Thread(target=delayed_delete, daemon=True).start()
            
    except Exception as e:
        print(f"❌ [Cache] Fehler beim Speichern: {e}")


def clear_old_cache(max_age_hours: int = 24) -> int:
    """
    Löscht alle Cache-Einträge älter als max_age_hours.
    Gibt die Anzahl der gelöschten Dateien zurück.
    """
    deleted = 0
    now = datetime.now()
    
    for cache_file in CACHE_DIR.glob("*.json"):
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            cache_time = datetime.fromisoformat(data.get("cached_at", "1970-01-01"))
            age_hours = (now - cache_time).total_seconds() / 3600
            
            if age_hours > max_age_hours:
                cache_file.unlink()
                deleted += 1
        except Exception:
            pass
    
    if deleted > 0:
        print(f"🧹 [Cache] Gelöscht: {deleted} alte Einträge")
    
    return deleted


def list_cache_entries() -> list[dict]:
    """Listet alle Cache-Einträge mit Metadaten."""
    entries = []
    
    for cache_file in CACHE_DIR.glob("*.json"):
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            entries.append({
                "file": cache_file.name,
                "input_preview": data.get("input_preview", "-"),
                "cached_at": data.get("cached_at", "-"),
                "delete_after": data.get("delete_after", False)
            })
        except Exception:
            pass
    
    return sorted(entries, key=lambda x: x.get("cached_at", ""), reverse=True)
