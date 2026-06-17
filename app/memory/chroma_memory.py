# Ergänzung / Refactoring von app/memory/chroma_memory.py
import json

import chromadb
import uuid
import datetime

client = chromadb.PersistentClient(path="./chroma_db")
collection = client.get_or_create_collection("argus_memory")
profile_collection = client.get_or_create_collection("user_profile")

def save_analysis(query: str, content: str):
    """
    Speichert den Input (query) und die Ergebnisse/Zusammenfassung (content).
    """
    # Um Duplikate bei gleichem Input zu vermeiden oder historische Versionen zu erlauben,
    # nutzen wir eine UUID als primäre ID und packen die Query in die Metadaten.
    analysis_id = str(uuid.uuid4())
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    collection.add(
        documents=[content],
        ids=[analysis_id],
        metadatas=[{
            "query": query,
            "timestamp": timestamp
        }],
    )

def get_last_analyses(limit=10):
    """
    Holt die letzten Analysen sortiert nach Auftreten.
    """
    data = collection.get()
    if not data or not data["ids"]:
        return []

    docs = []
    # Zusammenführen für einfachere UI-Iteration
    for idx in range(len(data["ids"])):
        docs.append({
            "id": data["ids"][idx],
            "query": data["metadatas"][idx].get("query", "Unbekannte Suche"),
            "timestamp": data["metadatas"][idx].get("timestamp", ""),
            "content": data["documents"][idx]
        })
    
    # Optional nach Zeitstempel sortieren oder einfach die neuesten zurückgeben
    return docs[-limit:]

def get_user_profile() -> dict:
    """
    Lädt das aktuelle, aggregierte Benutzerprofil aus ChromaDB.
    Gibt ein Standardprofil zurück, wenn noch keins existiert.
    """
    default_profile = {
        "vorname": "Unbekannt",
        "nachname": "Unbekannt",
        "email": "Unbekannt",
        "telefon": "Unbekannt",
        "kompetenz_level": "UNBEKANNT",
        "fachbegriffe": [],
        "charakteristik": "Noch keine ausreichenden Textdaten analysiert."
    }
    
    try:
        res = profile_collection.get(ids=["global_user_profile"])
        if res and res["documents"]:
            return json.loads(res["documents"][0])
    except Exception:
        pass
    return default_profile

def save_user_profile(profile_data: dict):
    """Persistiert das aktualisierte Benutzerprofil in ChromaDB."""
    profile_collection.upsert(
        ids=["global_user_profile"],
        documents=[json.dumps(profile_data, ensure_ascii=False)],
        metadatas=[{"updated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}]
    )