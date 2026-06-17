# Ergänzung / Refactoring von app/memory/chroma_memory.py
import chromadb
import uuid
import datetime

client = chromadb.PersistentClient(path="./chroma_db")
collection = client.get_or_create_collection("argus_memory")

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