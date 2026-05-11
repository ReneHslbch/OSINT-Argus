import chromadb


client = chromadb.PersistentClient(path="./chroma_db")
collection = client.get_or_create_collection("argus_memory")



def save_analysis(query: str, content: str):
    collection.add(
        documents=[content],
        ids=[query],
        metadatas=[{"query": query}],
    )



def search_memory(query: str):
    results = collection.query(
        query_texts=[query],
        n_results=3,
    )

    return results