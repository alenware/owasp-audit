"""Recuperación de artículos de ayuda y tickets anteriores para dar contexto al modelo."""
import chromadb

_client = chromadb.PersistentClient(path="./kb")
_collection = _client.get_or_create_collection("support_kb")


def index_document(doc_id: str, text: str, tenant_id: str, source: str) -> None:
    _collection.add(ids=[doc_id], documents=[text], metadatas=[{"tenant_id": tenant_id, "source": source}])


def search(query: str, k: int = 5) -> list[str]:
    result = _collection.query(query_texts=[query], n_results=k)
    return result["documents"][0] if result["documents"] else []
