########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                         #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2026  #
# version 5.0 24-06-2026                               #
########################################################
"""
RAG (Retrieval-Augmented Generation) Vector Index for APISCAN.

Builds a local ChromaDB vector store from:
- Markdown/HTML scan reports
- OWASP API Security reference docs
- Raw scan findings (JSON)
- Any text/markdown files you feed it

Usage:
    python rag_index.py --build                          # Build index from default sources
    python rag_index.py --build --dir ./my_docs          # Build from custom directory
    python rag_index.py --query "SQL injection in GET"   # Query the index
    python rag_index.py --add scan_report.md             # Add a single file
    python rag_index.py --stats                          # Show index statistics

Env vars:
    RAG_INDEX_PATH         = path to ChromaDB persistence dir (default: ./rag_data/)
    RAG_EMBEDDING_MODEL    = sentence-transformers model (default: all-MiniLM-L6-v2)
    RAG_CHUNK_SIZE         = max chars per chunk (default: 1000)
    RAG_CHUNK_OVERLAP      = overlap between chunks (default: 150)
    RAG_TOP_K              = results to return (default: 5)
"""

from __future__ import annotations

import os
import sys
import json
import argparse
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime


# ── Optional dependency check ──────────────────────────────────────────
_CHROMADB_OK = False
_SENTENCE_TRANSFORMERS_OK = False

try:
    import chromadb
    from chromadb.config import Settings as ChromaSettings
    _CHROMADB_OK = True
except ImportError:
    pass

try:
    from sentence_transformers import SentenceTransformer
    _SENTENCE_TRANSFORMERS_OK = True
except ImportError:
    pass


def _check_deps():
    """Print missing dependencies and exit if required ones are absent."""
    missing = []
    if not _CHROMADB_OK:
        missing.append("chromadb  (pip install chromadb)")
    if not _SENTENCE_TRANSFORMERS_OK:
        missing.append("sentence-transformers  (pip install sentence-transformers)")
    if missing:
        print("Missing dependencies:")
        for m in missing:
            print(f"  - {m}")
        print()
        print("Install with:  pip install chromadb sentence-transformers")
        sys.exit(1)


# ── Configuration ──────────────────────────────────────────────────────

class RAGConfig:
    def __init__(self):
        self.index_path: str = os.getenv("RAG_INDEX_PATH", str(
            Path(__file__).resolve().parent / "rag_data"
        ))
        self.embedding_model: str = os.getenv(
            "RAG_EMBEDDING_MODEL", "all-MiniLM-L6-v2"
        )
        self.chunk_size: int = int(os.getenv("RAG_CHUNK_SIZE", "1000"))
        self.chunk_overlap: int = int(os.getenv("RAG_CHUNK_OVERLAP", "150"))
        self.top_k: int = int(os.getenv("RAG_TOP_K", "5"))


# ── Chunking ───────────────────────────────────────────────────────────

def _chunk_text(text: str, chunk_size: int = 1000, overlap: int = 150) -> List[Dict[str, Any]]:
    """Split text into overlapping chunks with metadata."""
    text = text.strip()
    if not text:
        return []

    # Try to split on paragraph boundaries first
    paragraphs = re.split(r'\n\s*\n', text)
    chunks = []
    current = ""
    para_index = 0

    for para in paragraphs:
        para = para.strip()
        if not para:
            continue
        if len(current) + len(para) + 2 <= chunk_size:
            current = (current + "\n\n" + para).strip() if current else para
        else:
            if current:
                chunks.append({
                    "text": current[:chunk_size + overlap],
                    "meta": {"chunk_index": len(chunks), "para_start": para_index}
                })
            # Start new chunk, carry over overlap from previous
            overlap_text = current[-overlap:] if current and len(current) > overlap else ""
            current = (overlap_text + "\n\n" + para).strip() if overlap_text else para
        para_index += 1

    if current:
        chunks.append({
            "text": current[:chunk_size + overlap],
            "meta": {"chunk_index": len(chunks), "para_start": para_index}
        })

    return chunks


def _extract_metadata_from_path(file_path: Path) -> Dict[str, str]:
    """Extract useful metadata from file path."""
    meta = {
        "source": str(file_path),
        "filename": file_path.name,
        "suffix": file_path.suffix.lower(),
        "parent": file_path.parent.name,
    }
    # Try to detect scan reports by path pattern
    path_str = str(file_path).lower()
    if "audit_" in path_str:
        meta["type"] = "scan_report"
    elif "readme" in path_str or "index" in path_str:
        meta["type"] = "documentation"
    elif file_path.suffix in (".json", ".ndjson"):
        meta["type"] = "data"
    elif file_path.suffix in (".py",):
        meta["type"] = "code"
    else:
        meta["type"] = "general"
    return meta


# ── Document Loaders ───────────────────────────────────────────────────

def _load_text_file(file_path: Path) -> str:
    """Load any text-based file."""
    encodings = ["utf-8", "latin-1", "cp1252"]
    for enc in encodings:
        try:
            return file_path.read_text(encoding=enc)
        except (UnicodeDecodeError, UnicodeError):
            continue
    # Last resort: read as binary
    return file_path.read_bytes().decode("utf-8", errors="replace")


def _load_html_report(file_path: Path) -> str:
    """Extract readable text from an HTML scan report."""
    content = _load_text_file(file_path)
    # Strip HTML tags, keep text
    text = re.sub(r'<style[^>]*>.*?</style>', '', content, flags=re.DOTALL | re.I)
    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL | re.I)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def _load_json_findings(file_path: Path) -> str:
    """Convert raw findings JSON to readable text chunks."""
    data = json.loads(_load_text_file(file_path))
    if not isinstance(data, list):
        data = [data]

    texts = []
    for item in data:
        parts = []
        if item.get("issue"):
            parts.append(f"Issue: {item['issue']}")
        if item.get("description"):
            parts.append(f"Description: {item['description']}")
        if item.get("severity"):
            parts.append(f"Severity: {item['severity']}")
        if item.get("endpoint") or item.get("url"):
            parts.append(f"Endpoint: {item.get('endpoint') or item.get('url')}")
        if item.get("method"):
            parts.append(f"Method: {item['method']}")
        if item.get("status_code"):
            parts.append(f"Status: {item['status_code']}")
        if item.get("recommendation"):
            parts.append(f"Recommendation: {item['recommendation']}")
        if item.get("response_body"):
            body = item["response_body"]
            if len(body) > 500:
                body = body[:500] + "..."
            parts.append(f"Response: {body}")
        if parts:
            texts.append(" | ".join(parts))

    return "\n\n".join(texts)


def _load_ndjson_log(file_path: Path) -> str:
    """Load NDJSON scan log."""
    lines = []
    for line in _load_text_file(file_path).splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            lines.append(json.dumps(obj))
        except json.JSONDecodeError:
            lines.append(line)
    return "\n".join(lines)


LOADERS = {
    ".html": _load_html_report,
    ".htm": _load_html_report,
    ".json": _load_json_findings,
    ".ndjson": _load_ndjson_log,
}


def load_document(file_path: Path) -> Tuple[str, Dict[str, str]]:
    """Load a document with the appropriate loader, return (text, metadata)."""
    meta = _extract_metadata_from_path(file_path)
    suffix = file_path.suffix.lower()

    loader = LOADERS.get(suffix)
    if loader:
        try:
            text = loader(file_path)
            return text, meta
        except Exception:
            pass  # Fall through to plain text load

    # Plain text for .md, .txt, .py, etc.
    text = _load_text_file(file_path)
    return text, meta


def load_directory(directory: Path, recursive: bool = True) -> List[Tuple[str, Dict[str, str]]]:
    """Load all supported documents from a directory."""
    supported = {".html", ".htm", ".json", ".ndjson", ".md", ".txt", ".py", ".rst", ".yml", ".yaml"}
    documents = []

    pattern = "**/*" if recursive else "*"
    for file_path in sorted(directory.glob(pattern)):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() not in supported:
            continue
        # Skip very large files (>10MB)
        if file_path.stat().st_size > 10_000_000:
            print(f"  [skip] Too large: {file_path.name}")
            continue
        try:
            text, meta = load_document(file_path)
            if text.strip():
                documents.append((text, meta))
        except Exception as e:
            print(f"  [warn] {file_path.name}: {e}")

    return documents


# ── Vector Index ───────────────────────────────────────────────────────

class RAGIndex:
    """ChromaDB-backed vector index for API security documents."""

    def __init__(self, config: Optional[RAGConfig] = None):
        _check_deps()
        self.config = config or RAGConfig()
        self.embedding_model: Optional[SentenceTransformer] = None
        self._client: Optional[chromadb.PersistentClient] = None
        self._collection: Optional[Any] = None

    @property
    def client(self) -> chromadb.PersistentClient:
        if self._client is None:
            os.makedirs(self.config.index_path, exist_ok=True)
            self._client = chromadb.PersistentClient(
                path=self.config.index_path,
                settings=ChromaSettings(anonymized_telemetry=False),
            )
        return self._client

    @property
    def collection(self):
        if self._collection is None:
            self._collection = self.client.get_or_create_collection(
                name="apiscan_rag",
                metadata={"description": "APISCAN RAG index — API security findings & docs"}
            )
        return self._collection

    def _get_embedding_fn(self):
        if self.embedding_model is None:
            print(f"  Loading embedding model: {self.config.embedding_model} ...")
            self.embedding_model = SentenceTransformer(self.config.embedding_model)
        return self.embedding_model

    # ── Build ────────────────────────────────────────────────────

    def build(self, sources: List[Path], recursive: bool = True):
        """Build / rebuild the entire vector index from source directories/files."""
        documents = []
        for src in sources:
            if src.is_dir():
                print(f"  Scanning directory: {src}")
                docs = load_directory(src, recursive=recursive)
                documents.extend(docs)
                print(f"    Loaded {len(docs)} documents")
            elif src.is_file():
                print(f"  Loading file: {src.name}")
                text, meta = load_document(src)
                if text.strip():
                    documents.append((text, meta))

        if not documents:
            print("  No documents found.")
            return 0

        # Chunk all documents
        all_chunks = []
        for text, meta in documents:
            chunks = _chunk_text(text, self.config.chunk_size, self.config.chunk_overlap)
            for chunk in chunks:
                chunk["meta"].update(meta)
                chunk["meta"]["timestamp"] = datetime.now().isoformat()
            all_chunks.extend(chunks)

        print(f"  Total chunks: {len(all_chunks)}")

        # Clear existing collection
        try:
            self.client.delete_collection("apiscan_rag")
        except Exception:
            pass
        self._collection = None  # Force re-create

        # Embed and store in batches
        model = self._get_embedding_fn()
        batch_size = 32

        for i in range(0, len(all_chunks), batch_size):
            batch = all_chunks[i:i + batch_size]
            texts = [c["text"] for c in batch]
            ids = [f"chunk_{j}" for j in range(i, i + len(batch))]
            metadatas = [c["meta"] for c in batch]

            embeddings = model.encode(texts, show_progress_bar=False).tolist()

            self.collection.add(
                ids=ids,
                embeddings=embeddings,
                documents=texts,
                metadatas=metadatas,
            )

            pct = min(100, int((i + batch_size) / len(all_chunks) * 100))
            print(f"\r  Indexing: {pct}%", end="", flush=True)

        print(f"\n  Done. {len(all_chunks)} chunks indexed in {self.config.index_path}")

        # Persist
        return len(all_chunks)

    # ── Add ──────────────────────────────────────────────────────

    def add_document(self, file_path: Path):
        """Add a single document to the index."""
        if not file_path.is_file():
            print(f"  File not found: {file_path}")
            return 0

        text, meta = load_document(file_path)
        if not text.strip():
            print("  Empty document, skipped.")
            return 0

        chunks = _chunk_text(text, self.config.chunk_size, self.config.chunk_overlap)
        for chunk in chunks:
            chunk["meta"].update(meta)
            chunk["meta"]["timestamp"] = datetime.now().isoformat()

        model = self._get_embedding_fn()
        existing_count = self.collection.count()

        for i, chunk in enumerate(chunks):
            cid = f"chunk_{existing_count + i}"
            embedding = model.encode([chunk["text"]], show_progress_bar=False).tolist()
            self.collection.add(
                ids=[cid],
                embeddings=embedding,
                documents=[chunk["text"]],
                metadatas=[chunk["meta"]],
            )

        print(f"  Added {len(chunks)} chunks from {file_path.name}")
        return len(chunks)

    # ── Query ────────────────────────────────────────────────────

    def query(self, query_text: str, top_k: Optional[int] = None) -> List[Dict[str, Any]]:
        """Search the index and return top-k results."""
        k = top_k or self.config.top_k
        model = self._get_embedding_fn()
        query_embedding = model.encode([query_text], show_progress_bar=False).tolist()

        results = self.collection.query(
            query_embeddings=query_embedding,
            n_results=k,
            include=["documents", "metadatas", "distances"],
        )

        output = []
        if results and results["ids"] and results["ids"][0]:
            for i in range(len(results["ids"][0])):
                output.append({
                    "id": results["ids"][0][i],
                    "document": results["documents"][0][i] if results["documents"] else "",
                    "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                    "distance": results["distances"][0][i] if results["distances"] else 0.0,
                })
        return output

    def query_as_context(self, query_text: str, top_k: Optional[int] = None) -> str:
        """Query and return results formatted as context for an LLM prompt."""
        results = self.query(query_text, top_k)
        if not results:
            return "No relevant documents found in the RAG index."

        lines = ["[Relevant context from APISCAN RAG index:]"]
        for i, r in enumerate(results, 1):
            source = r["metadata"].get("source", "unknown")
            doc_type = r["metadata"].get("type", "general")
            lines.append(f"\n--- Result {i} (type={doc_type}, source={Path(source).name}) ---")
            lines.append(r["document"][:2000])  # Cap per chunk for prompt size
        return "\n".join(lines)

    # ── Stats ────────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        """Return index statistics."""
        count = self.collection.count()
        peek = self.collection.peek(limit=1) if count > 0 else None

        types = {}
        if count > 0 and count <= 10000:
            # Count by type (only for reasonably sized collections)
            all_meta = self.collection.get(include=["metadatas"])
            if all_meta and all_meta["metadatas"]:
                for m in all_meta["metadatas"]:
                    t = m.get("type", "unknown")
                    types[t] = types.get(t, 0) + 1

        return {
            "total_chunks": count,
            "index_path": self.config.index_path,
            "embedding_model": self.config.embedding_model,
            "chunk_size": self.config.chunk_size,
            "by_type": types,
            "sample_metadata": peek["metadatas"][0] if peek and peek.get("metadatas") else None,
        }


# ── CLI ────────────────────────────────────────────────────────────────

def _cli():
    p = argparse.ArgumentParser(
        description="APISCAN RAG Vector Index — build, query, and manage API security knowledge"
    )
    p.add_argument("--build", action="store_true", help="Build/rebuild full index")
    p.add_argument("--dir", type=str, nargs="*", default=None,
                   help="Directories to index (default: current dir + past scans)")
    p.add_argument("--add", type=str, nargs="*", default=None,
                   help="Add specific files to the index")
    p.add_argument("--query", "-q", type=str, default=None,
                   help="Query the index")
    p.add_argument("--top-k", type=int, default=None,
                   help="Number of results (default from RAG_TOP_K)")
    p.add_argument("--context", action="store_true",
                   help="Format query results as LLM-ready context")
    p.add_argument("--stats", action="store_true", help="Show index statistics")
    p.add_argument("--reset", action="store_true", help="Delete and rebuild from scratch")

    args = p.parse_args()

    if not any([args.build, args.add, args.query, args.stats, args.reset]):
        p.print_help()
        return

    config = RAGConfig()
    rag = RAGIndex(config)

    if args.reset:
        print("Resetting index...")
        try:
            rag.client.delete_collection("apiscan_rag")
        except Exception:
            pass
        rag._collection = None
        print("Index cleared.")

    if args.build:
        # Default: scan reports + project docs
        if args.dir:
            sources = [Path(d).resolve() for d in args.dir]
        else:
            sources = [Path(__file__).resolve().parent]  # Project root
            # Also scan recent audit dirs
            audit_base = Path(__file__).resolve().parent
            for d in sorted(audit_base.glob("audit_*"), reverse=True)[:5]:
                sources.append(d)

        print(f"Building index from {len(sources)} source(s)...")
        rag.build(sources)
        print()

    if args.add:
        for f in args.add:
            rag.add_document(Path(f).resolve())
        print()

    if args.query:
        results = rag.query(args.query, args.top_k)
        if args.context:
            print(rag.query_as_context(args.query, args.top_k))
        else:
            for i, r in enumerate(results, 1):
                source = Path(r["metadata"].get("source", "?")).name
                doc_type = r["metadata"].get("type", "?")
                dist = r["distance"]
                print(f"\n{'='*60}")
                print(f"[{i}] {doc_type} | {source} | distance={dist:.4f}")
                print(f"{'='*60}")
                print(r["document"][:800])

    if args.stats:
        s = rag.stats()
        print(f"\nRAG Index Stats")
        print(f"  Path:       {s['index_path']}")
        print(f"  Model:      {s['embedding_model']}")
        print(f"  Chunks:     {s['total_chunks']}")
        print(f"  Chunk size: {s['chunk_size']}")
        if s["by_type"]:
            print(f"  By type:")
            for t, c in sorted(s["by_type"].items()):
                print(f"    {t}: {c}")


if __name__ == "__main__":
    _cli()
