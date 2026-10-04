"""
Hybrid Retrieval Engine for RAG-IDS.
Combines deterministic YAML mapping lookup with neural semantic search over ChromaDB.
Formats grounded evidence blocks capped at 6 chunks and ~1,000 words.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

os.environ["TOKENIZERS_PARALLELISM"] = "false"

import chromadb
from sentence_transformers import SentenceTransformer

from src.config import (
    PROJECT_ROOT,
    KB_RAW_DIR,
    CHROMA_DB_DIR,
    get_attack_mapping,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("retriever")

EMBEDDING_MODEL_NAME = "BAAI/bge-small-en-v1.5"
CHROMA_COLLECTION_NAME = "threat_knowledge_base"

# Global retriever cache
_GLOBAL_CHROMA_COLLECTION = None
_GLOBAL_EMBEDDER = None
_GLOBAL_CHUNK_CATALOG = None
_GLOBAL_ATTACK_MAPPING = None


def init_retriever():
    """Initialize and cache ChromaDB client, embedder, and catalog."""
    global _GLOBAL_CHROMA_COLLECTION, _GLOBAL_EMBEDDER, _GLOBAL_CHUNK_CATALOG, _GLOBAL_ATTACK_MAPPING

    if _GLOBAL_CHROMA_COLLECTION is None:
        client = chromadb.PersistentClient(path=str(CHROMA_DB_DIR))
        _GLOBAL_CHROMA_COLLECTION = client.get_collection(name=CHROMA_COLLECTION_NAME)

        _GLOBAL_EMBEDDER = SentenceTransformer(EMBEDDING_MODEL_NAME, device="cpu")

        catalog_path = KB_RAW_DIR / "chunk_catalog.json"
        if catalog_path.exists():
            with open(catalog_path, "r", encoding="utf-8") as f:
                _GLOBAL_CHUNK_CATALOG = json.load(f)
        else:
            _GLOBAL_CHUNK_CATALOG = {}

        _GLOBAL_ATTACK_MAPPING = get_attack_mapping().get("attacks", {})

    return _GLOBAL_CHROMA_COLLECTION, _GLOBAL_EMBEDDER, _GLOBAL_CHUNK_CATALOG, _GLOBAL_ATTACK_MAPPING


def retrieve_threat_evidence(
    query: str,
    detection_result: Optional[Dict[str, Any]] = None,
    max_chunks: int = 6,
    max_words: int = 1000,
) -> Dict[str, Any]:
    """
    Two-step hybrid retrieval:
    1. Deterministic ID lookup for predicted label (CAPEC, ATT&CK, label card).
    2. Semantic vector search for query + context over ChromaDB.
    Returns merged, deduplicated evidence chunks capped at max_chunks and max_words.
    """
    collection, embedder, catalog, attack_mapping = init_retriever()

    retrieved_chunks = []
    seen_ids = set()

    predicted_label = detection_result.get("predicted_label") if detection_result else None

    # --- Step 1: Deterministic ID Lookup ---
    if predicted_label:
        # Check label card
        card_id = f"CARD_{predicted_label}"
        if card_id in catalog and card_id not in seen_ids:
            retrieved_chunks.append(catalog[card_id])
            seen_ids.add(card_id)

        # Check attack mapping
        if predicted_label in attack_mapping:
            mapping_info = attack_mapping[predicted_label]

            # Fetch mapped CAPEC IDs
            for capec_entry in mapping_info.get("capec", []):
                cid = capec_entry.get("id")
                if cid and cid in catalog and cid not in seen_ids:
                    retrieved_chunks.append(catalog[cid])
                    seen_ids.add(cid)

            # Fetch mapped ATT&CK IDs
            for attack_entry in mapping_info.get("attack", []):
                tid = attack_entry.get("id")
                if tid and tid in catalog and tid not in seen_ids:
                    retrieved_chunks.append(catalog[tid])
                    seen_ids.add(tid)

        # Check top-contributing features for glossary entries
        if detection_result and "top_features" in detection_result:
            for feat in detection_result["top_features"]:
                raw_feat_name = feat.get("feature", "")
                base_feat = raw_feat_name.replace("cat__", "").replace("num__", "")
                glossary_id = f"GLOSSARY_{base_feat}"
                if glossary_id in catalog and glossary_id not in seen_ids:
                    retrieved_chunks.append(catalog[glossary_id])
                    seen_ids.add(glossary_id)
                    if len(retrieved_chunks) >= 4:
                        break

    # --- Step 2: Semantic Vector Search ---
    context_hint = f" [Context: {predicted_label}]" if predicted_label else ""
    formatted_query = f"Represent this sentence for searching relevant passages: {query}{context_hint}"

    query_embedding = embedder.encode(
        [formatted_query], normalize_embeddings=True, show_progress_bar=False
    ).tolist()

    search_limit = max_chunks * 2
    results = collection.query(
        query_embeddings=query_embedding,
        n_results=search_limit,
    )

    if results and "ids" in results and results["ids"]:
        result_ids = results["ids"][0]
        for rid in result_ids:
            if rid not in seen_ids and rid in catalog:
                retrieved_chunks.append(catalog[rid])
                seen_ids.add(rid)
            if len(retrieved_chunks) >= max_chunks:
                break

    # --- Step 3: Enforce Word & Chunk Caps ---
    final_chunks = []
    total_words = 0

    for chunk in retrieved_chunks:
        chunk_words = len(chunk["text"].split())
        if len(final_chunks) < max_chunks and (total_words + chunk_words) <= max_words:
            final_chunks.append(chunk)
            total_words += chunk_words
        elif not final_chunks:
            final_chunks.append(chunk)
            break

    # --- Step 4: Build Formatted Evidence Block ---
    evidence_blocks = []

    # Inject Detector Telemetry [DET]
    if detection_result:
        det_text = (
            f"### [DET: Detector Telemetry]\n"
            f"- **Predicted Label**: {detection_result.get('predicted_label')}\n"
            f"- **Classification**: {'Attack' if detection_result.get('is_attack') else 'Normal'}\n"
            f"- **Attack Family**: {detection_result.get('attack_family')}\n"
            f"- **Confidence**: {detection_result.get('confidence'):.2%}\n"
            f"- **Top Contributing Features (TreeSHAP)**:\n"
        )
        for tf in detection_result.get("top_features", []):
            det_text += f"  - `{tf['feature']}` = {tf['value']} (Contribution: {tf['contribution']:+.4f})\n"
        evidence_blocks.append(det_text)

    # Append Retrieved Chunks
    for chunk in final_chunks:
        evidence_blocks.append(chunk["text"])

    formatted_evidence = "\n\n" + ("=" * 40) + "\nEVIDENCE BLOCK\n" + ("=" * 40) + "\n\n"
    formatted_evidence += "\n\n".join(evidence_blocks)

    return {
        "chunks": final_chunks,
        "chunk_count": len(final_chunks),
        "total_words": total_words,
        "formatted_evidence": formatted_evidence,
    }


if __name__ == "__main__":
    from src.detector import detect
    import pandas as pd

    test_df = pd.read_parquet(PROJECT_ROOT / "data/processed/test.parquet")
    sample = test_df[test_df["Attack_type"] == "DDOS_Slowloris"].iloc[0]
    det_res = detect(sample)

    q = "What is this attack and how should I mitigate it?"
    res = retrieve_threat_evidence(q, det_res)

    print(f"Retrieved {res['chunk_count']} chunks ({res['total_words']} words).")
    print(res["formatted_evidence"][:500])
