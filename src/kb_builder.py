"""
Threat Knowledge Base Builder for RAG-IDS.
Ingests MITRE ATT&CK Enterprise STIX 2.1, MITRE CAPEC v3.9, NVD CVEs,
label cards, and feature glossary into local ChromaDB with BAAI/bge-small-en-v1.5 embeddings.
"""

import os
import sys
import json
import zipfile
import io
import time
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

import requests
import certifi
import numpy as np
import pandas as pd
import yaml
from sentence_transformers import SentenceTransformer
import chromadb

from src.config import (
    PROJECT_ROOT,
    KB_RAW_DIR,
    KB_MANUAL_DIR,
    CHROMA_DB_DIR,
    get_attack_mapping,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("kb_builder")

EMBEDDING_MODEL_NAME = "BAAI/bge-small-en-v1.5"
CHROMA_COLLECTION_NAME = "threat_knowledge_base"


def fetch_mitre_attack() -> Path:
    """Download official MITRE ATT&CK Enterprise STIX 2.1 JSON."""
    raw_path = KB_RAW_DIR / "enterprise-attack.json"
    if raw_path.exists():
        logger.info(f"Existing MITRE ATT&CK STIX found at {raw_path}")
        return raw_path

    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    logger.info(f"Downloading MITRE ATT&CK Enterprise STIX from {url}...")
    resp = requests.get(url, verify=certifi.where(), timeout=60)
    resp.raise_for_status()
    with open(raw_path, "wb") as f:
        f.write(resp.content)
    logger.info(f"Saved MITRE ATT&CK STIX ({len(resp.content):,} bytes) to {raw_path}")
    return raw_path


def fetch_mitre_capec() -> Path:
    """Download official MITRE CAPEC v3.9 CSV."""
    raw_path = KB_RAW_DIR / "capec_1000.csv"
    if raw_path.exists():
        logger.info(f"Existing CAPEC CSV found at {raw_path}")
        return raw_path

    url = "https://capec.mitre.org/data/csv/1000.csv.zip"
    logger.info(f"Downloading CAPEC 1000 CSV from {url}...")
    resp = requests.get(url, verify=certifi.where(), timeout=60)
    resp.raise_for_status()
    z = zipfile.ZipFile(io.BytesIO(resp.content))
    csv_filename = [f for f in z.namelist() if f.endswith(".csv")][0]
    with open(raw_path, "wb") as f:
        f.write(z.open(csv_filename).read())
    logger.info(f"Saved CAPEC CSV to {raw_path}")
    return raw_path


def fetch_nvd_cves() -> Path:
    """Fetch targeted CVEs for protocols in the dataset via NVD API."""
    raw_path = KB_RAW_DIR / "nvd_cves.json"
    if raw_path.exists():
        logger.info(f"Existing NVD CVE cache found at {raw_path}")
        return raw_path

    logger.info("Fetching targeted CVE records from NVD REST API...")
    keywords = ["Slowloris", "MQTT broker", "OpenSSH brute force", "IoT firmware"]
    all_cves = []

    for kw in keywords:
        try:
            logger.info(f"Querying NVD API for keyword: '{kw}'...")
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={kw}&resultsPerPage=15"
            resp = requests.get(url, verify=certifi.where(), timeout=20)
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("vulnerabilities", [])
                for item in items:
                    cve = item.get("cve", {})
                    all_cves.append(cve)
            else:
                logger.warning(f"NVD API returned status {resp.status_code} for keyword {kw}")
            time.sleep(1.0)  # Gentle rate pacing
        except Exception as e:
            logger.warning(f"Failed to fetch CVEs for keyword {kw}: {e}")

    # Fallback default CVEs if NVD rate limited or network failed
    if not all_cves:
        logger.info("Using embedded benchmark CVE records as fallback...")
        all_cves = [
            {
                "id": "CVE-2007-6750",
                "descriptions": [
                    {
                        "value": "The Apache HTTP Server 1.x and 2.x allows remote attackers to cause a denial of service (daemon outage) via partial HTTP requests, as demonstrated by Slowloris."
                    }
                ],
                "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2007-6750"}],
            },
            {
                "id": "CVE-2018-12615",
                "descriptions": [
                    {
                        "value": "An issue was discovered in Eclipse Mosquitto before 1.4.15. If a client sends a SUBSCRIBE packet containing an invalid topic, the broker crashes."
                    }
                ],
                "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2018-12615"}],
            },
            {
                "id": "CVE-2006-5051",
                "descriptions": [
                    {
                        "value": "Signal handler race condition in OpenSSH allows remote attackers to cause a denial of service and possibly execute arbitrary code."
                    }
                ],
                "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2006-5051"}],
            },
        ]

    with open(raw_path, "w", encoding="utf-8") as f:
        json.dump(all_cves, f, indent=2)
    logger.info(f"Saved {len(all_cves)} CVE records to {raw_path}")
    return raw_path


def parse_mitre_attack_stix(stix_path: Path) -> List[Dict[str, Any]]:
    """Parse ATT&CK techniques, sub-techniques, and mitigations into chunks."""
    logger.info("Parsing MITRE ATT&CK STIX objects...")
    with open(stix_path, "r", encoding="utf-8") as f:
        stix_data = json.load(f)

    chunks = []
    objects = stix_data.get("objects", [])

    for obj in objects:
        obj_type = obj.get("type")
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        if obj_type in ["attack-pattern", "course-of-action"]:
            ext_refs = obj.get("external_references", [])
            mitre_id = None
            mitre_url = None
            for ref in ext_refs:
                if ref.get("source_name") in ["mitre-attack", "mitre-enterprise"]:
                    mitre_id = ref.get("external_id")
                    mitre_url = ref.get("url")
                    break

            if not mitre_id:
                continue

            name = obj.get("name", "Unknown Technique")
            desc = obj.get("description", "")
            if not desc:
                continue

            # Word count limit (~350 words per chunk)
            words = desc.split()
            desc_clean = " ".join(words[:320])

            chunk_text = (
                f"### [MITRE ATT&CK {mitre_id}]: {name}\n"
                f"**Type**: {obj_type}\n"
                f"**URL**: {mitre_url or 'https://attack.mitre.org/'}\n\n"
                f"{desc_clean}"
            )

            chunks.append(
                {
                    "id": mitre_id,
                    "name": name,
                    "source": "mitre_attack",
                    "type": obj_type,
                    "url": mitre_url or "",
                    "text": chunk_text,
                }
            )

    logger.info(f"Generated {len(chunks)} MITRE ATT&CK knowledge chunks.")
    return chunks


def parse_capec_csv(capec_path: Path) -> List[Dict[str, Any]]:
    """Parse CAPEC attack pattern CSV into chunks."""
    logger.info("Parsing MITRE CAPEC CSV records...")
    df = pd.read_csv(capec_path)

    chunks = []
    for idx, row in df.iterrows():
        try:
            capec_num = int(idx)
        except (ValueError, TypeError):
            continue

        cid = f"CAPEC-{capec_num}"
        # In capec_1000.csv, columns are shifted by one:
        # Index is the numeric ID, column "'ID" is the pattern Name,
        # column "Status" holds the Description, and "Consequences" holds Mitigations
        name = str(row.get("'ID", "Attack Pattern"))
        desc = str(row.get("Status", ""))
        mitigations = str(row.get("Consequences", ""))

        if desc == "nan" or not desc or len(desc.strip()) < 10:
            # Fallback check if description is in another column
            desc = str(row.get("Description", ""))
            if desc == "nan" or not desc:
                continue

        words = desc.split()
        desc_clean = " ".join(words[:280])

        content = f"### [CAPEC: {cid}]: {name}\n**Source**: MITRE CAPEC v3.9\n\n{desc_clean}"
        if mitigations and mitigations != "nan" and len(mitigations) > 10:
            clean_mit = mitigations.replace("::", " ").strip()
            content += f"\n\n**Mitigations**: {clean_mit[:300]}"

        chunks.append(
            {
                "id": cid,
                "name": name,
                "source": "capec",
                "type": "attack_pattern",
                "url": f"https://capec.mitre.org/data/definitions/{capec_num}.html",
                "text": content,
            }
        )

    logger.info(f"Generated {len(chunks)} CAPEC knowledge chunks.")
    return chunks


def parse_nvd_cves(nvd_path: Path) -> List[Dict[str, Any]]:
    """Parse cached NVD CVE JSON records into chunks."""
    logger.info("Parsing NVD CVE records...")
    with open(nvd_path, "r", encoding="utf-8") as f:
        cves = json.load(f)

    chunks = []
    seen = set()
    for cve in cves:
        cid = cve.get("id")
        if not cid or cid in seen:
            continue
        seen.add(cid)

        descs = cve.get("descriptions", [])
        desc_text = descs[0].get("value", "") if descs else ""
        refs = cve.get("references", [])
        url = refs[0].get("url", f"https://nvd.nist.gov/vuln/detail/{cid}") if refs else ""

        content = (
            f"### [CVE Vulnerability {cid}]\n"
            f"**Source**: NVD (National Vulnerability Database)\n"
            f"**URL**: {url}\n\n"
            f"{desc_text}"
        )

        chunks.append(
            {
                "id": cid,
                "name": f"Vulnerability {cid}",
                "source": "nvd_cve",
                "type": "vulnerability",
                "url": url,
                "text": content,
            }
        )

    logger.info(f"Generated {len(chunks)} NVD CVE knowledge chunks.")
    return chunks


def parse_manual_cards() -> List[Dict[str, Any]]:
    """Parse label cards and feature glossary into chunks."""
    chunks = []

    # 1. Label Cards
    cards_path = KB_MANUAL_DIR / "label_cards.yaml"
    if cards_path.exists():
        with open(cards_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f).get("labels", {})
        for lbl_key, card in data.items():
            cid = f"CARD_{lbl_key}"
            text = (
                f"### [Label Reference: {lbl_key} - {card['name']}]\n"
                f"**Attack Family**: {card['family']}\n"
                f"**Tool / Origin**: {card['tool']}\n\n"
                f"**Description**: {card['description']}\n\n"
                f"**Network Mechanics**: {card['mechanics']}"
            )
            chunks.append(
                {
                    "id": cid,
                    "name": card["name"],
                    "source": "label_card",
                    "type": "dataset_card",
                    "url": "local_label_card",
                    "text": text,
                }
            )

    # 2. Feature Glossary
    glossary_path = KB_MANUAL_DIR / "feature_glossary.yaml"
    if glossary_path.exists():
        with open(glossary_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f).get("features", {})
        for feat_key, feat in data.items():
            cid = f"GLOSSARY_{feat_key}"
            text = (
                f"### [Zeek Feature Glossary: {feat_key} ({feat['name']})]\n"
                f"**Description**: {feat['description']}\n\n"
                f"**Security Interpretation**: {feat['interpretation']}"
            )
            chunks.append(
                {
                    "id": cid,
                    "name": feat["name"],
                    "source": "feature_glossary",
                    "type": "feature_definition",
                    "url": "local_feature_glossary",
                    "text": text,
                }
            )

    logger.info(f"Generated {len(chunks)} manual label card and glossary chunks.")
    return chunks


def build_knowledge_base():
    """Execute complete threat knowledge base acquisition, parsing, and vector indexing."""
    print("\n" + "=" * 75)
    print("BUILDING THREAT KNOWLEDGE BASE & CHROMADB VECTOR INDEX")
    print("=" * 75)

    # 1. Download / verify raw threat intelligence
    stix_file = fetch_mitre_attack()
    capec_file = fetch_mitre_capec()
    nvd_file = fetch_nvd_cves()

    # 2. Parse all sources into standardized chunks
    attack_chunks = parse_mitre_attack_stix(stix_file)
    capec_chunks = parse_capec_csv(capec_file)
    nvd_chunks = parse_nvd_cves(nvd_file)
    manual_chunks = parse_manual_cards()

    all_chunks = attack_chunks + capec_chunks + nvd_chunks + manual_chunks
    logger.info(f"Total knowledge chunks assembled: {len(all_chunks):,}")

    # 3. Initialize sentence-transformers model
    logger.info(f"Loading embedding model: {EMBEDDING_MODEL_NAME} on CPU...")
    embedder = SentenceTransformer(EMBEDDING_MODEL_NAME, device="cpu")

    # 4. Initialize ChromaDB
    logger.info(f"Initializing local persistent ChromaDB at {CHROMA_DB_DIR}...")
    client = chromadb.PersistentClient(path=str(CHROMA_DB_DIR))

    # Reset collection if exists for clean indexing
    try:
        client.delete_collection(name=CHROMA_COLLECTION_NAME)
    except Exception:
        pass

    collection = client.create_collection(
        name=CHROMA_COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )

    # 5. Batch embedding and indexing
    logger.info("Generating embeddings and indexing chunks into ChromaDB...")
    batch_size = 256
    total = len(all_chunks)

    for i in range(0, total, batch_size):
        batch = all_chunks[i : i + batch_size]
        docs = [b["text"] for b in batch]
        ids = [b["id"] for b in batch]
        metadatas = [
            {
                "id": b["id"],
                "name": b["name"],
                "source": b["source"],
                "type": b["type"],
                "url": b.get("url", ""),
            }
            for b in batch
        ]

        # bge-small requires query prefix for retrieval, but passages are embedded directly
        embeddings = embedder.encode(docs, show_progress_bar=False, normalize_embeddings=True)
        collection.add(
            documents=docs,
            embeddings=embeddings.tolist(),
            metadatas=metadatas,
            ids=ids,
        )
        logger.info(f"Indexed chunks {i + len(batch)} / {total}...")

    # Also save an in-memory JSON catalog of chunks for O(1) ID lookup
    catalog_path = KB_RAW_DIR / "chunk_catalog.json"
    catalog_dict = {b["id"]: b for b in all_chunks}
    with open(catalog_path, "w", encoding="utf-8") as f:
        json.dump(catalog_dict, f, indent=2)
    logger.info(f"Saved chunk lookup catalog to {catalog_path}")

    print("\n" + "=" * 75)
    print("THREAT KNOWLEDGE BASE INGESTION COMPLETE")
    print(f"Total Chunks Indexed: {total:,}")
    print(f"ChromaDB Location:    {CHROMA_DB_DIR}")
    print(f"Embedding Model:      {EMBEDDING_MODEL_NAME}")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    build_knowledge_base()
