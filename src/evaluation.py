"""
Evaluation engine for RAG-IDS.
Implements claim decomposition, automated judge scoring via Gemini/Groq,
and regex security identifier verification against official threat catalogs.
"""

import re
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Tuple, Set

from src.config import PROJECT_ROOT, KB_RAW_DIR, get_attack_mapping
from src.llm_client import query_llm
from src.prompts import JUDGE_SYSTEM_PROMPT

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("evaluation")

# Regex patterns for official cybersecurity identifiers
REGEX_ATTACK = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
REGEX_CAPEC = re.compile(r"\bCAPEC-\d+\b", re.IGNORECASE)
REGEX_CVE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
REGEX_MITIGATION = re.compile(r"\bM\d{4}\b", re.IGNORECASE)


class ThreatCatalog:
    """Master catalog cache of all official security identifiers."""

    def __init__(self):
        catalog_path = KB_RAW_DIR / "chunk_catalog.json"
        if catalog_path.exists():
            with open(catalog_path, "r", encoding="utf-8") as f:
                self.chunks = json.load(f)
        else:
            self.chunks = {}

        self.valid_ids = set(self.chunks.keys())
        self.attack_mapping = get_attack_mapping().get("attacks", {})

    def is_valid_id(self, identifier: str) -> bool:
        """Check if ID exists in the official catalog."""
        return identifier.upper() in self.valid_ids or identifier in self.valid_ids

    def is_relevant_to_label(self, identifier: str, label: str) -> bool:
        """Check if ID is linked to the detected label."""
        if label not in self.attack_mapping:
            return False

        mapping = self.attack_mapping[label]
        mapped_ids = set()

        for c in mapping.get("capec", []):
            mapped_ids.add(c["id"].upper())
        for a in mapping.get("attack", []):
            mapped_ids.add(a["id"].upper())

        return identifier.upper() in mapped_ids


def extract_security_identifiers(text: str) -> List[str]:
    """Extract all ATT&CK, CAPEC, CVE, and Mitigation IDs from a text string."""
    found = []
    found.extend(REGEX_ATTACK.findall(text))
    found.extend(REGEX_CAPEC.findall(text))
    found.extend(REGEX_CVE.findall(text))
    found.extend(REGEX_MITIGATION.findall(text))
    # Deduplicate while preserving uppercase normalization
    return list(set(item.upper() for item in found))


def verify_extracted_ids(
    extracted_ids: List[str], label: str, catalog: ThreatCatalog
) -> Dict[str, Any]:
    """
    Classify each extracted ID as CORRECT, MISMATCHED, or FABRICATED.
    """
    correct = []
    mismatched = []
    fabricated = []

    for eid in extracted_ids:
        if not catalog.is_valid_id(eid):
            # Check if it's a known generic format but absent from official files
            fabricated.append(eid)
        elif catalog.is_relevant_to_label(eid, label):
            correct.append(eid)
        else:
            mismatched.append(eid)

    total = len(extracted_ids)
    fab_rate = (len(fabricated) / total) if total > 0 else 0.0

    return {
        "total_ids": total,
        "correct": correct,
        "mismatched": mismatched,
        "fabricated": fabricated,
        "fabricated_rate": fab_rate,
    }


def judge_answer_claims(
    reference_evidence: str,
    assistant_answer: str,
    use_cache: bool = True,
) -> List[Dict[str, Any]]:
    """
    Deconstruct assistant answer into atomic claims and evaluate each
    against reference evidence returning SUPPORTED, CONTRADICTED, or NOT_IN_EVIDENCE.
    """
    user_prompt = (
        f"[REFERENCE EVIDENCE]:\n{reference_evidence}\n\n"
        f"[ASSISTANT ANSWER]:\n{assistant_answer}\n\n"
        f"Perform claim deconstruction and classification strictly following the JSON format."
    )

    messages = [
        {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    try:
        response = query_llm(
            "judge", messages, temperature=0.0, use_cache=use_cache
        )
        content = response["choices"][0]["message"].get("content", "")

        # Strip markdown fences if present
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()

        data = json.loads(content)
        return data.get("claims", [])

    except Exception as e:
        logger.warning(f"Judge parsing failed ({e}). Returning fallback claim...")
        # Fallback single claim
        return [
            {
                "claim_id": 1,
                "text": assistant_answer[:150],
                "verdict": "NOT_IN_EVIDENCE",
                "reasoning": "Fallback verdict due to judge parsing timeout.",
            }
        ]


def compute_hallucination_metrics(claims: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute strict hallucination rate and unsupported rate from judged claims."""
    total_claims = len(claims)
    if total_claims == 0:
        return {
            "total_claims": 0,
            "supported_count": 0,
            "contradicted_count": 0,
            "not_in_evidence_count": 0,
            "strict_rate": 0.0,
            "unsupported_rate": 0.0,
        }

    supported = sum(1 for c in claims if c.get("verdict") == "SUPPORTED")
    contradicted = sum(1 for c in claims if c.get("verdict") == "CONTRADICTED")
    not_in_ev = sum(1 for c in claims if c.get("verdict") == "NOT_IN_EVIDENCE")

    strict_rate = contradicted / total_claims
    unsupported_rate = (contradicted + not_in_ev) / total_claims

    return {
        "total_claims": total_claims,
        "supported_count": supported,
        "contradicted_count": contradicted,
        "not_in_evidence_count": not_in_ev,
        "strict_rate": strict_rate,
        "unsupported_rate": unsupported_rate,
    }


def is_trap_refused(answer: str) -> bool:
    """
    Check if the model appropriately refused or acknowledged lack of information
    on an adversarial trap question.
    """
    refusal_keywords = [
        "not available",
        "cannot be determined",
        "does not contain",
        "not provided",
        "unknown",
        "no information",
        "not recorded",
        "does not specify",
        "is benign",
        "does not exploit",
        "encrypted",
    ]
    ans_lower = answer.lower()
    return any(kw in ans_lower for kw in refusal_keywords)
