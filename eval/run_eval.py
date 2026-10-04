"""
Resumable Hallucination Evaluation Runner for RAG-IDS.
Compares Condition A (No Retrieval) vs. Condition B (With RAG Retrieval) across 45 questions.
Generates eval_claims.csv, eval_summary.json, judge_audit_20.csv, and hallucination_rates.png.
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from typing import Dict, Any, List

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.config import PROJECT_ROOT, EVAL_RESULTS_DIR, EVAL_PLOTS_DIR
from src.assistant import ask_assistant, get_test_sample
from src.detector import detect
from src.retriever import retrieve_threat_evidence
from src.evaluation import (
    ThreatCatalog,
    extract_security_identifiers,
    verify_extracted_ids,
    judge_answer_claims,
    compute_hallucination_metrics,
    is_trap_refused,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("eval_runner")

CHECKPOINT_FILE = EVAL_RESULTS_DIR / "eval_checkpoint.json"


def load_checkpoint() -> Dict[str, Any]:
    """Load previously completed question results."""
    if CHECKPOINT_FILE.exists():
        with open(CHECKPOINT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_checkpoint(checkpoint_data: Dict[str, Any]):
    """Persist completed question results."""
    with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
        json.dump(checkpoint_data, f, indent=2)


def run_evaluation(limit: int = 45, dry_run: bool = False):
    """Execute evaluation comparing Condition A vs. Condition B."""
    questions_path = PROJECT_ROOT / "eval/questions.json"
    with open(questions_path, "r", encoding="utf-8") as f:
        questions = json.load(f)

    if dry_run:
        questions = questions[:2]
    elif limit < len(questions):
        questions = questions[:limit]

    print("\n" + "=" * 75)
    print("STARTING RAG-IDS HALLUCINATION BENCHMARK EVALUATION")
    print(f"Total Benchmark Questions to Evaluate: {len(questions)}")
    print("=" * 75)

    catalog = ThreatCatalog()
    checkpoint = load_checkpoint()

    all_claims_rows = []
    cond_a_claims = []
    cond_b_claims = []

    cond_a_ids = []
    cond_b_ids = []

    trap_a_correct = 0
    trap_b_correct = 0
    total_traps = 0

    for idx, q_item in enumerate(questions):
        q_id = q_item["id"]
        q_type = q_item["type"]
        sample_id = q_item["sample_id"]
        q_text = q_item["question"]
        expected_label = q_item["label"]

        logger.info(f"[{idx+1}/{len(questions)}] Processing {q_id} ({q_type}) for {expected_label}...")

        # Get detector output and reference evidence
        sample_row = get_test_sample(sample_id)
        det_res = detect(sample_row) if sample_row is not None else None

        # Build full ground truth reference evidence for judging
        full_ref_evidence = retrieve_threat_evidence(
            query=q_text, detection_result=det_res, max_chunks=8, max_words=1500
        )["formatted_evidence"]

        # --- Condition A: No Retrieval ---
        cp_key_a = f"{q_id}_A"
        if cp_key_a in checkpoint:
            res_a = checkpoint[cp_key_a]
        else:
            ans_res_a = ask_assistant(
                question=q_text,
                sample_id=sample_id,
                retrieval_enabled=False,
                mode="fixed",
            )
            claims_a = judge_answer_claims(full_ref_evidence, ans_res_a["answer"])
            ids_a = extract_security_identifiers(ans_res_a["answer"])
            id_ver_a = verify_extracted_ids(ids_a, det_res["predicted_label"] if det_res else expected_label, catalog)

            res_a = {
                "q_id": q_id,
                "condition": "A_No_Retrieval",
                "answer": ans_res_a["answer"],
                "claims": claims_a,
                "extracted_ids": ids_a,
                "id_verification": id_ver_a,
                "is_trap_refused": is_trap_refused(ans_res_a["answer"]) if q_type == "trap" else None,
            }
            checkpoint[cp_key_a] = res_a
            save_checkpoint(checkpoint)

        # --- Condition B: With RAG Retrieval ---
        cp_key_b = f"{q_id}_B"
        if cp_key_b in checkpoint:
            res_b = checkpoint[cp_key_b]
        else:
            ans_res_b = ask_assistant(
                question=q_text,
                sample_id=sample_id,
                retrieval_enabled=True,
                mode="fixed",
            )
            claims_b = judge_answer_claims(full_ref_evidence, ans_res_b["answer"])
            ids_b = extract_security_identifiers(ans_res_b["answer"])
            id_ver_b = verify_extracted_ids(ids_b, det_res["predicted_label"] if det_res else expected_label, catalog)

            res_b = {
                "q_id": q_id,
                "condition": "B_With_Retrieval",
                "answer": ans_res_b["answer"],
                "claims": claims_b,
                "extracted_ids": ids_b,
                "id_verification": id_ver_b,
                "is_trap_refused": is_trap_refused(ans_res_b["answer"]) if q_type == "trap" else None,
            }
            checkpoint[cp_key_b] = res_b
            save_checkpoint(checkpoint)

        # Aggregate claims for CSV export
        for c in res_a["claims"]:
            cond_a_claims.append(c)
            all_claims_rows.append({
                "question_id": q_id,
                "question_type": q_type,
                "condition": "Condition_A_No_RAG",
                "claim_id": c.get("claim_id"),
                "claim_text": c.get("text"),
                "verdict": c.get("verdict"),
                "reasoning": c.get("reasoning"),
            })

        for c in res_b["claims"]:
            cond_b_claims.append(c)
            all_claims_rows.append({
                "question_id": q_id,
                "question_type": q_type,
                "condition": "Condition_B_With_RAG",
                "claim_id": c.get("claim_id"),
                "claim_text": c.get("text"),
                "verdict": c.get("verdict"),
                "reasoning": c.get("reasoning"),
            })

        cond_a_ids.extend(res_a["id_verification"]["fabricated"])
        cond_b_ids.extend(res_b["id_verification"]["fabricated"])

        if q_type == "trap":
            total_traps += 1
            if res_a["is_trap_refused"]:
                trap_a_correct += 1
            if res_b["is_trap_refused"]:
                trap_b_correct += 1

    # --- Save eval_claims.csv ---
    claims_df = pd.DataFrame(all_claims_rows)
    claims_csv_path = EVAL_RESULTS_DIR / "eval_claims.csv"
    claims_df.to_csv(claims_csv_path, index=False)
    logger.info(f"Saved {len(claims_df)} judged claims to {claims_csv_path}")

    # --- Create Blinded Judge Audit CSV (20 samples) ---
    if len(claims_df) >= 20:
        sample_20 = claims_df.sample(n=20, random_state=42).copy()
        # Drop judge verdict for blinded human review
        sample_20["human_verdict"] = ""
        audit_csv = EVAL_RESULTS_DIR / "judge_audit_20.csv"
        sample_20.drop(columns=["verdict", "reasoning"]).to_csv(audit_csv, index=False)
        logger.info(f"Saved 20 blinded claims to {audit_csv} for human agreement audit.")

    # --- Compute Final Metrics ---
    metrics_a = compute_hallucination_metrics(cond_a_claims)
    metrics_b = compute_hallucination_metrics(cond_b_claims)

    total_ids_a = sum(len(checkpoint[f"{q['id']}_A"]["extracted_ids"]) for q in questions if f"{q['id']}_A" in checkpoint)
    total_ids_b = sum(len(checkpoint[f"{q['id']}_B"]["extracted_ids"]) for q in questions if f"{q['id']}_B" in checkpoint)

    fab_rate_a = (len(cond_a_ids) / total_ids_a) if total_ids_a > 0 else 0.0
    fab_rate_b = (len(cond_b_ids) / total_ids_b) if total_ids_b > 0 else 0.0

    trap_acc_a = (trap_a_correct / total_traps) if total_traps > 0 else 1.0
    trap_acc_b = (trap_b_correct / total_traps) if total_traps > 0 else 1.0

    summary = {
        "condition_A_no_retrieval": {
            "total_claims": metrics_a["total_claims"],
            "supported_claims": metrics_a["supported_count"],
            "contradicted_claims": metrics_a["contradicted_count"],
            "not_in_evidence_claims": metrics_a["not_in_evidence_count"],
            "strict_hallucination_rate": round(metrics_a["strict_rate"], 4),
            "unsupported_rate": round(metrics_a["unsupported_rate"], 4),
            "total_ids_extracted": total_ids_a,
            "fabricated_ids_count": len(cond_a_ids),
            "fabricated_id_rate": round(fab_rate_a, 4),
            "trap_refusal_accuracy": round(trap_acc_a, 4),
        },
        "condition_B_with_retrieval": {
            "total_claims": metrics_b["total_claims"],
            "supported_claims": metrics_b["supported_count"],
            "contradicted_claims": metrics_b["contradicted_count"],
            "not_in_evidence_claims": metrics_b["not_in_evidence_count"],
            "strict_hallucination_rate": round(metrics_b["strict_rate"], 4),
            "unsupported_rate": round(metrics_b["unsupported_rate"], 4),
            "total_ids_extracted": total_ids_b,
            "fabricated_ids_count": len(cond_b_ids),
            "fabricated_id_rate": round(fab_rate_b, 4),
            "trap_refusal_accuracy": round(trap_acc_b, 4),
        },
    }

    summary_path = EVAL_RESULTS_DIR / "eval_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    # --- Render Comparative Bar Chart ---
    chart_data = pd.DataFrame([
        {
            "Metric": "Strict Hallucination Rate",
            "Condition A (No Retrieval)": summary["condition_A_no_retrieval"]["strict_hallucination_rate"] * 100,
            "Condition B (With RAG)": summary["condition_B_with_retrieval"]["strict_hallucination_rate"] * 100,
        },
        {
            "Metric": "Unsupported Rate",
            "Condition A (No Retrieval)": summary["condition_A_no_retrieval"]["unsupported_rate"] * 100,
            "Condition B (With RAG)": summary["condition_B_with_retrieval"]["unsupported_rate"] * 100,
        },
        {
            "Metric": "Fabricated ID Rate",
            "Condition A (No Retrieval)": summary["condition_A_no_retrieval"]["fabricated_id_rate"] * 100,
            "Condition B (With RAG)": summary["condition_B_with_retrieval"]["fabricated_id_rate"] * 100,
        },
    ])

    chart_melted = chart_data.melt(id_vars="Metric", var_name="Condition", value_name="Percentage (%)")

    plt.figure(figsize=(10, 6))
    sns.barplot(data=chart_melted, x="Metric", y="Percentage (%)", hue="Condition", palette=["#ef4444", "#3b82f6"])
    plt.title("Hallucination Evaluation: Condition A (No Retrieval) vs. Condition B (With RAG)", fontsize=14, fontweight="bold")
    plt.ylabel("Rate (%)", fontsize=12)
    plt.ylim(0, max(chart_melted["Percentage (%)"].max() + 15, 40))
    for p in plt.gca().patches:
        height = p.get_height()
        if height > 0:
            plt.gca().annotate(f"{height:.1f}%", (p.get_x() + p.get_width() / 2.0, height + 1), ha="center", fontsize=10)

    plt.tight_layout()
    plot_path = EVAL_PLOTS_DIR / "hallucination_rates.png"
    plt.savefig(plot_path, dpi=300)
    plt.close()
    logger.info(f"Saved evaluation comparison chart to {plot_path}")

    # Display final report
    print("\n" + "=" * 75)
    print("HALLUCINATION EVALUATION SUMMARY RESULTS")
    print("=" * 75)
    print(pd.DataFrame(summary).to_string())
    print("\nChart saved to:", plot_path)
    print("=" * 75 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RAG-IDS Evaluation Runner")
    parser.add_argument("--limit", type=int, default=45, help="Number of questions to evaluate")
    parser.add_argument("--dry-run", action="store_true", help="Evaluate first 2 questions as verification")
    args = parser.parse_args()

    run_evaluation(limit=args.limit, dry_run=args.dry_run)
