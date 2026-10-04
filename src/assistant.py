"""
Incident Response Assistant for RAG-IDS.
Implements both the Fixed Pipeline (detect -> retrieve -> grounded answer)
and Tool-Calling Mode (LLM executes detector and search tools autonomously).
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import pandas as pd

from src.config import PROJECT_ROOT, get_dataset_config
from src.detector import detect
from src.retriever import retrieve_threat_evidence
from src.llm_client import query_llm
from src.prompts import GROUNDED_SYSTEM_PROMPT, NO_RETRIEVAL_SYSTEM_PROMPT

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("assistant")

# Global test data cache
_GLOBAL_TEST_DF = None


def get_test_sample(sample_id: str) -> Optional[pd.Series]:
    """Retrieve sample row by persistent sample ID from test partition."""
    global _GLOBAL_TEST_DF
    if _GLOBAL_TEST_DF is None:
        config = get_dataset_config("rt_iot2022")
        test_path = PROJECT_ROOT / config["processed_test_path"]
        _GLOBAL_TEST_DF = pd.read_parquet(test_path).set_index("sample_id", drop=False)

    if sample_id in _GLOBAL_TEST_DF.index:
        return _GLOBAL_TEST_DF.loc[sample_id]
    return None


# Tool definitions for OpenAI tool calling
TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "run_detector",
            "description": "Run the machine learning intrusion detector on a network flow sample by its sample ID to identify attacks, confidence, and top driving features.",
            "parameters": {
                "type": "object",
                "properties": {
                    "sample_id": {
                        "type": "string",
                        "description": "The unique sample ID of the traffic flow to inspect (e.g., 'sample_00004').",
                    }
                },
                "required": ["sample_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_knowledge",
            "description": "Perform semantic search across the threat knowledge base (MITRE ATT&CK, CAPEC, NVD CVEs, label cards).",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The cybersecurity technical search query (e.g., 'Slowloris Apache mitigation' or 'TCP SYN flood').",
                    }
                },
                "required": ["query"],
            },
        },
    },
]


def execute_tool_call(tool_name: str, args: Dict[str, Any]) -> str:
    """Execute local function corresponding to LLM tool call."""
    if tool_name == "run_detector":
        sample_id = args.get("sample_id")
        sample = get_test_sample(sample_id)
        if sample is None:
            return json.dumps({"error": f"Sample ID '{sample_id}' not found in test pool."})
        det_res = detect(sample)
        return json.dumps(det_res)

    elif tool_name == "search_knowledge":
        q = args.get("query", "")
        ret_res = retrieve_threat_evidence(query=q, max_chunks=3)
        return ret_res["formatted_evidence"]

    return json.dumps({"error": f"Unknown tool: {tool_name}"})


def ask_assistant(
    question: str,
    sample_id: Optional[str] = None,
    retrieval_enabled: bool = True,
    mode: str = "fixed",
    use_cache: bool = True,
) -> Dict[str, Any]:
    """
    Core entrypoint for the RAG-IDS assistant.
    Supports fixed pipeline and tool-calling modes, with or without retrieval.
    """
    detection_result = None
    retrieval_result = None

    sample = None
    if sample_id:
        sample = get_test_sample(sample_id)
        if sample is not None:
            detection_result = detect(sample)

    # Mode 1: Tool-Calling Mode
    if mode == "tool" and retrieval_enabled:
        try:
            logger.info("Executing assistant in Tool-Calling mode...")
            messages = [
                {
                    "role": "system",
                    "content": GROUNDED_SYSTEM_PROMPT
                    + "\nYou have access to run_detector(sample_id) and search_knowledge(query). Use them to collect evidence before answering.",
                },
                {
                    "role": "user",
                    "content": f"Traffic Sample ID: {sample_id}\n\nQuestion: {question}",
                },
            ]

            max_turns = 4
            for _ in range(max_turns):
                res = query_llm(
                    "answering",
                    messages,
                    tools=TOOL_DEFINITIONS,
                    temperature=0.0,
                    use_cache=use_cache,
                )
                msg = res["choices"][0]["message"]
                tool_calls = msg.get("tool_calls")

                if not tool_calls:
                    # Final textual answer reached
                    return {
                        "answer": msg.get("content", ""),
                        "detection": detection_result,
                        "retrieval": retrieval_result,
                        "mode": "tool",
                        "retrieval_enabled": True,
                    }

                # Single tool call per turn as per prompt constraints
                tool_call = tool_calls[0]
                t_id = tool_call["id"]
                t_name = tool_call["function"]["name"]
                t_args = json.loads(tool_call["function"].get("arguments", "{}"))

                # Execute tool
                tool_output = execute_tool_call(t_name, t_args)

                # Append assistant message and tool response
                messages.append(
                    {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [tool_call],
                    }
                )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": t_id,
                        "name": t_name,
                        "content": tool_output,
                    }
                )

        except Exception as e:
            logger.warning(f"Tool-calling error ({e}). Gracefully falling back to Fixed Pipeline...")
            mode = "fixed"

    # Mode 2: Fixed Pipeline (Always reliable)
    if retrieval_enabled:
        system_prompt = GROUNDED_SYSTEM_PROMPT
        retrieval_result = retrieve_threat_evidence(
            query=question, detection_result=detection_result
        )
        user_content = (
            f"{retrieval_result['formatted_evidence']}\n\n"
            f"USER QUESTION: {question}\n\n"
            f"Provide your grounded incident response explanation following all citation rules:"
        )
    else:
        # Condition A: No Retrieval (Telemetry only)
        system_prompt = NO_RETRIEVAL_SYSTEM_PROMPT
        det_block = ""
        if detection_result:
            det_block = (
                f"### [DET: Detector Telemetry]\n"
                f"- Predicted Label: {detection_result['predicted_label']}\n"
                f"- Attack Family: {detection_result['attack_family']}\n"
                f"- Confidence: {detection_result['confidence']:.2%}\n"
                f"- Top Features: {', '.join([f'{tf['feature']}={tf['value']}' for tf in detection_result['top_features']])}\n\n"
            )
        user_content = f"{det_block}USER QUESTION: {question}"

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content},
    ]

    res = query_llm(
        "answering", messages, temperature=0.0, use_cache=use_cache
    )
    answer = res["choices"][0]["message"].get("content", "")

    return {
        "answer": answer,
        "detection": detection_result,
        "retrieval": retrieval_result,
        "mode": "fixed",
        "retrieval_enabled": retrieval_enabled,
    }


def main():
    parser = argparse.ArgumentParser(description="RAG-IDS CLI Assistant")
    parser.add_argument("--sample-id", type=str, default="sample_00004", help="Sample ID to inspect")
    parser.add_argument("--question", type=str, default="What attack is this and how should I stop it?", help="Analyst query")
    parser.add_argument("--no-retrieval", action="store_true", help="Disable RAG retrieval (Condition A)")
    parser.add_argument("--mode", type=str, default="fixed", choices=["fixed", "tool"], help="Assistant mode")

    args = parser.parse_args()

    print("\n" + "=" * 75)
    print("RAG-IDS INCIDENT RESPONSE ASSISTANT (CLI)")
    print("=" * 75)
    print(f"Sample ID:  {args.sample_id}")
    print(f"Retrieval:  {'DISABLED (Condition A)' if args.no_retrieval else 'ENABLED (Condition B)'}")
    print(f"Mode:       {args.mode}")
    print(f"Question:   {args.question}\n")

    res = ask_assistant(
        question=args.question,
        sample_id=args.sample_id,
        retrieval_enabled=not args.no_retrieval,
        mode=args.mode,
    )

    if res["detection"]:
        d = res["detection"]
        print(f"DETECTOR VERDICT: {d['predicted_label']} ({d['attack_family']}) - Confidence: {d['confidence']:.2%}")
        print("Top Features:")
        for tf in d["top_features"]:
            print(f"  - {tf['feature']} = {tf['value']} (Contrib: {tf['contribution']:+.4f})")
        print()

    print("-" * 75)
    print("ASSISTANT RESPONSE:")
    print("-" * 75)
    print(res["answer"])
    print("-" * 75 + "\n")


if __name__ == "__main__":
    main()
