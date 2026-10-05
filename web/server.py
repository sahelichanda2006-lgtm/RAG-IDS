"""
Web server for the RAG-IDS range.

    python -m web.server            # then open http://127.0.0.1:8000

The page itself is in web/static/ (plain HTML, CSS and JavaScript, no build step).
This file is only the data side: it runs the detector, the retrieval and the LLM
and returns JSON.
"""

import json
import random
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal, Optional

import pandas as pd
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src import presentation as pres
from src.assistant import answer
from src.config import (DEFAULT_DATASET, EVAL_PLOTS_DIR, dataset_paths, get_dataset_config,
                        get_llm_config, trained_datasets)
from src.detector import detect, load_test_sample
from src.evaluation import check_ids, normalize_dashes
from src import llm_client
from src.llm_client import LLMError
from src.retriever import glossary, semantic_search

STATIC = Path(__file__).resolve().parent / "static"
LLM_LOCK = threading.Lock()   # one LLM question at a time keeps the free-plan pacing simple
_POOLS = {}


def pool(dataset: str):
    if dataset not in _POOLS:
        _POOLS[dataset] = json.loads(dataset_paths(dataset)["pool"].read_text())
    return _POOLS[dataset]


@asynccontextmanager
async def lifespan(app):
    llm_client.FALLBACK_ENABLED = True   # the demo may use the fallback models; the evaluation never does
    # Load the model and the embedder once, so the first launch is instant.
    detect(load_test_sample("sample_00000", DEFAULT_DATASET), DEFAULT_DATASET)
    semantic_search("warm up", 1)
    print("RAG-IDS range ready: http://127.0.0.1:8000")
    yield


app = FastAPI(title="RAG-IDS range", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Meta: everything the lab screen needs
# ---------------------------------------------------------------------------
@app.get("/api/meta")
def meta(dataset: str = DEFAULT_DATASET):
    cfg = get_dataset_config(dataset)
    metrics = json.loads((dataset_paths(dataset)["results_dir"] / "detector_metrics.json").read_text())
    by_label = {}
    for p in pool(dataset):
        by_label.setdefault(p["label"], {"family": p["attack_family"], "count": 0})["count"] += 1
    scenarios = []
    for label, info in by_label.items():
        sc = pres.scenario(label, info["family"])
        sc["count"] = info["count"]
        sc["attack"] = info["family"] != "Normal"
        scenarios.append(sc)
    order = ["DoS", "Brute force", "Spoofing", "Reconnaissance"]
    scenarios.sort(key=lambda s: (not s["attack"], order.index(s["family"]) if s["family"] in order else 9, s["headline"]))
    return {"dataset": dataset, "dataset_name": cfg["dataset_name"], "citation": cfg.get("citation", ""),
            "datasets": trained_datasets(), "scenarios": scenarios, "test_flows": len(pool(dataset)),
            "macro_f1": metrics["test"]["macro_f1"], "labels": len(by_label),
            "answer_model": get_llm_config()["roles"]["answering"]["model"], "colors": pres.FAMILY_COLORS}


# ---------------------------------------------------------------------------
# Launch: choose a real flow, run the detector
# ---------------------------------------------------------------------------
class LaunchReq(BaseModel):
    dataset: str = DEFAULT_DATASET
    label: Optional[str] = None
    mystery: bool = False
    sample_id: Optional[str] = None


def _num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


@app.post("/api/launch")
def launch(req: LaunchReq):
    cfg = get_dataset_config(req.dataset)
    flows = pool(req.dataset)
    if req.sample_id:
        sample_id = req.sample_id
    elif req.mystery:
        sample_id = random.choice(flows)["sample_id"]
    else:
        options = [p["sample_id"] for p in flows if p["label"] == req.label]
        if not options:
            raise HTTPException(404, f"No flows with label '{req.label}'.")
        sample_id = random.choice(options)
    row = load_test_sample(sample_id, req.dataset)
    if row is None:
        raise HTTPException(404, f"There is no flow called '{sample_id}'. "
                                 f"IDs run from sample_00000 to sample_{len(flows) - 1:05d}.")
    det = detect(row, req.dataset)
    true_label = row[cfg["label_column"]]
    true_family = cfg["label_to_family"].get(true_label, "Other")
    gloss = glossary()
    skip = set(cfg.get("drop_columns", [])) | {cfg["label_column"], "sample_id"}
    port_col = (cfg.get("port_columns") or [None])[0]
    service = str(row.get("service", "-"))
    features = []
    for f in det["top_features"]:
        g = gloss.get(f["feature"], {})
        features.append({"name": f["feature"], "meaning": g.get("meaning", ""),
                         "value": pres.fmt_value(f["value"], g.get("unit", "")), "push": f["contribution"]})
    return {
        "sample_id": sample_id,
        "facts": {"protocol": str(row.get("proto", "")) + ("" if service == "-" else f" · {service}"),
                  "port": int(_num(row.get(port_col))) if port_col else None,
                  "duration": pres.fmt_duration(_num(row.get("flow_duration"))),
                  "packets_out": int(_num(row.get("fwd_pkts_tot"))), "packets_back": int(_num(row.get("bwd_pkts_tot"))),
                  "features": len([c for c in row.index if c not in skip])},
        "true": {"label": true_label, "family": true_family, "name": pres.pretty_label(true_label),
                 "scenario": pres.scenario(true_label, true_family)},
        "detection": {"label": det["predicted_label"], "name": pres.pretty_label(det["predicted_label"]),
                      "family": det["attack_family"], "color": pres.FAMILY_COLORS.get(det["attack_family"], "#8A94A6"),
                      "is_attack": det["is_attack"], "confidence": det["confidence"],
                      "low_confidence": det["low_confidence"], "probabilities": det["probabilities"],
                      "correct": det["predicted_label"] == true_label, "features": features,
                      "references": pres.mapped_refs(det["predicted_label"])},
    }


# ---------------------------------------------------------------------------
# Ask: the assistant
# ---------------------------------------------------------------------------
class AskReq(BaseModel):
    dataset: str = DEFAULT_DATASET
    sample_id: Optional[str] = None
    question: str
    mode: Literal["memory", "kb", "compare"] = "kb"
    tools: bool = False


def _one(req: AskReq, use_retrieval: bool):
    out = answer(req.question, req.sample_id, req.dataset, use_retrieval, "tool" if (req.tools and use_retrieval) else "fixed")
    det = out["detection"]
    text = normalize_dashes(out["answer"])
    allowed = pres.allowed_tags(out["evidence_chunks"], det is not None) if use_retrieval else None
    flags = []
    if det:   # checking IDs against "the detected attack" only makes sense when there is a detection
        for r in check_ids(text, req.question, det["predicted_label"], online=False):
            flags.append({"id": r["id"], "outcome": r["outcome"], "note": r["note"], "name": r["official_name"]})
    return {"kind": "kb" if use_retrieval else "memory", "text": text,
            "tags": pres.tag_info(text, allowed, out["evidence_chunks"]), "id_flags": flags,
            "sources": [{"id": c["chunk_id"], "tag": c["tag"], "name": c["name"], "source": c["source"],
                         "url": c.get("url", ""), "kind": pres.tag_kind(c["tag"]),
                         "snippet": c["text"].split("\n", 2)[-1][:320]} for c in out["evidence_chunks"]],
            "model": out["model"], "cached": out["cached"], "mode": out["mode"],
            "fallback": out["model"] != get_llm_config()["roles"]["answering"]["model"],
            "tool_trace": out["tool_trace"], "fallback_reason": out["fallback_reason"], "warnings": out["warnings"]}


@app.post("/api/ask")
def ask(req: AskReq):
    question = req.question.strip()
    if not question:
        raise HTTPException(400, "Type a question first.")
    req.question = question
    try:
        with LLM_LOCK:
            if req.mode == "compare":
                return {"answers": [_one(req, False), _one(req, True)]}
            return {"answers": [_one(req, req.mode == "kb")]}
    except ValueError as e:
        raise HTTPException(400, str(e))
    except LLMError as e:
        raise HTTPException(502, str(e))


# ---------------------------------------------------------------------------
# Results page
# ---------------------------------------------------------------------------
def _records(path: Path):
    return json.loads(pd.read_csv(path).to_json(orient="records")) if path.exists() else []


@app.get("/api/results")
def results(dataset: str = DEFAULT_DATASET):
    rd = dataset_paths(dataset)["results_dir"]
    metrics = json.loads((rd / "detector_metrics.json").read_text())
    per = _records(rd / "test_per_class.csv")
    for r in per:
        r["name"] = pres.pretty_label(r["label"])
    return {"dataset": dataset, "metrics": metrics, "per_label": per, "comparison": _records(rd / "model_comparison.csv"),
            "class_counts": _records(rd / "class_counts.csv"),
            "eval": {run: _records(rd / run / "summary.csv") for run in ("main", "small")},
            "confusion_png": f"/plots/{dataset}/confusion_matrix.png"}


# ---------------------------------------------------------------------------
@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
app.mount("/plots", StaticFiles(directory=EVAL_PLOTS_DIR), name="plots")

if __name__ == "__main__":
    uvicorn.run("web.server:app", host="127.0.0.1", port=8000, log_level="warning")
