# RAG-IDS: Retrieval-Augmented Intrusion Detection System

RAG-IDS is an intelligent cybersecurity prototype that pairs a high-performance machine learning intrusion detector with a Retrieval-Augmented Generation (RAG) threat explanation assistant. The system detects attacks in IoT network flow data and produces grounded incident response guidance referencing official MITRE ATT&CK techniques, CAPEC attack patterns, and NVD CVE records.

---

## Technical Overview

```
                      +-----------------------------+
                      |   IoT Flowmeter Telemetry   |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |   1. Tabular ML Detector    |
                      | (XGBoost / TreeSHAP Top-5)  |
                      +--------------+--------------+
                                     |
                                     v  Predicted Label + Top Features
                      +-----------------------------+
                      |   2. Hybrid Threat RAG      |
                      |  - Deterministic ID Lookup  |
                      |  - Semantic Vector Search   |
                      +--------------+--------------+
                                     |
                                     v  Retrieved Evidence Block [TAG]
                      +-----------------------------+
                      |   3. Grounded LLM Assistant |
                      |    (Groq: gpt-oss-120b)     |
                      +--------------+--------------+
                                     |
                      +--------------+--------------+
                      |                             |
                      v                             v
       +-----------------------------+ +-----------------------------+
       |   Streamlit Interactive UI  | |  Hallucination Evaluation   |
       |  - Real-time flow inspector | |  - Claim extraction & judge |
       |  - Evidence citations & links| |  - Fabricated ID detection |
       +-----------------------------+ +-----------------------------+
```

---

## Project Structure

```
.
├── .env                       # API keys (GROQ_API_KEY, GEMINI_API_KEY)
├── README.md                  # Project overview and run instructions
├── PLAN.md                    # Complete project blueprint and audit records
├── requirements.txt           # Pinned Python package dependencies
├── configs/
│   ├── rt_iot2022.yaml        # Dataset column roles, drops, and split settings
│   └── attack_mapping.yaml    # Mapping from dataset labels to CAPEC and ATT&CK
├── data/
│   ├── raw/                   # rt_iot2022.csv downloaded from UCI repository
│   ├── processed/             # train.parquet, test.parquet, test_samples_pool.json
│   ├── kb_raw/                # Official MITRE and NVD data files
│   ├── kb_manual/             # Label cards and feature glossary
│   └── chroma_db/             # Local vector store
├── models/                    # Saved detector checkpoints and preprocessors
├── src/
│   ├── config.py              # Configuration and environment loader
│   ├── data_loader.py         # Data cleaning, deduplication, and stratified split
│   ├── detector.py            # Model training and detect(sample) interface
│   ├── kb_builder.py          # Threat knowledge base builder
│   ├── retriever.py           # Hybrid retrieval engine
│   ├── llm_client.py          # Rate-limited LLM API client with caching
│   ├── assistant.py           # Conversational assistant (Fixed & Tool Calling)
│   ├── prompts.py             # Grounding rules, system prompts, and judge prompt
│   └── evaluation.py          # Hallucination evaluation metrics
└── app/
    ├── Home.py                # Streamlit live traffic inspector & chat
    └── pages/
        └── 1_Model_Metrics.py # Detector performance & evaluation benchmarks
```

---

## Getting Started

### 1. Prerequisites
- **Operating System:** macOS (Apple Silicon / Intel) or Linux.
- **Python Version:** Python 3.10+ (tested and verified on Python 3.14).
- **Virtual Environment:** Recommended to avoid package collisions.

### 2. Setup Virtual Environment & Dependencies
```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Install verified dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. API Keys Configuration
Copy your API keys into `.env` at the project root:
```env
GROQ_API_KEY="gsk_..."
GEMINI_API_KEY="AQ...."
```
*Note: Never commit `.env` to Git. It is already included in `.gitignore`.*

---

## Milestone Execution Guide

### Milestone 1: Data Ingestion & Preprocessing Pipeline
Loads the RT-IoT2022 dataset from the UCI Machine Learning Repository, removes the ephemeral source port `id.orig_p`, analyzes flow duplicates, performs a stratified 80/20 train/test split, and indexes the test pool with persistent sample IDs (`sample_00000` to `sample_04767`).

```bash
python -m src.data_loader
```

### Milestone 2: Baseline Models, XGBoost Detector & Leakage Audit
Trains and compares Logistic Regression, Random Forest, and XGBoost using 5-fold Stratified Cross-Validation on the training partition only. Trains the production XGBoost detector, evaluates the holdout test set, runs the port leakage audit, and provides the `detect(sample)` inference API with TreeSHAP feature attributions.

```bash
python -m src.detector
```

**Results:**
- **5-Fold CV Comparison:**
  - Logistic Regression: Macro-F1 = 0.8166 ± 0.0097 (Fit Time: 0.42s)
  - Random Forest: Macro-F1 = 0.8800 ± 0.0061 (Fit Time: 0.19s)
  - XGBoost: Macro-F1 = **0.8852 ± 0.0096** (Fit Time: 1.76s)
- **Holdout Test Set Performance:**
  - Overall Accuracy: **98.51%**
  - Weighted F1: **98.54%**
  - Macro F1: **87.41%** (minority class `NMAP_FIN_SCAN` had 1 test sample due to pre-split deduplication)
  - False Alarm Rate: **1.30%** (31 / 2,393 normal flows flagged as attack)
- **Port Leakage Audit:**
  - Macro-F1 WITH destination port: **87.41%**
  - Macro-F1 WITHOUT destination port: **87.03%**
  - Delta: **0.38%** (Confirms the detector relies on flow mechanics rather than memorizing destination port numbers)
- **Artifacts Saved:**
  - `models/detector_xgboost.json`
  - `models/preprocessor.joblib`
  - `eval/results/model_comparison.csv`
  - `eval/plots/confusion_matrix.png`
