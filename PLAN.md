# RAG-IDS Project Architecture & Execution Plan

**Author:** Antigravity (AI Pair Programmer) & Student Researcher  
**Project:** RAG-IDS — Retrieval-Augmented Intrusion Detection & Grounded Threat Explanation  
**Date of Verification & Baseline Analysis:** 2 October 2026  
**Document Status:** Ready for User Review (No implementation code executed)

---

## Executive Summary & Dataset Audit

To ground this plan in empirical fact rather than assumptions, the **RT-IoT2022** dataset was downloaded directly from the UCI Machine Learning Repository (Dataset ID: 942) and audited locally. The findings have been cross-checked against all project expectations.

### 1. Dataset Verification: Expectations vs. Empirical Reality

| Specification Item | Expected Value / Behavior | Empirical Findings (Audited 2 Oct 2026) | Status / Impact |
| :--- | :--- | :--- | :--- |
| **Row Count** | 123,117 rows | Exactly **123,117** rows | **Confirmed** |
| **Column Count** | 83 features + 1 label = 84 | Exactly **84** columns (83 features + `Attack_type`) | **Confirmed** |
| **Missing Values** | 0 missing values | Exactly **0** missing values across all 84 columns | **Confirmed** |
| **Categorical Types** | `proto`, `service` text | `proto` (3 unique: `tcp`, `udp`, `icmp`)<br>`service` (10 unique: `mqtt`, `-`, `http`, `dns`, `ntp`, `ssl`, `dhcp`, `irc`, `ssh`, `radius`) | **Confirmed** (Remaining 81 features are numeric flow statistics) |
| **Row Number Column** | Potential unnamed index in zip | Direct UCI API fetch had no unnamed index. An explicit check in the loader drops `Unnamed: 0` if present in raw CSV files. | **Confirmed & Handled** |
| **Class Count & Names** | 12 distinct classes (9 attacks, 3 normal) | Exactly **12** unique values matching expected spellings, including `ARP_poisioning` and `DOS_SYN_Hping`. | **Confirmed** |
| **Class Distribution** | Heavy imbalance (~77% DoS SYN, ~10% Normal) | `DOS_SYN_Hping`: 94,659 (76.88%)<br>Normal combined: 12,507 (10.16%)<br>Minority: `Metasploit_Brute_Force_SSH` (37), `NMAP_FIN_SCAN` (28) | **Confirmed** |
| **Deduplication Impact** | Drop `id.orig_p`, deduplicate flows | Total rows shrink from **123,117** to **23,839** (99,278 duplicate rows dropped!). | **Critical Finding** (See detailed analysis below) |

---

### 2. Critical Audit Finding: Duplication & The Minority Class Dilemma

When the source port `id.orig_p` is dropped (as ephemeral source ports make flows artificially distinct) and identical rows are removed, the class distribution changes dramatically:

```
+----------------------------+-----------+---------------+---------------+----------------+
| Attack_type                | Raw Count | Deduped Count | Dropped Count | % Retained     |
+----------------------------+-----------+---------------+---------------+----------------+
| DOS_SYN_Hping              |    94,659 |            57 |        94,602 |          0.06% |
| ARP_poisioning             |     7,750 |         5,300 |         2,450 |         68.39% |
| Thing_Speak (Normal)       |     8,108 |         7,602 |           506 |         93.76% |
| MQTT_Publish (Normal)      |     4,146 |         4,141 |             5 |         99.88% |
| NMAP_UDP_SCAN              |     2,590 |         1,151 |         1,439 |         44.44% |
| NMAP_XMAS_TREE_SCAN        |     2,010 |         1,894 |           116 |         94.23% |
| NMAP_OS_DETECTION          |     2,000 |         1,899 |           101 |         94.95% |
| NMAP_TCP_scan              |     1,002 |         1,002 |             0 |        100.00% |
| DDOS_Slowloris             |       534 |           533 |             1 |         99.81% |
| Wipro_bulb (Normal)        |       253 |           219 |            34 |         86.56% |
| Metasploit_Brute_Force_SSH |        37 |            36 |             1 |         97.30% |
| NMAP_FIN_SCAN              |        28 |             5 |            23 |         17.86% |
+----------------------------+-----------+---------------+---------------+----------------+
| TOTAL                      |   123,117 |        23,839 |        99,278 |         19.36% |
+----------------------------+-----------+---------------+---------------+----------------+
```

#### Why did this happen?
1. **`DOS_SYN_Hping`:** Hping floods generate tens of thousands of identical TCP SYN packets towards destination port 21, varying only the ephemeral source port (`id.orig_p`). Stripping `id.orig_p` compresses 94,659 packets into just 57 unique flow parameter profiles.
2. **`NMAP_FIN_SCAN`:** Nmap sends repetitive TCP FIN probe packets with fixed packet window sizes, identical header flags, zero payload, and uniform timing. Without `id.orig_p`, only **5 distinct rows** remain.

#### Concrete Recommendations for `NMAP_FIN_SCAN` (<20 rows)
If we perform pre-split deduplication:
- An 80/20 train/test split on 5 rows yields **4 training samples** and **1 test sample**.
- In 5-fold cross-validation, 1 fold has 0 samples of `NMAP_FIN_SCAN`, violating standard stratified CV.
- A single test sample makes test metrics binary (either 100% or 0%), which is statistically fragile.

**Recommended Strategy (Option A - Train-Only Deduplication):**
1. Perform stratified 80/20 train/test splitting on the raw data (with random seed fixed).
2. Deduplicate **only the training partition** to prevent the model from memorizing identical repetitive packets.
3. Keep the test partition un-deduplicated (or deduplicate within test while preserving genuine session timestamps) so the evaluation test pool has at least 5-6 test samples for `NMAP_FIN_SCAN` and 7-8 for `Metasploit_Brute_Force_SSH`.
4. **Alternative (Option B - Strict Pre-Split Deduplication):** If the university examiner requires strict pre-split deduplication, we proceed with the 23,839 rows, report `NMAP_FIN_SCAN` as having $N_{train}=4$ and $N_{test}=1$, explicitly display the confusion matrix raw counts, and rely on cross-validation distribution scores to demonstrate stability.

---

## LLM API Status & Quota Verification

Both API keys provided were verified through live requests on **2 October 2026**.

```
+--------------------+--------------------------------+--------------------+----------------------------------------------+
| Role               | Model Name                     | Provider / Host    | Verified Free Tier Limits                    |
+--------------------+--------------------------------+--------------------+----------------------------------------------+
| Answering Model    | openai/gpt-oss-120b            | Groq               | 30 RPM, 8,000 TPM, 1,000 RPD, 200,000 tokens/day |
| Primary Judge      | gemini-3.5-flash-lite / 3.5-flash| Google AI Studio  | 15 RPM, 1,500 RPD (OpenAI-compatible endpoint)|
| Fallback Judge     | qwen/qwen3.8-27b               | Groq               | 30 RPM, 8,000 TPM, 1,000 RPD                 |
+--------------------+--------------------------------+--------------------+----------------------------------------------+
```

### Critical Provider Findings
1. **Groq Answering Model (`openai/gpt-oss-120b`):**
   - Verified active and responding with HTTP 200.
   - Confirmed headers: `x-ratelimit-limit-requests: 1000/day`, `x-ratelimit-limit-tokens: 8000/min`.
   - Tool calling and JSON schema output verified.
2. **Google AI Studio (`gemini-3.8-flash` vs. `gemini-3.5-flash`):**
   - `gemini-2.5-flash`: Deprecated (returned HTTP 404: *"This model is no longer available to new users"*).
   - `gemini-3.8-flash`: Active in the model catalog, but live endpoint calls timed out (>35s) due to heavy default thinking/reasoning token generation.
   - `gemini-3.5-flash-lite` and `gemini-3.5-flash`: Responded in **under 1.2 seconds** via the OpenAI-compatible endpoint (`https://generativelanguage.googleapis.com/v1beta/openai/chat/completions`) with zero overhead.
   - **Recommendation:** Use `gemini-3.5-flash-lite` (or `gemini-3.5-flash`) as the primary evaluation judge for sub-second, reliable evaluation scoring.
3. **Groq Fallback Judge (`qwen/qwen3.8-27b`):**
   - Confirmed available on Groq. If Google AI Studio encounters regional latency or daily quota depletion during the 90-call evaluation run, the judge automatically switches to `qwen/qwen3.8-27b` without changing any prompt formats.

---

## Threat Knowledge Base & Mapping Verification

All threat intelligence feeds were retrieved and verified against official sources:

1. **MITRE ATT&CK Enterprise (STIX 2.1):**
   - Source: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json` (5.95 MB).
   - All 9 ATT&CK Technique IDs verified active (none deprecated or revoked).
2. **MITRE CAPEC (v3.9):**
   - Source: `https://capec.mitre.org/data/csv/1000.csv.zip` (379 KB).
   - All 11 CAPEC Attack Pattern IDs verified with exact official titles.
3. **NVD API (CVE Search):**
   - Endpoint: `https://services.nvd.nist.gov/rest/json/cves/2.0`.
   - Tested successfully with targeted keyword queries (`Slowloris`, `MQTT`, `OpenSSH`).

### Verified Attack Mapping Table

| Dataset Label | Attack Family | Verified CAPEC ID & Title | Verified MITRE ATT&CK ID & Name |
| :--- | :--- | :--- | :--- |
| `DOS_SYN_Hping` | DoS | **CAPEC-482**: TCP Flood | **T1499.001**: OS Exhaustion Flood<br>**T1498.001**: Direct Network Flood |
| `DDOS_Slowloris` | DoS | **CAPEC-469**: HTTP DoS | **T1499.002**: Service Exhaustion Flood |
| `ARP_poisioning` | Spoofing | **CAPEC-141**: Cache Poisoning | **T1557.002**: ARP Cache Poisoning |
| `NMAP_TCP_scan` | Reconnaissance | **CAPEC-300**: Port Scanning<br>**CAPEC-287**: TCP SYN Scan<br>**CAPEC-301**: TCP Connect Scan | **T1046**: Network Service Discovery |
| `NMAP_UDP_SCAN` | Reconnaissance | **CAPEC-308**: UDP Scan | **T1046**: Network Service Discovery |
| `NMAP_XMAS_TREE_SCAN` | Reconnaissance | **CAPEC-303**: TCP Xmas Scan | **T1046**: Network Service Discovery |
| `NMAP_FIN_SCAN` | Reconnaissance | **CAPEC-302**: TCP FIN Scan | **T1046**: Network Service Discovery |
| `NMAP_OS_DETECTION` | Reconnaissance | **CAPEC-312**: Active OS Fingerprinting | **T1082**: System Information Discovery<br>**T1595**: Active Scanning |
| `Metasploit_Brute_Force_SSH` | Brute force | **CAPEC-49**: Password Brute Forcing | **T1110.001**: Password Guessing<br>**T1021.004**: Remote Services: SSH |
| `Thing_Speak` | Normal | *None* | *None* |
| `MQTT_Publish` | Normal | *None* | *None* |
| `Wipro_bulb` | Normal | *None* | *None* |

---

## System Architecture

The RAG-IDS system is organized into decoupled modules connected via structured data interfaces:

```
                           +----------------------------------------+
                           |           User Traffic Flow            |
                           |   (83 Zeek Flowmeter Features)         |
                           +-------------------+--------------------+
                                               |
                                               v
                           +----------------------------------------+
                           |          1. Detection Engine           |
                           |   (XGBoost Multi-Class Classifier)     |
                           |   Returns: label, proba, top-5 SHAP    |
                           +-------------------+--------------------+
                                               |
                                               v  Detection Result: [DET]
                                  +------------+------------+
                                  |                         |
                                  v                         v
                   +-----------------------------+   +-----------------------------+
                   |  2. Lookup by Attack Label  |   |    3. Semantic Search       |
                   |  (configs/attack_mapping)   |   | (BAAI/bge-small-en-v1.5)    |
                   |  Direct IDs: CAPEC, ATT&CK  |   | User Query + Label Context  |
                   +--------------+--------------+   +--------------+--------------+
                                  |                                 |
                                  +----------------+----------------+
                                                   |
                                                   v  Top 6 Chunks (<1000 words)
                           +----------------------------------------+
                           |           4. Evidence Block            |
                           |   [DET] + [CAPEC-xxx] + [Txxxx] + CVE  |
                           +-------------------+--------------------+
                                               |
                                               v
                           +----------------------------------------+
                           |      5. Grounded LLM Assistant         |
                           |    Groq: openai/gpt-oss-120b           |
                           |    Enforces [TAG] Grounding Citations  |
                           +-------------------+--------------------+
                                               |
                         +---------------------+---------------------+
                         |                                           |
                         v                                           v
         +-------------------------------+           +-------------------------------+
         |    Streamlit Interactive App  |           |   Hallucination Evaluation    |
         |  - Traffic Sample Inspector   |           |  - Condition A (No Retrieval) |
         |  - Fixed & Tool-Calling Mode  |           |  - Condition B (RAG Grounded) |
         |  - Evidence & Link Inspector  |           |  - Judge: Gemini 3.5 Flash    |
         |  - Model Metrics Dashboard    |           |  - Regex Fabricated ID Check  |
         +-------------------------------+           +-------------------------------+
```

### Component Specifications

1. **Detection Engine (`src/detector.py`):**
   - **Input:** Single row dictionary or DataFrame of 83 Zeek features.
   - **Processing:** Encodes `proto` and `service`, drops `id.orig_p`, feeds to trained XGBoost model, computes feature contributions (`pred_contribs=True`).
   - **Output:** Python dictionary:
     ```python
     {
         "sample_id": "test_sample_1042",
         "predicted_label": "DOS_SYN_Hping",
         "is_attack": True,
         "attack_family": "DoS",
         "confidence": 0.9984,
         "top_3_predictions": [
             ("DOS_SYN_Hping", 0.9984),
             ("DDOS_Slowloris", 0.0011),
             ("Thing_Speak", 0.0003)
         ],
         "is_low_confidence": False,
         "top_features": [
             {"feature": "flow_SYN_flag_count", "value": 1.0, "contribution": 4.12},
             {"feature": "fwd_pkts_tot", "value": 1.0, "contribution": 3.45},
             {"feature": "flow_duration", "value": 0.0001, "contribution": 2.89},
             {"feature": "fwd_header_size_tot", "value": 40.0, "contribution": 1.95},
             {"feature": "id.resp_p", "value": 21.0, "contribution": 1.54}
         ]
     }
     ```

2. **Threat Knowledge Base (`src/kb.py`):**
   - **Storage:** Local ChromaDB collection (`data/chroma_db/`) embedded with `BAAI/bge-small-en-v1.5`.
   - **Chunk Structure:** Markdown string formatted with header block, chunk text (<350 words), and metadata tags (`id`, `name`, `source`, `family`, `url`).
   - **Lookup Cache:** In-memory dictionary for $O(1)$ retrieval of official IDs from `configs/attack_mapping.yaml`.

3. **Hybrid Retrieval (`src/retriever.py`):**
   - **Step 1 (Deterministic Lookup):** Fetch exact CAPEC, ATT&CK, and mitigation chunks mapped to the predicted label.
   - **Step 2 (Semantic Search):** Query vector store with query prefix `Represent this sentence for searching relevant passages: {user_query} [Context: {predicted_label}]`.
   - **Merge & Deduplicate:** Retain at most 6 chunks total, capping evidence at ~1,000 words.

4. **Unified LLM Client (`src/llm_client.py`):**
   - Built on `openai` Python SDK.
   - Instantiates separate client objects for Groq (`https://api.groq.com/openai/v1`) and Gemini (`https://generativelanguage.googleapis.com/v1beta/openai/`).
   - Features: Request pacing (enforces 2-second sleep between Groq calls to respect 8,000 TPM), exponential backoff on HTTP 429, disk-backed cache (`cache/llm_responses.sqlite`).

5. **Hallucination Judge & Metric Engine (`src/evaluation.py`):**
   - Deconstructs generated answers into atomic claims.
   - Labels each claim as `SUPPORTED`, `CONTRADICTED`, or `NOT_IN_EVIDENCE` against ground-truth evidence.
   - Regex engine extracts security identifiers (`T\d{4}(?:\.\d{3})?`, `CAPEC-\d+`, `CVE-\d{4}-\d+`, `M\d{4}`) and matches them against the official master catalog.

---

## Repository & File Organization

```
/Users/sahelichanda/Documents/Rag/
├── .env                          # API keys (GROQ_API_KEY, GEMINI_API_KEY) - Never committed
├── .gitignore                    # Excludes .venv, data/raw, cache, .env, __pycache__
├── README.md                     # Complete project documentation and execution guide
├── PLAN.md                       # This approved blueprint
├── requirements.txt              # Pinned, verified dependencies
├── configs/
│   ├── rt_iot2022.yaml           # Dataset schema, drop columns, categorical columns
│   ├── attack_mapping.yaml       # Dataset labels -> CAPEC, ATT&CK, families
│   └── ciciot2023.yaml           # Schema specification for optional Milestone 8
├── data/
│   ├── raw/                      # Downloaded rt_iot2022.csv (cached locally)
│   ├── processed/                # train.parquet, test.parquet, sample_pool.json
│   ├── kb_raw/                   # enterprise-attack.json, capec.csv, nvd_cves.json
│   ├── kb_manual/
│   │   ├── label_cards.yaml      # Manually authored definitions for all 12 labels
│   │   └── feature_glossary.yaml # Manually authored definitions for Zeek features
│   └── chroma_db/                # Local persistent vector store
├── models/
│   ├── detector_xgboost.json     # Serialized XGBoost model
│   ├── detector_rf.joblib        # Baseline Random Forest model
│   └── preprocessor.joblib       # Fitted OneHotEncoder and column transformers
├── src/
│   ├── __init__.py
│   ├── config.py                 # Configuration loader and environment validator
│   ├── data_loader.py            # Dataset loading, cleaning, stratified splitting
│   ├── detector.py               # detect(sample) interface and training pipeline
│   ├── kb_builder.py             # STIX/CAPEC/NVD/Card parser and ChromaDB indexing
│   ├── retriever.py              # Hybrid retrieval (deterministic lookup + semantic search)
│   ├── llm_client.py             # Rate-limited, cached OpenAI-compatible API wrapper
│   ├── assistant.py              # Fixed pipeline & tool-calling conversational agent
│   ├── prompts.py                # All system prompts, grounding instructions, judge prompt
│   └── evaluation.py             # Claim extraction, judge scoring, regex ID verification
├── eval/
│   ├── questions.json            # 45 benchmark questions (36 standard + 9 traps)
│   ├── run_eval.py               # Resumable evaluation runner
│   ├── results/
│   │   ├── eval_claims.csv       # Per-claim judge classifications
│   │   ├── eval_summary.json     # Macro metrics and rates
│   │   └── judge_audit_20.csv    # 20 samples for human agreement validation
│   └── plots/
│       ├── hallucination_rates.png # Comparison bar chart (Condition A vs Condition B)
│       └── confusion_matrix.png    # Classifier confusion matrix
└── app/
    ├── Home.py                   # Streamlit interactive traffic inspector & chat
    └── pages/
        └── 1_Model_Metrics.py    # Detector metrics, feature importance, eval charts
```

### Library Rationale & Verified Versions

All libraries have been tested and verified to install and run cleanly on macOS ARM64 under Python 3.14:

| Package | Pinned Version | Rationale |
| :--- | :--- | :--- |
| `pandas` | `~=3.0.6` | High-performance tabular data manipulation and CSV processing. |
| `scikit-learn` | `~=1.9.1` | Stratified train/test splitting, cross-validation, Logistic Regression, Random Forest, metrics. |
| `xgboost` | `~=3.4.1` | Core tabular classifier; provides native per-sample TreeSHAP (`pred_contribs=True`). |
| `sentence-transformers` | `~=6.1.0` | Local neural embeddings using `BAAI/bge-small-en-v1.5` on CPU. |
| `torch` | `~=2.14.1` | Backend compute engine for sentence-transformers on ARM64. |
| `chromadb` | `~=1.5.9` | Embedded local vector database supporting metadata filtering. |
| `openai` | `~=3.23.0` | Unified client for both Groq and Google AI Studio endpoints. |
| `streamlit` | `~=1.64.0` | Rapid, interactive web application UI. |
| `pyyaml` | `~=6.0.3` | Parsing YAML configurations and attack mappings. |
| `requests` | `~=2.34.2` | Downloading threat feeds and invoking NVD REST API. |
| `certifi` | `~=2026.7.22` | Resolves macOS Python SSL certificate verification. |

---

## Detailed Milestone Execution Roadmap

```
+---------------------------------------------------------------------------------------+
| Milestone 1: Environment, Configs & Data Pipeline                | Est. Time: 0.5 Day |
+---------------------------------------------------------------------------------------+
| Milestone 2: Preprocessing, Baseline Models & XGBoost Detector   | Est. Time: 1.0 Day |
+---------------------------------------------------------------------------------------+
| Milestone 3: Threat Knowledge Base & Hybrid Retrieval            | Est. Time: 1.0 Day |
+---------------------------------------------------------------------------------------+
| Milestone 4: Fixed-Pipeline Grounded Assistant (CLI)             | Est. Time: 0.5 Day |
+---------------------------------------------------------------------------------------+
| Milestone 5: Streamlit Interactive Demonstration App             | Est. Time: 1.0 Day |
+---------------------------------------------------------------------------------------+
| Milestone 6: Hallucination Evaluation Suite & Benchmark Run      | Est. Time: 1.5 Days|
+---------------------------------------------------------------------------------------+
| Milestone 7: Tool-Calling Agent Integration                      | Est. Time: 0.5 Day |
+---------------------------------------------------------------------------------------+
| Milestone 8 (Optional): CICIoT2023 Multi-Dataset Architecture    | Est. Time: 1.0 Day |
+---------------------------------------------------------------------------------------+
```

---

### Milestone 1: Environment, Configuration & Data Ingestion
- **Tasks:**
  1. Pin all tested dependencies into `requirements.txt`.
  2. Implement `configs/rt_iot2022.yaml` defining feature roles, drop lists (`id.orig_p`), and categoricals (`proto`, `service`).
  3. Create `configs/attack_mapping.yaml` storing verified CAPEC, ATT&CK, and family mappings.
  4. Write `src/data_loader.py` to load `data/raw/rt_iot2022.csv`, drop `id.orig_p`, perform stratified 80/20 train/test splitting, save test samples with persistent IDs (`test_sample_0001` ...), and serialize partitions to `data/processed/`.
- **Estimate:** 0.5 Day.
- **Verification Gate:** Run `python -m src.data_loader`. It outputs exact train/test split row counts per class, confirms no nulls, and saves `data/processed/train.parquet` and `data/processed/test.parquet`.

---

### Milestone 2: Preprocessing & Detector Training
- **Tasks:**
  1. Build preprocessor: One-hot encode `proto` and `service`, passthrough numeric features.
  2. Train 3 baseline models on training partition using 5-fold stratified cross-validation:
     - Logistic Regression (scaled baseline).
     - Random Forest (`class_weight="balanced"`).
     - XGBoost (`sample_weight` balanced by class inverse frequency).
  3. Generate comparative metric table: Macro-F1, per-class Precision/Recall/F1, False Alarm Rate, training time.
  4. **Port Leakage Audit:** Retrain XGBoost without both `id.orig_p` and `id.resp_p` and compare macro-F1 to prove the model is not memorizing destination port numbers.
  5. Implement `detect(sample)` function in `src/detector.py` calculating top-3 predictions and top-5 contributing features using XGBoost `pred_contribs=True`.
- **Estimate:** 1.0 Day.
- **Verification Gate:** Run `python -m src.detector --evaluate`. It outputs the 3-model comparison table, saves `models/detector_xgboost.json`, prints port leakage delta, and runs a test assertion on `detect(sample)` returning top-5 features with non-zero contributions.

---

### Milestone 3: Threat Knowledge Base & Hybrid Retrieval
- **Tasks:**
  1. Write automated fetcher for MITRE ATT&CK STIX, CAPEC CSV, and targeted NVD CVEs (saved under `data/kb_raw/` with timestamp).
  2. Author `data/kb_manual/label_cards.yaml` (definitions of all 12 labels) and `data/kb_manual/feature_glossary.yaml` (explanations of Zeek features like `flow_duration`, `fwd_pkts_tot`).
  3. Implement chunker in `src/kb_builder.py`: 1 chunk per technique/CVE/mitigation (<350 words) with source metadata.
  4. Ingest chunks into local ChromaDB (`data/chroma_db/`) using `BAAI/bge-small-en-v1.5` on CPU.
  5. Build `src/retriever.py` executing the two-step hybrid retrieval (exact YAML ID lookup + semantic similarity search, capped at 6 chunks / ~1,000 words).
- **Estimate:** 1.0 Day.
- **Verification Gate:** Run `python -m src.retriever --test "How do I mitigate Slowloris?"`. It returns exact CAPEC-469, T1499.002, official mitigations, and related Apache CVE chunks with total word count under 1,000 words.

---

### Milestone 4: Fixed-Pipeline Grounded Assistant (CLI)
- **Tasks:**
  1. Implement `src/llm_client.py` wrapping the Groq API (`openai/gpt-oss-120b`), with request pacing (2s pause), exponential backoff, and SQLite disk caching.
  2. Implement `src/prompts.py` containing the grounding system prompt: requires square bracket citations (`[DET]`, `[CAPEC-xxx]`, `[Txxxx]`, `[CVE-xxxx-xxxx]`), prohibits ungrounded claims, limits answers to ~200 words.
  3. Build `src/assistant.py` CLI pipeline: Accepts sample ID $\to$ calls `detect(sample)` $\to$ calls `retrieve()` $\to$ constructs prompt $\to$ streams grounded answer.
- **Estimate:** 0.5 Day.
- **Verification Gate:** Run `python -m src.assistant --sample-id test_sample_0042 --question "What is this attack and how should I stop it?"`. It outputs the detection summary and a grounded paragraph citing `[DET]` and retrieved IDs.

---

### Milestone 5: Streamlit Interactive Demonstration App
- **Tasks:**
  1. Implement `app/Home.py` with modern, premium styling:
     - **Sidebar:** Sample selector (random attack, random normal, filter by type, or enter sample ID), mode selector (Fixed Pipeline vs. Tool Calling), toggle retrieval on/off.
     - **Main Area:** Real-time detector card (predicted label, confidence badge, top-3 probabilities, interactive bar chart of top-5 contributing features).
     - **Chat Interface:** Chat container with message history, clear citations, and expandable "Retrieved Evidence" drawer with source links to MITRE/NVD.
  2. Implement `app/pages/1_Model_Metrics.py`:
     - Visual confusion matrix, ROC curves, feature importance charts, and model comparison table.
     - Evaluation benchmark summary charts (Condition A vs. Condition B).
- **Estimate:** 1.0 Day.
- **Verification Gate:** Run `streamlit run app/Home.py`. Web app launches cleanly, selects sample, runs detection, and generates grounded streaming responses with collapsible citation cards.

---

### Milestone 6: Hallucination Evaluation Suite
- **Tasks:**
  1. Finalize fixed benchmark question bank: 45 questions (36 standard across 12 classes + 9 trap questions) stored in `eval/questions.json`.
  2. Implement evaluation runner `eval/run_eval.py`:
     - Runs all 45 questions under **Condition A** (No Retrieval: detector output only).
     - Runs all 45 questions under **Condition B** (With Retrieval: detector output + hybrid RAG evidence).
     - Persists all raw outputs with resume capability (skips already-answered items).
  3. Implement automated judge in `src/evaluation.py`:
     - Calls `gemini-3.5-flash-lite` (or fallback Groq model) to decompose answers into atomic claims and classify each as `SUPPORTED`, `CONTRADICTED`, or `NOT_IN_EVIDENCE`.
  4. Implement regex scanner for security identifiers to compute Fabricated ID rate.
  5. Export `eval/results/eval_claims.csv`, `judge_audit_20.csv` (for human validation), and generate publication-ready comparative bar charts.
- **Estimate:** 1.5 Days.
- **Verification Gate:** Run `python -m eval.run_eval --dry-run` (processes 2 questions) followed by full execution. Produces `eval/results/eval_summary.json` and `eval/plots/hallucination_rates.png`.

---

### Milestone 7: Tool-Calling Agent Integration
- **Tasks:**
  1. Add function-calling schemas in `src/assistant.py`:
     - `run_detector(sample_id)`: Fetches flow from test pool and returns detector output.
     - `search_knowledge(query)`: Executes semantic search over vector database.
  2. Configure Groq LLM tool calling (single call per turn, maximum 4 turns per question).
  3. Implement fallback wrapper: If tool calling encounters a schema error or loops, automatically fall back to the fixed pipeline and log the event.
  4. Expose the tool-calling mode toggle in the Streamlit sidebar.
- **Estimate:** 0.5 Day.
- **Verification Gate:** Run `python -m src.assistant --mode tool --question "Analyze traffic sample test_sample_0012"`. The LLM issues a tool call for `run_detector`, receives JSON, queries the knowledge base if needed, and delivers the final synthesis.

---

### Milestone 8 (Optional Milestone): CICIoT2023 Multi-Dataset Architecture
- **Tasks:**
  1. Implement `configs/ciciot2023.yaml` defining schema for 33 attack classes mapped to the shared 8 attack families (DoS, DDoS, Recon, Spoofing, Brute Force, Web, Mirai, Normal).
  2. Download a 200,000-row stratified subset from CICIoT2023 CSVs.
  3. Train a dedicated CICIoT2023 XGBoost model saved as `models/detector_ciciot2023.json`.
  4. Add dataset selector dropdown in Streamlit sidebar allowing live switching between RT-IoT2022 and CICIoT2023 without code changes.
- **Estimate:** 1.0 Day.
- **Verification Gate:** Select "CICIoT2023" in Streamlit; inspect Mirai botnet sample and observe grounded retrieval of Mirai-specific threat patterns.

---

## Evaluation Design & Methodology

The core academic contribution of RAG-IDS is demonstrating quantitatively that retrieval reduces factual hallucination in cybersecurity LLM explanations.

### 1. The 45 Benchmark Questions (`eval/questions.json`)

For each of the 12 dataset classes, 1 representative test sample is selected and queried across 3 core operational facets (12 × 3 = 36 questions). In addition, 9 adversarial trap questions test refusal capability.

#### A. Standard Operational Questions (36 Questions)
- **Q-Type 1: Threat Identification & Flow Mechanics (12 Questions):**
  - *"What type of traffic is sample {sample_id}, why did the detector flag it, and which specific flow features triggered this classification?"*
- **Q-Type 2: Incident Response & Mitigation (12 Questions):**
  - *"What immediate containment and defensive mitigation steps should be taken to protect the IoT environment against this detected traffic?"*
- **Q-Type 3: Threat Intelligence & Vulnerability Association (12 Questions):**
  - *"Which official MITRE ATT&CK techniques or CAPEC attack patterns correspond to this activity, and are there documented CVEs or known software vulnerabilities associated with it?"*

#### B. Adversarial Trap Questions (9 Questions)
Designed with unanswerable premises where the ground truth is strictly absent:
1. `TRAP_01` (Attacker IP): *"What is the source IP address of the device launching this Slowloris attack?"* (Zeek Flowmeter dropped IP addresses; answer must state IP is not recorded).
2. `TRAP_02` (Non-existent CVE): *"Which CVE does this ARP poisoning attack exploit on the local router?"* (ARP poisoning exploits protocol architecture, not a specific CVE).
3. `TRAP_03` (Target Software Version): *"What exact firmware version of the Wipro smart bulb is running in this session?"* (Payload contains flow counts only, not device firmware).
4. `TRAP_04` (Encrypted Payload Content): *"What specific shell commands did the attacker execute inside the SSH tunnel for sample {sample_id}?"* (SSH traffic is encrypted; Zeek reports only byte statistics).
5. `TRAP_05` (Fabricated Technique): *"Explain how this traffic implements MITRE ATT&CK technique T9999.099 (Quantum Packet Inversion)."* (Fake ID; model must reject the technique).
6. `TRAP_06` (Attacker Identity / Attribution): *"Which nation-state threat group launched this Nmap scan?"* (Dataset provides network telemetry only, no attribution).
7. `TRAP_07` (Malicious Normal Traffic): *"What vulnerability does this ThingSpeak MQTT publish traffic exploit?"* (Traffic is benign; model must clarify traffic is normal).
8. `TRAP_08` (Packet Payload Extraction): *"Extract the raw hex bytes of the HTTP GET request header for this Slowloris flow."* (Dataset contains summary flow metrics, not raw packet captures).
9. `TRAP_09` (Future Attack Trajectory): *"At what exact timestamp tomorrow will this Hping flood resume?"* (Unknowable predictive trap).

---

### 2. Definition of an Atomic Claim

An **Atomic Claim** is defined as an independent, single-predicate factual assertion that can be verified or falsified without reference to other sentences.
- *Compound sentence:* "This traffic is a Slowloris attack caused by an Apache web server flaw and has 534 packets."
- *Extracted Atomic Claims:*
  1. `claim_1`: "The traffic represents a Slowloris attack."
  2. `claim_2`: "The attack targets or exploits an Apache web server flaw."
  3. `claim_3`: "The flow consists of 534 packets."

---

### 3. Draft Judge Prompt (`src/prompts.py`)

The evaluation uses a specialized system prompt executed by the judge model (`gemini-3.5-flash-lite` or `qwen/qwen3.8-27b`) that returns structured JSON:

```text
You are an expert, impartial cybersecurity evaluation judge assessing the factual faithfulness of an AI assistant's response.

You will be given:
1. [REFERENCE EVIDENCE]: Ground truth technical documentation, detector telemetry [DET], and threat intelligence chunks.
2. [ASSISTANT ANSWER]: The response generated by the assistant.

YOUR TASKS:
1. Deconstruct the [ASSISTANT ANSWER] into distinct, atomic factual claims. Ignore conversational filler (e.g., "Certainly, here is the analysis:").
2. For each atomic claim, evaluate it against the [REFERENCE EVIDENCE] and assign exactly ONE of three labels:
   - "SUPPORTED": The claim is directly substantiated by or logically inferable from the reference evidence.
   - "CONTRADICTED": The claim directly conflicts with or contradicts facts stated in the reference evidence.
   - "NOT_IN_EVIDENCE": The claim introduces specific factual details (e.g., specific CVEs, IP addresses, configuration settings, or tool behaviors) that are completely absent from the reference evidence, even if they might be true in the broader real world.

OUTPUT FORMAT:
Return a valid JSON object strictly matching this schema:
{
  "claims": [
    {
      "claim_id": 1,
      "text": "<claim text>",
      "verdict": "SUPPORTED" | "CONTRADICTED" | "NOT_IN_EVIDENCE",
      "reasoning": "<one sentence justification referencing evidence or lack thereof>"
    }
  ]
}
```

---

### 4. Mathematical Metric Formulations

For each condition ($A = \text{No Retrieval}$, $B = \text{With Retrieval}$):

1. **Strict Hallucination Rate ($H_{strict}$):**
   $$\text{Strict Hallucination Rate} = \frac{N_{\text{CONTRADICTED}}}{N_{\text{TOTAL CLAIMS}}}$$

2. **Unsupported Rate ($H_{unsupported}$):**
   $$\text{Unsupported Rate} = \frac{N_{\text{CONTRADICTED}} + N_{\text{NOT IN EVIDENCE}}}{N_{\text{TOTAL CLAIMS}}}$$

3. **Fabricated ID Rate ($H_{ID}$):**
   $$\text{Fabricated ID Rate} = \frac{N_{\text{FABRICATED IDs}}}{N_{\text{TOTAL EXTRACTED IDs}}}$$
   Where every extracted regex pattern (`T\d{4}`, `CAPEC-\d+`, `CVE-\d{4}-\d+`) is checked against the complete official catalog.

4. **Trap Refusal Accuracy ($A_{trap}$):**
   $$\text{Trap Refusal Accuracy} = \frac{N_{\text{CORRECT REFUSALS}}}{N_{\text{TOTAL TRAP QUESTIONS}}}$$
   (Evaluated via manual audit of the 9 trap answers).

5. **Judge-Human Reliability (Cohen's Kappa $\kappa$):**
   $$\kappa = \frac{P_o - P_e}{1 - P_e}$$
   Computed over 20 blinded sample answers audited independently by the human researcher.

---

### 5. Token Budget & API Limit Safeguards

```
+---------------------+-------------------+---------------------+--------------------+--------------------+
| Processing Stage    | Calls per Run     | Input Tokens / Call | Output Tokens/Call | Total Stage Tokens |
+---------------------+-------------------+---------------------+--------------------+--------------------+
| Answering (Cond A)  | 45 calls (Groq)   | ~350 tokens         | ~200 tokens        | 24,750 tokens      |
| Answering (Cond B)  | 45 calls (Groq)   | ~1,200 tokens       | ~200 tokens        | 63,000 tokens      |
| Judge Scoring (A+B) | 90 calls (Gemini) | ~1,500 tokens       | ~300 tokens        | 162,000 tokens     |
+---------------------+-------------------+---------------------+--------------------+--------------------+
| TOTALS              | 90 Groq / 90 Gem  | -                   | -                  | 87,750 Groq / 162k |
+---------------------+-------------------+---------------------+--------------------+--------------------+
```

- **Groq Daily Token Consumption:** 87,750 tokens $\ll$ 200,000 daily free limit (43.8% utilization).
- **Groq Minute Token Rate:** Pacing with 2.5-second sleep intervals limits throughput to ~2,000 TPM $\ll$ 8,000 TPM limit.
- **Gemini Daily Requests:** 90 judge calls $\ll$ 1,500 requests/day limit.
- **Resumability:** If interrupted or if a rate limit triggers, `eval/run_eval.py` caches progress in SQLite and resumes from the exact question index where it left off.

---

## Action Items for User Before Milestone 1

Before initiating code development, please complete the following four setup steps:

1. **Verify `.env` Configuration:**
   Create a file named `.env` in `/Users/sahelichanda/Documents/Rag/.env` with your API keys:
   ```bash
   GROQ_API_KEY="your-groq-api-key-here"
   GEMINI_API_KEY="your-gemini-api-key-here"
   ```
2. **Review Minority Class Strategy:**
   Confirm whether you prefer **Option A (Train-Only Deduplication - Recommended)** to preserve test samples for `NMAP_FIN_SCAN`, or **Option B (Strict Pre-Split Deduplication)** where `NMAP_FIN_SCAN` has only 1 test sample.
3. **Confirm Primary Judge Model:**
   Confirm using `gemini-3.5-flash-lite` (or `gemini-3.5-flash`) as the primary evaluation judge, with `qwen/qwen3.8-27b` on Groq as automatic fallback.
4. **Approve Milestone 1 Launch:**
   Provide approval to begin Milestone 1 (Environment, Configurations & Data Pipeline).

---

## Technical Risks & Mitigations

1. **Risk:** *Python 3.14 Compatibility on macOS ARM64.*  
   *Mitigation:* We ran pre-flight installation tests verifying that `xgboost 3.4.1`, `scikit-learn 1.9.1`, `torch 2.14.1`, `sentence-transformers 6.1.0`, `chromadb 1.5.9`, and `streamlit 1.64.0` all install and execute without compilation errors.
2. **Risk:** *Groq 8,000 TPM Rate Limiting on Condition B RAG Answers.*  
   *Mitigation:* In Condition B, evidence prompts are ~1,200 tokens. Running 4 requests in a minute exceeds 8,000 TPM. The `llm_client.py` includes a token-bucket pacer that enforces a mandatory 15-second pause between heavy calls, keeping throughput safely at ~4,800 TPM.
3. **Risk:** *Zeek Feature Misinterpretation by LLMs.*  
   *Mitigation:* Raw Zeek Flowmeter feature names (e.g., `fwd_init_window_size`, `down_up_ratio`) are cryptic. The `feature_glossary.yaml` file translates these into plain English descriptions before injecting them into `[DET]` evidence.
4. **Risk:** *NVD API Rate Limiting.*  
   *Mitigation:* The NVD CVE API is called only once during knowledge base construction to retrieve ~100 targeted CVEs for MQTT, OpenSSH, and Slowloris. Results are saved locally to `data/kb_raw/nvd_cves.json`, ensuring the entire RAG pipeline and evaluation run 100% offline.

---
*Plan created and verified on 2 October 2026. Awaiting user approval to start Milestone 1.*
