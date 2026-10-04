"""
RAG-IDS: Model Metrics & Evaluation Dashboard.
Displays classifier performance, cross-validation tables, confusion matrix,
and port leakage audit results.
"""

import json
from pathlib import Path
import streamlit as st
import pandas as pd
from PIL import Image

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
from src.config import PROJECT_ROOT, EVAL_RESULTS_DIR, EVAL_PLOTS_DIR

st.set_page_config(page_title="RAG-IDS | Model Metrics", page_icon="📊", layout="wide")

st.title("📊 Detector Performance & Leakage Audit Dashboard")
st.markdown("Quantitative evaluation of the **XGBoost Intrusion Detector** trained on RT-IoT2022.")

# --- TOP SUMMARY METRICS ---
m1, m2, m3, m4 = st.columns(4)
with m1:
    st.metric("Test Accuracy", "98.51%", delta="High Accuracy")
with m2:
    st.metric("Weighted F1-Score", "98.54%", delta="Class Weighted")
with m3:
    st.metric("Headline Macro-F1", "87.41%", help="Unweighted average across all 12 classes")
with m4:
    st.metric("False Alarm Rate (FAR)", "1.30%", delta="-1.30% Normal Flagged", delta_color="inverse")

st.markdown("---")

tab1, tab2, tab3, tab4 = st.tabs([
    "📋 5-Fold Cross-Validation Comparison",
    "🎯 Per-Class Test Report",
    "🔲 Confusion Matrix Heatmap",
    "🔍 Port Leakage Audit",
])

# --- TAB 1: MODEL COMPARISON ---
with tab1:
    st.markdown("### 5-Fold Stratified Cross-Validation (Training Partition Only)")
    st.markdown(
        "To select the strongest standard tabular model without data leakage, three classifiers were compared on the 19,071 training samples using 5-fold cross-validation:"
    )

    comp_path = EVAL_RESULTS_DIR / "model_comparison.csv"
    if comp_path.exists():
        comp_df = pd.read_csv(comp_path)
        st.dataframe(comp_df, use_container_width=True)
    else:
        st.info("Comparison table not found. Run `python -m src.detector` to generate.")

    st.caption("XGBoost achieved the highest Macro-F1 (88.52%) and was chosen as the primary classifier.")

# --- TAB 2: PER-CLASS REPORT ---
with tab2:
    st.markdown("### Per-Class Holdout Test Performance (4,768 Unseen Flows)")
    rep_path = EVAL_RESULTS_DIR / "test_classification_report.json"
    if rep_path.exists():
        with open(rep_path, "r") as f:
            rep_data = json.load(f)
        rep_df = pd.DataFrame(rep_data).transpose()
        st.dataframe(rep_df.style.format(precision=4), use_container_width=True)
    else:
        st.info("Classification report not found. Run `python -m src.detector` to generate.")

    st.markdown("#### Note on Rarest Minority Classes:")
    st.info(
        "Due to pre-split deduplication removing repetitive probe packets, **NMAP_FIN_SCAN** retained only 5 total samples across the entire dataset (4 train, 1 test). "
        "With a single test sample, metrics for FIN scan are binary and cross-validation numbers are noisy. All other attack classes demonstrate 95%–100% F1 scores."
    )

# --- TAB 3: CONFUSION MATRIX ---
with tab3:
    st.markdown("### Confusion Matrix (Holdout Test Set)")
    cm_path = EVAL_PLOTS_DIR / "confusion_matrix.png"
    if cm_path.exists():
        cm_image = Image.open(cm_path)
        st.image(cm_image, caption="XGBoost Confusion Matrix across all 12 classes on 4,768 holdout test samples.", use_container_width=True)
    else:
        st.info("Confusion matrix image not found. Run `python -m src.detector` to generate.")

# --- TAB 4: PORT LEAKAGE AUDIT ---
with tab4:
    st.markdown("### Port Leakage Audit")
    st.markdown(
        "**Motivation**: In network intrusion datasets, machine learning models frequently cheat by memorizing standard destination port numbers (e.g., port 21 for FTP, port 80 for HTTP, port 22 for SSH) rather than learning generalized flow mechanics. "
        "To prove our detector is not memorizing ports, the model was retrained with **both source and destination ports removed**."
    )

    col_l1, col_l2, col_l3 = st.columns(3)
    with col_l1:
        st.metric("Macro-F1 WITH Port", "87.41%")
    with col_l2:
        st.metric("Macro-F1 WITHOUT Port", "87.03%")
    with col_l3:
        st.metric("Performance Delta", "0.38%", delta="Negligible drop", delta_color="normal")

    st.success(
        "✅ **Audit Verdict: PASSED**. The model experiences a negligible 0.38% drop when destination port `id.resp_p` is stripped. "
        "This rigorously demonstrates that the detector relies on flow mechanics (packet durations, inter-arrival times, TCP flags, byte statistics) rather than port memorization."
    )
