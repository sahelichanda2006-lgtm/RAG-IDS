"""
RAG-IDS: Interactive Streamlit Demonstration Application
Main Page: Live IoT Traffic Telemetry Inspector & Grounded Incident Response Chat.
"""

import os
import sys
import json
import random
from pathlib import Path
from typing import Dict, Any, List

import streamlit as st
import pandas as pd
import numpy as np
import altair as alt

# Ensure project root is in python path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.config import PROJECT_ROOT, get_dataset_config, get_attack_mapping
from src.detector import detect
from src.retriever import retrieve_threat_evidence
from src.assistant import ask_assistant

# Page Configuration
st.set_page_config(
    page_title="RAG-IDS | IoT Intrusion Detection & Threat Explanation",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for rich, polished aesthetics
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    .metric-card {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 18px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
    }
    .badge-attack {
        background-color: #ef4444;
        color: white;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-normal {
        background-color: #10b981;
        color: white;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-family {
        background-color: #3b82f6;
        color: white;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .citation-box {
        background-color: #1e1e2e;
        border-left: 4px solid #6366f1;
        padding: 10px 14px;
        border-radius: 4px;
        margin-top: 8px;
        font-size: 0.9rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data
def load_test_pool():
    """Load lightweight test sample index."""
    pool_path = PROJECT_ROOT / "data/processed/test_samples_pool.json"
    if not pool_path.exists():
        st.error("Test sample pool missing. Please run `python -m src.data_loader`.")
        return []
    with open(pool_path, "r", encoding="utf-8") as f:
        return json.load(f)


@st.cache_data
def load_test_data():
    """Load test parquet DataFrame."""
    test_path = PROJECT_ROOT / "data/processed/test.parquet"
    if not test_path.exists():
        st.error("Test partition missing. Please run `python -m src.data_loader`.")
        return None
    return pd.read_parquet(test_path).set_index("sample_id", drop=False)


# Initialize Session State
if "messages" not in st.session_state:
    st.session_state.messages = []
if "current_sample_id" not in st.session_state:
    st.session_state.current_sample_id = "sample_00004"
if "current_detection" not in st.session_state:
    st.session_state.current_detection = None

test_pool = load_test_pool()
test_df = load_test_data()

# ==============================================================================
# SIDEBAR CONTROLS
# ==============================================================================
st.sidebar.image(
    "https://img.icons8.com/fluency/96/shield.png", width=64
)
st.sidebar.title("RAG-IDS Controls")

st.sidebar.markdown("### 1. Dataset Selection")
dataset_choice = st.sidebar.selectbox(
    "Active Dataset",
    ["RT-IoT2022 (UCI #942)", "CICIoT2023 (Roadmap Milestone 8)"],
    index=0,
)
if "CICIoT2023" in dataset_choice:
    st.sidebar.info("CICIoT2023 is configured as an extensible roadmap milestone.")

st.sidebar.markdown("### 2. Traffic Flow Selection")
selection_mode = st.sidebar.radio(
    "Selection Strategy",
    ["Filter by Attack Type", "Random Attack Flow", "Random Benign Flow", "Direct Sample ID"],
)

selected_sample_id = st.session_state.current_sample_id

if selection_mode == "Filter by Attack Type" and test_pool:
    labels_available = sorted(list(set(item["label"] for item in test_pool)))
    chosen_label = st.sidebar.selectbox("Select Traffic Label", labels_available, index=labels_available.index("DDOS_Slowloris") if "DDOS_Slowloris" in labels_available else 0)
    filtered = [item["sample_id"] for item in test_pool if item["label"] == chosen_label]
    if filtered:
        selected_sample_id = st.sidebar.selectbox("Select Sample ID", filtered)

elif selection_mode == "Random Attack Flow" and test_pool:
    attacks_pool = [item["sample_id"] for item in test_pool if item["attack_family"] != "Normal"]
    if st.sidebar.button("🎲 Pick Random Attack", use_container_width=True):
        selected_sample_id = random.choice(attacks_pool)

elif selection_mode == "Random Benign Flow" and test_pool:
    normal_pool = [item["sample_id"] for item in test_pool if item["attack_family"] == "Normal"]
    if st.sidebar.button("🌱 Pick Random Normal Flow", use_container_width=True):
        selected_sample_id = random.choice(normal_pool)

elif selection_mode == "Direct Sample ID":
    selected_sample_id = st.sidebar.text_input("Enter Sample ID", value=st.session_state.current_sample_id)

st.session_state.current_sample_id = selected_sample_id

st.sidebar.markdown("### 3. Assistant Mode")
assistant_mode = st.sidebar.selectbox(
    "Execution Pipeline",
    ["Fixed Pipeline (Detect -> Retrieve -> Answer)", "Autonomous Tool Calling (LLM Agent)"],
    index=0,
)
mode_flag = "tool" if "Tool Calling" in assistant_mode else "fixed"

st.sidebar.markdown("### 4. Retrieval Grounding (RAG)")
retrieval_toggle = st.sidebar.toggle(
    "Enable Threat RAG Retrieval",
    value=True,
    help="When enabled (Condition B), answers are grounded with MITRE ATT&CK, CAPEC, and CVE evidence tags.",
)

st.sidebar.markdown("---")
st.sidebar.caption("RAG-IDS Prototype | Model: XGBoost + Groq gpt-oss-120b | Local ChromaDB")

# ==============================================================================
# MAIN PAGE: DETECTION DASHBOARD & CHAT
# ==============================================================================
st.title("🛡️ RAG-IDS: IoT Intrusion Detection & Threat Explanation")
st.markdown(
    "Pairing a high-performance **XGBoost tabular intrusion detector** with **Retrieval-Augmented Threat Intelligence** from MITRE ATT&CK, CAPEC, and NVD CVEs."
)

if test_df is not None and selected_sample_id in test_df.index:
    sample_row = test_df.loc[selected_sample_id]
    detection = detect(sample_row)
    st.session_state.current_detection = detection
else:
    st.error(f"Sample ID `{selected_sample_id}` not found in test pool.")
    st.stop()

# --- TOP ROW: DETECTION TELEMETRY CARD ---
col1, col2, col3, col4 = st.columns([2, 1.5, 1.5, 3])

with col1:
    st.markdown("#### Sample Identification")
    badge_cls = "badge-attack" if detection["is_attack"] else "badge-normal"
    status_text = "ATTACK DETECTED" if detection["is_attack"] else "BENIGN TRAFFIC"
    st.markdown(f"**ID**: `{selected_sample_id}`")
    st.markdown(f"<span class='{badge_cls}'>{status_text}</span> <span class='badge-family'>{detection['attack_family']}</span>", unsafe_allow_html=True)
    st.markdown(f"**Predicted Label**: `{detection['predicted_label']}`")

with col2:
    st.markdown("#### Model Confidence")
    conf = detection["confidence"]
    st.metric(label="Detector Confidence", value=f"{conf:.2%}")
    st.progress(conf)
    if detection["is_low_confidence"]:
        st.warning("⚠️ Low Confidence (< 60%)")

with col3:
    st.markdown("#### Top Predictions")
    for lbl, prob in detection["top_3_predictions"]:
        st.write(f"- **{lbl}**: `{prob:.1%}`")

with col4:
    st.markdown("#### Key Network Attributes")
    proto = str(sample_row.get("proto", "-"))
    service = str(sample_row.get("service", "-"))
    dest_p = str(sample_row.get("id.resp_p", "-"))
    fwd_pkts = str(sample_row.get("fwd_pkts_tot", "-"))
    flow_dur = str(sample_row.get("flow_duration", "-"))
    st.markdown(f"- **Protocol / Service**: `{proto.upper()}` / `{service}`")
    st.markdown(f"- **Destination Port**: `{dest_p}` | **Packets**: `{fwd_pkts}`")
    st.markdown(f"- **Flow Duration**: `{flow_dur}` μs")

# --- SECOND ROW: TREESHAP FEATURE IMPORTANCE BAR CHART ---
with st.expander("🔍 **Explainable AI (TreeSHAP): Top 5 Features Driving This Prediction**", expanded=True):
    feat_data = pd.DataFrame(detection["top_features"])
    feat_data["abs_contribution"] = feat_data["contribution"].abs()

    chart = (
        alt.Chart(feat_data)
        .mark_bar(cornerRadius=4)
        .encode(
            x=alt.X("contribution:Q", title="SHAP Log-Odds Contribution (Impact on Prediction)"),
            y=alt.Y("feature:N", sort="-x", title="Zeek Flow Feature"),
            color=alt.condition(
                alt.datum.contribution > 0,
                alt.value("#3b82f6"),  # Positive push
                alt.value("#ef4444"),  # Negative push
            ),
            tooltip=["feature", "value", "contribution"],
        )
        .properties(height=200)
    )
    st.altair_chart(chart, use_container_width=True)
    st.caption("Blue bars push the model toward this classification. Hover to view the exact flow metric value.")

# --- THIRD ROW: RETRIEVED THREAT INTELLIGENCE EVIDENCE DRAWER ---
if retrieval_toggle:
    with st.expander("📚 **Retrieved Threat Evidence (MITRE ATT&CK, CAPEC, NVD)**", expanded=False):
        evidence_data = retrieve_threat_evidence(
            query="Threat identification, mechanics, mitigations and related vulnerabilities",
            detection_result=detection,
        )
        st.markdown(f"**Retrieved Chunks**: `{evidence_data['chunk_count']}` | **Word Count**: `{evidence_data['total_words']}`")
        for chunk in evidence_data["chunks"]:
            cid = chunk["id"]
            cname = chunk["name"]
            src = chunk["source"]
            url = chunk.get("url", "")
            url_link = f"[Official Reference]({url})" if url and url.startswith("http") else "Local Reference"
            st.markdown(
                f"""
                <div class="citation-box">
                    <strong>[{cid}] {cname}</strong> ({src.upper()}) &bull; {url_link}
                    <div style="margin-top:6px; color:#cbd5e1;">{chunk['text'][:350]}...</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

# ==============================================================================
# INTERACTIVE CHAT INTERFACE
# ==============================================================================
st.markdown("### 💬 Grounded Incident Response Assistant")

# Quick prompt buttons
col_q1, col_q2, col_q3 = st.columns(3)
with col_q1:
    if st.button("❓ What is this attack and why was it flagged?", use_container_width=True):
        st.session_state.prompt_input = "What is this traffic, why did the detector flag it, and which features drove the classification?"
with col_q2:
    if st.button("🛡️ What defensive mitigations should I take?", use_container_width=True):
        st.session_state.prompt_input = "What immediate containment and defensive mitigation steps should be taken against this detected traffic?"
with col_q3:
    if st.button("🔗 Which ATT&CK and CAPEC IDs apply?", use_container_width=True):
        st.session_state.prompt_input = "Which official MITRE ATT&CK techniques or CAPEC attack patterns describe this activity, and are there known CVEs?"

# Display message history
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# User chat input
user_prompt = st.chat_input("Ask a question about this traffic sample...")
if "prompt_input" in st.session_state and st.session_state.prompt_input:
    user_prompt = st.session_state.prompt_input
    st.session_state.prompt_input = None

if user_prompt:
    # Append and display user message
    st.session_state.messages.append({"role": "user", "content": user_prompt})
    with st.chat_message("user"):
        st.markdown(user_prompt)

    # Generate assistant answer
    with st.chat_message("assistant"):
        with st.spinner("Analyzing traffic telemetry and consulting threat knowledge base..."):
            res = ask_assistant(
                question=user_prompt,
                sample_id=selected_sample_id,
                retrieval_enabled=retrieval_toggle,
                mode=mode_flag,
            )
            answer_text = res["answer"]
            st.markdown(answer_text)

            # Metadata footer
            mode_badge = "Tool Calling" if res["mode"] == "tool" else "Fixed Pipeline"
            rag_badge = "RAG Grounded" if res["retrieval_enabled"] else "No Retrieval"
            st.caption(f"Mode: `{mode_badge}` &bull; Condition: `{rag_badge}` &bull; Answering Model: `Groq/gpt-oss-120b`")

    st.session_state.messages.append({"role": "assistant", "content": answer_text})
