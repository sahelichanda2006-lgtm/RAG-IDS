"""
Machine Learning Intrusion Detection Engine for RAG-IDS.
Trains Logistic Regression, Random Forest, and XGBoost with 5-fold Stratified CV.
Provides the detect(sample) interface with TreeSHAP feature attribution.
"""

import os
import sys
import json
import time
import logging
from pathlib import Path
from typing import Dict, Any, List, Tuple, Union

import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.preprocessing import OneHotEncoder, StandardScaler, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    confusion_matrix,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.utils.class_weight import compute_sample_weight
import xgboost as xgb

from src.config import (
    PROJECT_ROOT,
    MODELS_DIR,
    EVAL_RESULTS_DIR,
    EVAL_PLOTS_DIR,
    get_dataset_config,
    get_attack_mapping,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("detector")


class FlowPreprocessor:
    """
    Preprocessor that One-Hot Encodes categorical features (proto, service)
    and passes through numeric flow statistics.
    """

    def __init__(self, categorical_cols: List[str], scale_numeric: bool = False):
        self.categorical_cols = categorical_cols
        self.scale_numeric = scale_numeric
        self.column_transformer = None
        self.label_encoder = LabelEncoder()
        self.feature_names_out = []
        self.numeric_cols = []

    def fit(self, X: pd.DataFrame, y: pd.Series):
        """Fit feature encoders and target label encoder."""
        self.label_encoder.fit(y)
        self.numeric_cols = [c for c in X.columns if c not in self.categorical_cols]

        transformers = [
            (
                "cat",
                OneHotEncoder(handle_unknown="ignore", sparse_output=False),
                self.categorical_cols,
            )
        ]
        if self.scale_numeric:
            transformers.append(("num", StandardScaler(), self.numeric_cols))
        else:
            transformers.append(("num", "passthrough", self.numeric_cols))

        self.column_transformer = ColumnTransformer(
            transformers=transformers, remainder="drop"
        )
        self.column_transformer.fit(X)

        # Reconstruct output feature names
        cat_encoder = self.column_transformer.named_transformers_["cat"]
        cat_features = cat_encoder.get_feature_names_out(self.categorical_cols).tolist()
        self.feature_names_out = cat_features + self.numeric_cols
        return self

    def transform_X(self, X: pd.DataFrame) -> np.ndarray:
        """Transform features DataFrame into numeric matrix."""
        return self.column_transformer.transform(X)

    def transform_y(self, y: pd.Series) -> np.ndarray:
        """Transform string labels to integer classes."""
        return self.label_encoder.transform(y)

    def inverse_transform_y(self, y_encoded: np.ndarray) -> np.ndarray:
        """Transform integer classes back to string labels."""
        return self.label_encoder.inverse_transform(y_encoded)

    def save(self, file_path: Path):
        """Persist preprocessor to disk using standard sklearn objects."""
        payload = {
            "column_transformer": self.column_transformer,
            "label_encoder": self.label_encoder,
            "feature_names_out": self.feature_names_out,
            "categorical_cols": self.categorical_cols,
            "scale_numeric": self.scale_numeric,
        }
        joblib.dump(payload, file_path)

    @classmethod
    def load(cls, file_path: Path) -> "FlowPreprocessor":
        """Load preprocessor from disk."""
        payload = joblib.load(file_path)
        inst = cls(
            categorical_cols=payload["categorical_cols"],
            scale_numeric=payload["scale_numeric"],
        )
        inst.column_transformer = payload["column_transformer"]
        inst.label_encoder = payload["label_encoder"]
        inst.feature_names_out = payload["feature_names_out"]
        return inst


def evaluate_model_cv(
    model_name: str,
    model_fn,
    X_df: pd.DataFrame,
    y_series: pd.Series,
    n_splits: int = 5,
    scale_numeric: bool = False,
) -> Dict[str, Any]:
    """
    Evaluate a model using Stratified 5-Fold Cross Validation on training data only.
    """
    logger.info(f"Running {n_splits}-fold Stratified CV for: {model_name}...")
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)

    f1_scores = []
    precision_scores = []
    recall_scores = []
    fit_times = []
    per_class_f1_folds = []

    cat_cols = ["proto", "service"]

    for fold_idx, (train_idx, val_idx) in enumerate(skf.split(X_df, y_series)):
        t0 = time.time()
        X_tr, y_tr = X_df.iloc[train_idx], y_series.iloc[train_idx]
        X_va, y_va = X_df.iloc[val_idx], y_series.iloc[val_idx]

        prep = FlowPreprocessor(categorical_cols=cat_cols, scale_numeric=scale_numeric)
        prep.fit(X_tr, y_tr)

        X_tr_proc = prep.transform_X(X_tr)
        y_tr_proc = prep.transform_y(y_tr)
        X_va_proc = prep.transform_X(X_va)
        y_va_proc = prep.transform_y(y_va)

        model = model_fn()
        if model_name == "XGBoost":
            sample_weights = compute_sample_weight("balanced", y_tr_proc)
            model.fit(X_tr_proc, y_tr_proc, sample_weight=sample_weights)
        else:
            model.fit(X_tr_proc, y_tr_proc)

        elapsed = time.time() - t0
        fit_times.append(elapsed)

        preds = model.predict(X_va_proc)

        f1_scores.append(f1_score(y_va_proc, preds, average="macro", zero_division=0))
        precision_scores.append(
            precision_score(y_va_proc, preds, average="macro", zero_division=0)
        )
        recall_scores.append(
            recall_score(y_va_proc, preds, average="macro", zero_division=0)
        )

        # Per class F1 for tracking rare classes
        report_dict = classification_report(
            y_va_proc,
            preds,
            target_names=[str(c) for c in prep.label_encoder.classes_],
            output_dict=True,
            zero_division=0,
        )
        per_class_f1_folds.append(report_dict)

    result = {
        "model": model_name,
        "macro_f1_mean": float(np.mean(f1_scores)),
        "macro_f1_std": float(np.std(f1_scores)),
        "precision_mean": float(np.mean(precision_scores)),
        "recall_mean": float(np.mean(recall_scores)),
        "avg_fit_time_sec": float(np.mean(fit_times)),
        "per_class_folds": per_class_f1_folds,
    }
    logger.info(
        f"[{model_name}] Macro-F1: {result['macro_f1_mean']:.4f} ± {result['macro_f1_std']:.4f} "
        f"(Avg Training Time: {result['avg_fit_time_sec']:.2f}s)"
    )
    return result


def train_and_evaluate_all():
    """
    Main training workflow:
    1. 5-fold CV comparison (Logistic Regression, Random Forest, XGBoost).
    2. Final XGBoost model training on complete training set.
    3. Holdout test evaluation with confusion matrix & false alarm rate.
    4. Port leakage check (retrain without destination port).
    """
    config = get_dataset_config("rt_iot2022")
    train_path = PROJECT_ROOT / config["processed_train_path"]
    test_path = PROJECT_ROOT / config["processed_test_path"]

    logger.info(f"Loading preprocessed partitions from {train_path} and {test_path}...")
    train_df = pd.read_parquet(train_path)
    test_df = pd.read_parquet(test_path)

    label_col = config["label_column"]
    cat_cols = config.get("categorical_columns", ["proto", "service"])

    # Separate features and target
    X_train = train_df.drop(columns=[label_col])
    y_train = train_df[label_col]

    # Test features (drop sample_id and label)
    sample_ids_test = test_df["sample_id"]
    X_test = test_df.drop(columns=[label_col, "sample_id"])
    y_test = test_df[label_col]

    # --- Step 1: Model Comparison with 5-Fold Stratified Cross-Validation ---
    print("\n" + "=" * 75)
    print("STEP 1: 5-FOLD STRATIFIED CROSS-VALIDATION (Training Partition Only)")
    print("=" * 75)

    models_to_test = [
        (
            "Logistic Regression",
            lambda: LogisticRegression(
                class_weight="balanced", max_iter=500, random_state=42
            ),
            True,  # Scale numeric features
        ),
        (
            "Random Forest",
            lambda: RandomForestClassifier(
                n_estimators=100,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
            ),
            False,
        ),
        (
            "XGBoost",
            lambda: xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                eval_metric="mlogloss",
                n_jobs=-1,
            ),
            False,
        ),
    ]

    cv_results = []
    for name, fn, scale in models_to_test:
        res = evaluate_model_cv(name, fn, X_train, y_train, scale_numeric=scale)
        cv_results.append(res)

    # Comparison summary table
    comp_rows = []
    for r in cv_results:
        comp_rows.append(
            {
                "Model": r["model"],
                "Macro F1 (Mean ± Std)": f"{r['macro_f1_mean']:.4f} ± {r['macro_f1_std']:.4f}",
                "Precision": f"{r['precision_mean']:.4f}",
                "Recall": f"{r['recall_mean']:.4f}",
                "Fit Time (s)": f"{r['avg_fit_time_sec']:.2f}",
            }
        )
    comp_table = pd.DataFrame(comp_rows)
    print("\n" + comp_table.to_string(index=False) + "\n")
    comp_table.to_csv(EVAL_RESULTS_DIR / "model_comparison.csv", index=False)

    # --- Step 2: Train Final Model (XGBoost) on All Training Data ---
    print("=" * 75)
    print("STEP 2: TRAINING FINAL PRODUCTION MODEL (XGBoost)")
    print("=" * 75)

    preprocessor = FlowPreprocessor(categorical_cols=cat_cols, scale_numeric=False)
    preprocessor.fit(X_train, y_train)

    X_train_proc = preprocessor.transform_X(X_train)
    y_train_proc = preprocessor.transform_y(y_train)
    X_test_proc = preprocessor.transform_X(X_test)
    y_test_proc = preprocessor.transform_y(y_test)

    # Save fitted preprocessor
    prep_path = MODELS_DIR / "preprocessor.joblib"
    preprocessor.save(prep_path)
    logger.info(f"Saved preprocessor to {prep_path}")

    # Train final XGBoost model
    xgb_model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
        eval_metric="mlogloss",
        n_jobs=-1,
    )
    sample_weights = compute_sample_weight("balanced", y_train_proc)
    xgb_model.fit(X_train_proc, y_train_proc, sample_weight=sample_weights)

    # Save XGBoost booster
    model_path = MODELS_DIR / "detector_xgboost.json"
    xgb_model.save_model(str(model_path))
    logger.info(f"Saved XGBoost model to {model_path}")

    # Also fit Random Forest baseline as persistent artifact
    rf_model = RandomForestClassifier(
        n_estimators=100, class_weight="balanced", random_state=42, n_jobs=-1
    )
    rf_model.fit(X_train_proc, y_train_proc)
    joblib.dump(rf_model, MODELS_DIR / "detector_rf.joblib")

    # --- Step 3: Single Holdout Test Evaluation ---
    print("\n" + "=" * 75)
    print("STEP 3: HOLDOUT TEST SET EVALUATION (XGBoost Final)")
    print("=" * 75)

    test_preds_proc = xgb_model.predict(X_test_proc)
    test_preds_labels = preprocessor.inverse_transform_y(test_preds_proc)

    test_macro_f1 = f1_score(y_test_proc, test_preds_proc, average="macro")
    print(f"HEADLINE METRIC: Macro-F1 = {test_macro_f1:.4%}\n")

    # Detailed Per-Class Report
    class_names = preprocessor.label_encoder.classes_.tolist()
    rep_dict = classification_report(
        y_test,
        test_preds_labels,
        target_names=class_names,
        output_dict=True,
        zero_division=0,
    )
    rep_df = pd.DataFrame(rep_dict).transpose()
    print("PER-CLASS CLASSIFICATION REPORT:")
    print(rep_df.round(4).to_string())

    with open(EVAL_RESULTS_DIR / "test_classification_report.json", "w") as f:
        json.dump(rep_dict, f, indent=2)

    # Confusion Matrix
    cm = confusion_matrix(y_test, test_preds_labels, labels=class_names)
    cm_df = pd.DataFrame(cm, index=class_names, columns=class_names)
    cm_df.to_csv(EVAL_RESULTS_DIR / "confusion_matrix.csv")

    plt.figure(figsize=(12, 10))
    sns.heatmap(cm_df, annot=True, fmt="d", cmap="Blues", cbar=True)
    plt.title(f"XGBoost Confusion Matrix (Holdout Test Set, Macro-F1: {test_macro_f1:.4f})")
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")
    plt.xticks(rotation=45, ha="right")
    plt.yticks(rotation=0)
    plt.tight_layout()
    cm_plot_path = EVAL_PLOTS_DIR / "confusion_matrix.png"
    plt.savefig(cm_plot_path, dpi=300)
    plt.close()
    logger.info(f"Saved confusion matrix plot to {cm_plot_path}")

    # False Alarm Rate (Normal traffic flagged as an attack)
    family_map = config.get("label_to_family", {})
    normal_labels = [k for k, v in family_map.items() if v == "Normal"]

    normal_mask = y_test.isin(normal_labels)
    total_normal = int(normal_mask.sum())
    normal_preds = pd.Series(test_preds_labels)[normal_mask.values]
    false_alarms = int((~normal_preds.isin(normal_labels)).sum())
    far = (false_alarms / total_normal) if total_normal > 0 else 0.0

    print(f"\nFalse Alarm Rate (FAR): {far:.4%} ({false_alarms} / {total_normal} normal flows flagged as attack)")

    # Rare classes notice
    print("\nNote on Rarest Classes:")
    for rare_cls in ["NMAP_FIN_SCAN", "Metasploit_Brute_Force_SSH"]:
        if rare_cls in rep_dict:
            metrics = rep_dict[rare_cls]
            print(
                f"  - {rare_cls}: Support in test = {int(metrics['support'])}, "
                f"Precision = {metrics['precision']:.2f}, Recall = {metrics['recall']:.2f}, F1 = {metrics['f1-score']:.2f}"
            )
    print("  (Due to pre-split deduplication compressing identical probe packets, minority test samples are scarce and metrics are high-variance).")

    # --- Step 4: Port Leakage Audit ---
    print("\n" + "=" * 75)
    print("STEP 4: PORT LEAKAGE AUDIT (Retrain Without Destination Port)")
    print("=" * 75)
    dest_col = config.get("destination_port_column", "id.resp_p")
    if dest_col in X_train.columns:
        X_train_no_port = X_train.drop(columns=[dest_col])
        X_test_no_port = X_test.drop(columns=[dest_col])

        prep_np = FlowPreprocessor(categorical_cols=cat_cols, scale_numeric=False)
        prep_np.fit(X_train_no_port, y_train)

        X_tr_np_proc = prep_np.transform_X(X_train_no_port)
        X_te_np_proc = prep_np.transform_X(X_test_no_port)

        xgb_np = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            random_state=42,
            eval_metric="mlogloss",
            n_jobs=-1,
        )
        xgb_np.fit(X_tr_np_proc, y_train_proc, sample_weight=sample_weights)
        preds_np = xgb_np.predict(X_te_np_proc)
        f1_no_port = f1_score(y_test_proc, preds_np, average="macro")

        print(f"Macro-F1 WITH destination port:    {test_macro_f1:.4%}")
        print(f"Macro-F1 WITHOUT destination port: {f1_no_port:.4%}")
        delta = test_macro_f1 - f1_no_port
        print(f"Delta (Performance drop):          {delta:.4%}")
        if delta < 0.03:
            print("Audit Verdict: PASSED. Model relies primarily on flow statistics (durations, flags, byte sizes) rather than memorizing destination port numbers.")
        else:
            print(f"Audit Verdict: Observable port reliance (drop of {delta:.2%}).")

    print("\n" + "=" * 75)
    print("DETECTOR PIPELINE TRAINING COMPLETE")
    print("=" * 75 + "\n")


# Global model cache for detect()
_GLOBAL_MODEL = None
_GLOBAL_PREPROCESSOR = None
_GLOBAL_ATTACK_MAPPING = None


def load_detector():
    """Load cached preprocessor and XGBoost model for fast inference."""
    global _GLOBAL_MODEL, _GLOBAL_PREPROCESSOR, _GLOBAL_ATTACK_MAPPING
    if _GLOBAL_MODEL is None:
        prep_path = MODELS_DIR / "preprocessor.joblib"
        model_path = MODELS_DIR / "detector_xgboost.json"

        if not prep_path.exists() or not model_path.exists():
            raise FileNotFoundError(
                f"Model or preprocessor missing. Please run `python -m src.detector` first."
            )

        _GLOBAL_PREPROCESSOR = FlowPreprocessor.load(prep_path)
        _GLOBAL_MODEL = xgb.XGBClassifier()
        _GLOBAL_MODEL.load_model(str(model_path))
        _GLOBAL_ATTACK_MAPPING = get_attack_mapping()

    return _GLOBAL_MODEL, _GLOBAL_PREPROCESSOR, _GLOBAL_ATTACK_MAPPING


def detect(sample: Union[Dict[str, Any], pd.Series, pd.DataFrame]) -> Dict[str, Any]:
    """
    Unified intrusion detection inference function.
    Takes a single traffic flow sample and returns:
    - predicted_label
    - is_attack
    - attack_family
    - confidence (predicted probability)
    - top_3_predictions (tuples of label and probability)
    - is_low_confidence (flagged if confidence < 0.60)
    - top_features (top 5 features driving the prediction with TreeSHAP contributions)
    """
    model, preprocessor, attack_mapping = load_detector()

    # Convert to DataFrame if dictionary or Series
    sample_id = "unknown_sample"
    if isinstance(sample, dict):
        sample_dict = sample.copy()
        if "sample_id" in sample_dict:
            sample_id = sample_dict.pop("sample_id")
        sample_df = pd.DataFrame([sample_dict])
    elif isinstance(sample, pd.Series):
        sample_dict = sample.to_dict()
        if "sample_id" in sample_dict:
            sample_id = sample_dict.pop("sample_id")
        sample_df = pd.DataFrame([sample_dict])
    elif isinstance(sample, pd.DataFrame):
        sample_df = sample.copy()
        if "sample_id" in sample_df.columns:
            sample_id = sample_df["sample_id"].iloc[0]
            sample_df = sample_df.drop(columns=["sample_id"])
    else:
        raise ValueError(f"Unsupported sample type: {type(sample)}")

    # Ensure label column is removed if present in sample
    config = get_dataset_config("rt_iot2022")
    lbl_col = config.get("label_column", "Attack_type")
    if lbl_col in sample_df.columns:
        sample_df = sample_df.drop(columns=[lbl_col])

    # Transform features
    X_proc = preprocessor.transform_X(sample_df)

    # Predict probabilities
    probs = model.predict_proba(X_proc)[0]
    pred_idx = int(np.argmax(probs))
    confidence = float(probs[pred_idx])

    class_names = preprocessor.label_encoder.classes_.tolist()
    predicted_label = class_names[pred_idx]

    # Top 3 predictions
    top_3_indices = np.argsort(probs)[::-1][:3]
    top_3 = [(class_names[i], float(probs[i])) for i in top_3_indices]

    # Family and attack status
    family_map = config.get("label_to_family", {})
    attack_family = family_map.get(predicted_label, "Other")
    is_attack = attack_family != "Normal"

    is_low_confidence = confidence < 0.60

    # TreeSHAP feature contributions via XGBoost booster
    booster = model.get_booster()
    dmatrix = xgb.DMatrix(X_proc)
    # contribs shape: (1, n_classes, n_features + 1)
    contribs = booster.predict(dmatrix, pred_contribs=True)
    # Extract contributions for the predicted class
    class_contribs = contribs[0, pred_idx, :-1]  # exclude bias term

    feat_names = preprocessor.feature_names_out

    # Rank features by absolute magnitude of contribution
    feature_contributions = []
    for f_idx, (f_name, cont_val) in enumerate(zip(feat_names, class_contribs)):
        # Match with original raw value
        if f_name in sample_df.columns:
            raw_val = float(sample_df[f_name].iloc[0])
        elif "_" in f_name and f_name.split("_")[0] in ["cat", "proto", "service"]:
            # One-hot encoded feature
            raw_val = float(X_proc[0, f_idx])
        else:
            raw_val = float(X_proc[0, f_idx])

        feature_contributions.append(
            {
                "feature": f_name,
                "value": raw_val,
                "contribution": float(cont_val),
                "abs_cont": abs(float(cont_val)),
            }
        )

    # Sort descending by absolute contribution and take top 5
    feature_contributions.sort(key=lambda x: x["abs_cont"], reverse=True)
    top_5 = [
        {"feature": item["feature"], "value": item["value"], "contribution": round(item["contribution"], 4)}
        for item in feature_contributions[:5]
    ]

    return {
        "sample_id": sample_id,
        "predicted_label": predicted_label,
        "is_attack": is_attack,
        "attack_family": attack_family,
        "confidence": round(confidence, 4),
        "top_3_predictions": [(lbl, round(p, 4)) for lbl, p in top_3],
        "is_low_confidence": is_low_confidence,
        "top_features": top_5,
    }


if __name__ == "__main__":
    train_and_evaluate_all()
