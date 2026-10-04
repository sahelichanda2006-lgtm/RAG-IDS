"""
Data loading, cleaning, and stratified splitting pipeline for RT-IoT2022.
Produces train.parquet, test.parquet, and test_samples_pool.json.
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Tuple, Dict, Any

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

from src.config import (
    PROJECT_ROOT,
    RAW_DATA_DIR,
    PROCESSED_DATA_DIR,
    get_dataset_config,
    get_attack_mapping,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("data_loader")


def load_raw_dataset(raw_csv_path: Path) -> pd.DataFrame:
    """
    Load raw RT-IoT2022 CSV. If not present locally, fetch from UCI repository.
    """
    if raw_csv_path.exists():
        logger.info(f"Loading local raw dataset from: {raw_csv_path}")
        df = pd.read_csv(raw_csv_path)
    else:
        logger.info("Local raw file not found. Fetching from UCI repository (id=942)...")
        raw_csv_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            from ucimlrepo import fetch_ucirepo
            dataset = fetch_ucirepo(id=942)
            X = dataset.data.features
            y = dataset.data.targets
            df = pd.concat([X, y], axis=1)
            df.to_csv(raw_csv_path, index=False)
            logger.info(f"Successfully downloaded and saved raw data to {raw_csv_path}")
        except Exception as e:
            logger.warning(f"ucimlrepo fetch failed: {e}. Downloading zip archive directly...")
            import requests
            import zipfile
            import io
            import certifi
            zip_url = "https://archive.ics.uci.edu/static/public/942/rt-iot2022.zip"
            resp = requests.get(zip_url, verify=certifi.where(), timeout=60)
            resp.raise_for_status()
            z = zipfile.ZipFile(io.BytesIO(resp.content))
            csv_files = [f for f in z.namelist() if f.endswith('.csv')]
            main_csv = csv_files[0]
            for f in csv_files:
                if "rt_iot2022" in f.lower() or "rt-iot2022" in f.lower():
                    main_csv = f
                    break
            df = pd.read_csv(z.open(main_csv))
            df.to_csv(raw_csv_path, index=False)
            logger.info(f"Extracted and saved raw data from zip to {raw_csv_path}")

    # Drop unnamed index column if present
    unnamed_cols = [c for c in df.columns if "unnamed" in str(c).lower()]
    if unnamed_cols:
        logger.info(f"Dropping unnamed row-number column(s): {unnamed_cols}")
        df = df.drop(columns=unnamed_cols)

    return df


def process_and_split(
    df: pd.DataFrame, config: Dict[str, Any]
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Clean columns, analyze duplicates, execute stratified train/test split,
    and attach persistent sample IDs to the test pool.
    """
    label_col = config["label_column"]
    drop_cols = config.get("drop_columns", [])
    dedup_strategy = config.get("dedup_strategy", "pre_split")
    test_size = config["split"]["test_size"]
    seed = config["split"]["random_seed"]

    # 1. Drop specified ephemeral/random columns (e.g. id.orig_p)
    cols_to_drop = [c for c in drop_cols if c in df.columns]
    if cols_to_drop:
        logger.info(f"Dropping ephemeral columns: {cols_to_drop}")
        df = df.drop(columns=cols_to_drop)

    raw_counts = df[label_col].value_counts()
    logger.info(f"Total rows before deduplication: {len(df)}")

    # 2. Deduplication analysis
    if dedup_strategy == "pre_split":
        logger.info("Applying strict pre-split deduplication across all retained features...")
        dups_count = df.duplicated().sum()
        logger.info(f"Identified {dups_count:,} duplicate rows ({dups_count/len(df)*100:.2f}%)")
        df_clean = df.drop_duplicates().copy()
        dedup_counts = df_clean[label_col].value_counts()

        # Display comparison table
        comp_df = pd.DataFrame({
            "Raw Count": raw_counts,
            "Deduped Count": dedup_counts,
            "Dropped Count": raw_counts - dedup_counts,
            "Retention %": ((dedup_counts / raw_counts) * 100).round(2),
        }).fillna(0)
        print("\n" + "=" * 70)
        print("CLASS DISTRIBUTION: BEFORE vs. AFTER DEDUPLICATION")
        print("=" * 70)
        print(comp_df.to_string())
        print("=" * 70 + "\n")

        # Check for minority classes with fewer than 20 rows
        critically_small = dedup_counts[dedup_counts < 20]
        if not critically_small.empty:
            for cls_name, count in critically_small.items():
                logger.warning(
                    f"Class '{cls_name}' has only {count} rows after deduplication! "
                    "In 80/20 split, this leaves only 1 test sample. "
                    "Cross-validation numbers will be noisy."
                )

        # Stratified train/test split
        train_df, test_df = train_test_split(
            df_clean,
            test_size=test_size,
            random_state=seed,
            stratify=df_clean[label_col],
        )

    elif dedup_strategy == "train_only":
        logger.info("Applying train-only deduplication (Option A)...")
        # Split first to preserve test representation
        train_raw, test_df = train_test_split(
            df,
            test_size=test_size,
            random_state=seed,
            stratify=df[label_col],
        )
        logger.info(f"Training partition raw count: {len(train_raw)}")
        train_df = train_raw.drop_duplicates().copy()
        logger.info(f"Training partition deduped count: {len(train_df)}")
        comp_df = pd.DataFrame({
            "Train Deduped": train_df[label_col].value_counts(),
            "Test Pool": test_df[label_col].value_counts(),
        }).fillna(0)
        print(comp_df.to_string())

    else:
        raise ValueError(f"Unknown dedup_strategy: {dedup_strategy}")

    # Reset indices
    train_df = train_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)

    # 3. Assign stable, unique sample IDs to test partition
    test_df["sample_id"] = [f"sample_{i:05d}" for i in range(len(test_df))]
    # Put sample_id as first column
    cols = ["sample_id"] + [c for c in test_df.columns if c != "sample_id"]
    test_df = test_df[cols]

    return train_df, test_df, comp_df


def save_processed_data(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    config: Dict[str, Any],
    attack_mapping: Dict[str, Any],
):
    """
    Serialize train.parquet, test.parquet, and create lightweight test_samples_pool.json.
    """
    train_path = PROJECT_ROOT / config["processed_train_path"]
    test_path = PROJECT_ROOT / config["processed_test_path"]
    pool_path = PROJECT_ROOT / config["test_samples_pool_path"]

    train_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info(f"Saving training set to {train_path} ({len(train_df):,} rows)...")
    train_df.to_parquet(train_path, index=False)

    logger.info(f"Saving test set to {test_path} ({len(test_df):,} rows)...")
    test_df.to_parquet(test_path, index=False)

    # Build lightweight test pool index for quick search in UI and evaluation
    label_col = config["label_column"]
    family_map = config.get("label_to_family", {})

    test_pool = []
    dest_port_col = config.get("destination_port_column", "id.resp_p")
    for _, row in test_df.iterrows():
        lbl = str(row[label_col])
        item = {
            "sample_id": row["sample_id"],
            "label": lbl,
            "attack_family": family_map.get(lbl, "Other"),
            "protocol": str(row.get("proto", "-")),
            "service": str(row.get("service", "-")),
            "dest_port": int(row[dest_port_col]) if dest_port_col in row and pd.notna(row[dest_port_col]) else 0,
        }
        test_pool.append(item)

    with open(pool_path, "w", encoding="utf-8") as f:
        json.dump(test_pool, f, indent=2)
    logger.info(f"Saved lightweight test sample pool ({len(test_pool):,} entries) to {pool_path}")


def main():
    """Execute data loading and preparation pipeline."""
    config = get_dataset_config("rt_iot2022")
    attack_mapping = get_attack_mapping()

    raw_csv = PROJECT_ROOT / config["raw_data_path"]
    df_raw = load_raw_dataset(raw_csv)

    train_df, test_df, _ = process_and_split(df_raw, config)
    save_processed_data(train_df, test_df, config, attack_mapping)

    print("\n" + "=" * 70)
    print("DATA PIPELINE SUMMARY (Milestone 1 Complete)")
    print("=" * 70)
    print(f"Dataset:            {config['dataset_name']}")
    print(f"Raw Instances:      {len(df_raw):,}")
    print(f"Training Rows:      {len(train_df):,}")
    print(f"Test Rows:          {len(test_df):,}")
    print(f"Strategy:           {config.get('dedup_strategy')}")
    print(f"Test Sample ID Ex:  {test_df['sample_id'].iloc[0]} -> {test_df['sample_id'].iloc[-1]}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
