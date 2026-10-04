"""
Configuration loader and environment validator for RAG-IDS.
Reads parameters from configs/*.yaml and secrets from .env.
"""

import os
from pathlib import Path
from typing import Dict, Any, List
import yaml
from dotenv import load_dotenv

# Base project paths
SRC_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SRC_DIR.parent
CONFIGS_DIR = PROJECT_ROOT / "configs"
DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
KB_RAW_DIR = DATA_DIR / "kb_raw"
KB_MANUAL_DIR = DATA_DIR / "kb_manual"
CHROMA_DB_DIR = DATA_DIR / "chroma_db"
MODELS_DIR = PROJECT_ROOT / "models"
EVAL_DIR = PROJECT_ROOT / "eval"
EVAL_RESULTS_DIR = EVAL_DIR / "results"
EVAL_PLOTS_DIR = EVAL_DIR / "plots"
CACHE_DIR = PROJECT_ROOT / "cache"

# Load environment variables from .env
load_dotenv(PROJECT_ROOT / ".env")

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")


def ensure_directories():
    """Ensure all required project directories exist."""
    directories = [
        RAW_DATA_DIR,
        PROCESSED_DATA_DIR,
        KB_RAW_DIR,
        KB_MANUAL_DIR,
        CHROMA_DB_DIR,
        MODELS_DIR,
        EVAL_RESULTS_DIR,
        EVAL_PLOTS_DIR,
        CACHE_DIR,
    ]
    for d in directories:
        d.mkdir(parents=True, exist_ok=True)


def load_yaml(file_path: Path) -> Dict[str, Any]:
    """Load and parse a YAML file."""
    if not file_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {file_path}")
    with open(file_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_dataset_config(dataset_name: str = "rt_iot2022") -> Dict[str, Any]:
    """Load configuration for a specific dataset."""
    config_file = CONFIGS_DIR / f"{dataset_name}.yaml"
    return load_yaml(config_file)


def get_attack_mapping() -> Dict[str, Any]:
    """Load verified attack mapping configuration."""
    mapping_file = CONFIGS_DIR / "attack_mapping.yaml"
    return load_yaml(mapping_file)


def validate_environment():
    """Validate that necessary API keys and directories are initialized."""
    ensure_directories()
    issues = []
    if not GROQ_API_KEY:
        issues.append("GROQ_API_KEY is not set in .env")
    if not GEMINI_API_KEY:
        issues.append("GEMINI_API_KEY is not set in .env")
    return issues


# Initialize directories on import
ensure_directories()
