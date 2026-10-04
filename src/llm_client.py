"""
Unified LLM Client for RAG-IDS.
Wraps OpenAI SDK for Groq and Google AI Studio endpoints with
SQLite disk caching, rate limiting/pacing, and exponential backoff retry.
"""

import os
import sys
import json
import time
import sqlite3
import hashlib
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from openai import OpenAI
from src.config import PROJECT_ROOT, CACHE_DIR, GROQ_API_KEY, GEMINI_API_KEY

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("llm_client")

DB_PATH = CACHE_DIR / "llm_cache.sqlite"

# Model constants
MODEL_ANSWERING_GROQ = "openai/gpt-oss-120b"
MODEL_JUDGE_GEMINI = "gemini-3.5-flash-lite"
MODEL_FALLBACK_GROQ = "qwen/qwen3.8-27b"

# Endpoints
URL_GROQ = "https://api.groq.com/openai/v1"
URL_GEMINI = "https://generativelanguage.googleapis.com/v1beta/openai/"


def init_db():
    """Initialize SQLite response cache table."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS response_cache (
                cache_key TEXT PRIMARY KEY,
                role TEXT,
                model TEXT,
                request_json TEXT,
                response_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


init_db()


def make_cache_key(role: str, model: str, messages: List[Dict[str, Any]], tools: Any) -> str:
    """Create a deterministic hash of the request parameters."""
    data = {"role": role, "model": model, "messages": messages, "tools": tools}
    payload = json.dumps(data, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def get_cached_response(cache_key: str) -> Optional[Dict[str, Any]]:
    """Retrieve response from local SQLite cache."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT response_json FROM response_cache WHERE cache_key = ?", (cache_key,))
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
    except Exception as e:
        logger.warning(f"Cache read error: {e}")
    return None


def store_cached_response(cache_key: str, role: str, model: str, request_json: str, response_json: str):
    """Store response in local SQLite cache."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO response_cache (cache_key, role, model, request_json, response_json) VALUES (?, ?, ?, ?, ?)",
                (cache_key, role, model, request_json, response_json),
            )
    except Exception as e:
        logger.warning(f"Cache write error: {e}")


def get_client_for_role(role: str) -> Tuple[OpenAI, str]:
    """Return OpenAI client instance and model name based on role."""
    if role == "answering":
        if not GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY is not set in .env")
        client = OpenAI(base_url=URL_GROQ, api_key=GROQ_API_KEY)
        return client, MODEL_ANSWERING_GROQ

    elif role == "judge":
        if GEMINI_API_KEY:
            client = OpenAI(base_url=URL_GEMINI, api_key=GEMINI_API_KEY)
            return client, MODEL_JUDGE_GEMINI
        elif GROQ_API_KEY:
            logger.info("GEMINI_API_KEY not set; using fallback judge on Groq...")
            client = OpenAI(base_url=URL_GROQ, api_key=GROQ_API_KEY)
            return client, MODEL_FALLBACK_GROQ
        else:
            raise ValueError("No API keys found for judge.")

    elif role == "fallback_groq":
        client = OpenAI(base_url=URL_GROQ, api_key=GROQ_API_KEY)
        return client, MODEL_FALLBACK_GROQ

    else:
        raise ValueError(f"Unknown role: {role}")


def query_llm(
    role: str,
    messages: List[Dict[str, Any]],
    tools: Optional[List[Dict[str, Any]]] = None,
    temperature: float = 0.0,
    max_retries: int = 4,
    use_cache: bool = True,
) -> Dict[str, Any]:
    """
    Query an LLM endpoint with automatic pacing, caching, and exponential backoff retry.
    """
    client, model = get_client_for_role(role)
    cache_key = make_cache_key(role, model, messages, tools)

    if use_cache:
        cached = get_cached_response(cache_key)
        if cached:
            return cached

    req_kwargs = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
    }
    if tools:
        req_kwargs["tools"] = tools
        req_kwargs["tool_choice"] = "auto"

    # Enforce safe request pacing
    time.sleep(1.2)

    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(**req_kwargs)
            res_dict = response.model_dump()

            if use_cache:
                store_cached_response(
                    cache_key,
                    role,
                    model,
                    json.dumps(req_kwargs),
                    json.dumps(res_dict),
                )
            return res_dict

        except Exception as e:
            err_msg = str(e)
            logger.warning(f"LLM request error on attempt {attempt+1}/{max_retries} ({role}:{model}): {err_msg}")

            # If Gemini fails on judge, attempt Groq fallback judge
            if role == "judge" and attempt == 1:
                logger.info("Switching to fallback judge model on Groq...")
                client, model = get_client_for_role("fallback_groq")
                req_kwargs["model"] = model

            if attempt == max_retries - 1:
                raise e

            backoff = (attempt + 1) * 3.0
            time.sleep(backoff)

    raise RuntimeError("Failed to query LLM after maximum retries.")
