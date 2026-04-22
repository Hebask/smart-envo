"""
app/categorizer.py

OpenAI-only domain categorization.
Keeps the same detect(domain) -> (app_name, category) interface.

Behavior:
- normalize domain
- check local SQLite cache first
- if not cached, call OpenAI
- if OpenAI fails or key is missing, return a neutral unresolved result
- do NOT fall back to local keyword guesses
- only cache successful OpenAI classifications
"""

import json
import os
from typing import Tuple

from openai import OpenAI

from app.db import get_db

VALID_CATEGORIES = [
    "Social",
    "Entertainment",
    "Video",
    "Messaging",
    "Gaming",
    "Education",
    "Shopping",
    "News",
    "Work",
    "Cloud",
    "Search",
    "Finance",
    "System",
    "Other",
]

SYSTEM_PROMPT = """
You classify internet domains into one concise app/site name and one category.

Return ONLY strict JSON with exactly these keys:
{
  "app_name": "string",
  "category": "Social|Entertainment|Video|Messaging|Gaming|Education|Shopping|News|Work|Cloud|Search|Finance|System|Other"
}

Rules:
- Infer the main service/site from the domain.
- If the domain is clearly infrastructure, CDN, telemetry, ad-serving, auth, analytics,
  update-related, OS/service background traffic, or cannot be confidently tied to a user-facing category,
  use one of: Cloud, System, Search, or Other as appropriate.
- Use a short human-readable app_name.
- Never return explanations.
"""

def _normalize_domain(domain: str) -> str:
    domain = (domain or "").strip().lower().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def _get_openai_client():
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return None
    return OpenAI(api_key=api_key)


def _ai_detect(domain: str) -> Tuple[str, str]:
    client = _get_openai_client()
    if client is None:
        raise RuntimeError("OPENAI_API_KEY is not set")

    prompt = f"Domain to classify: {domain}"

    response = client.responses.create(
        model=os.getenv("OPENAI_MODEL", "gpt-5.4-mini"),
        input=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        max_output_tokens=120,
    )

    raw = (response.output_text or "").strip()
    if not raw:
        raise RuntimeError("Empty OpenAI response")

    data = json.loads(raw)

    app_name = str(data.get("app_name", "")).strip() or domain.split(".")[0].capitalize()
    category = str(data.get("category", "Other")).strip()

    if category not in VALID_CATEGORIES:
        category = "Other"

    return app_name, category


def detect(domain: str) -> Tuple[str, str]:
    domain = _normalize_domain(domain)
    if not domain:
        return "Unknown", "Other"

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT app_name, category FROM domain_categories WHERE domain=?",
        (domain,)
    )
    row = cur.fetchone()
    if row and row["category"] in VALID_CATEGORIES:
        conn.close()
        return row["app_name"], row["category"]

    if row and row["category"] not in VALID_CATEGORIES:
        try:
            cur.execute("DELETE FROM domain_categories WHERE domain=?", (domain,))
            conn.commit()
        except Exception as e:
            print(f"[categorizer] cache cleanup error for {domain}: {e}")

    try:
        app_name, category = _ai_detect(domain)
    except Exception as e:
        print(f"[categorizer] OpenAI failed for {domain}: {e}")
        conn.close()
        return "Unclassified", "Other"

    if category not in VALID_CATEGORIES:
        category = "Other"

    try:
        cur.execute(
            "INSERT OR REPLACE INTO domain_categories(domain, app_name, category) VALUES(?,?,?)",
            (domain, app_name, category)
        )
        conn.commit()
    except Exception as e:
        print(f"[categorizer] DB write error: {e}")
    finally:
        conn.close()

    return app_name, category
