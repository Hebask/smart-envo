"""
app/services/ai_analysis.py

OpenAI-powered summaries for monitor/activity analysis.

Privacy approach:
- raw packet/DNS logs stay local
- we only send sanitized aggregated analytics to OpenAI
- no MAC addresses, no IP addresses, no raw domains are sent

This keeps OpenAI as the "insight layer" while local SQLite remains the source of truth.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from typing import Any, Dict, List

from openai import OpenAI

from app.db import get_db
from app.services.analysis import analysis_overview, device_activity_analysis

VALID_RISK = {"low", "medium", "high"}

SYSTEM_PROMPT = """
You are generating short activity-analysis insights for a Raspberry Pi smart firewall dashboard.

The input is sanitized and aggregated.
Do not ask for more information.
Do not mention MAC addresses, IP addresses, raw domains, or personal identifiers.
Do not claim certainty where the data is limited.

Return ONLY strict JSON with exactly these keys:
{
  "summary": "2-3 concise sentences",
  "risk_level": "low|medium|high",
  "recommended_actions": ["short action", "short action"],
  "notable_patterns": ["short pattern", "short pattern"]
}

Rules:
- maximum 3 recommended_actions
- maximum 4 notable_patterns
- keep language simple and dashboard-friendly
- if activity looks normal, use risk_level "low"
"""

def _now_epoch() -> int:
    return int(time.time())

def _get_openai_client():
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return None
    return OpenAI(api_key=api_key)

def _ensure_cache_table(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ai_analysis_cache (
            cache_key TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
    """)

def _cache_key(kind: str, payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{kind}:{raw}".encode("utf-8")).hexdigest()

def _cache_get(kind: str, payload: Dict[str, Any]) -> Dict[str, Any] | None:
    conn = get_db()
    _ensure_cache_table(conn)
    cur = conn.cursor()
    key = _cache_key(kind, payload)
    cur.execute("SELECT payload, expires_at FROM ai_analysis_cache WHERE cache_key=?", (key,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return None

    if int(row["expires_at"]) <= _now_epoch():
        return None

    try:
        data = json.loads(row["payload"])
        data["cached"] = True
        return data
    except Exception:
        return None

def _cache_put(kind: str, payload: Dict[str, Any], data: Dict[str, Any], ttl_seconds: int) -> None:
    conn = get_db()
    _ensure_cache_table(conn)
    cur = conn.cursor()
    key = _cache_key(kind, payload)
    now = _now_epoch()
    expires = now + ttl_seconds
    cur.execute("""
        INSERT OR REPLACE INTO ai_analysis_cache(cache_key, kind, payload, created_at, expires_at)
        VALUES(?,?,?,?,?)
    """, (
        key,
        kind,
        json.dumps(data, ensure_ascii=False),
        now,
        expires,
    ))
    conn.commit()
    conn.close()

def _safe_text(text: str) -> str:
    text = str(text or "")
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[ip]', text)
    text = re.sub(r'\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b', '[mac]', text, flags=re.I)
    text = re.sub(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', '[email]', text, flags=re.I)
    return text.strip()

def _normalize_output(data: Dict[str, Any], fallback_summary: str) -> Dict[str, Any]:
    summary = _safe_text(data.get("summary", "")).strip() or fallback_summary

    risk = str(data.get("risk_level", "low")).strip().lower()
    if risk not in VALID_RISK:
        risk = "low"

    actions = data.get("recommended_actions", [])
    if not isinstance(actions, list):
        actions = []
    actions = [_safe_text(x) for x in actions if str(x).strip()][:3]

    patterns = data.get("notable_patterns", [])
    if not isinstance(patterns, list):
        patterns = []
    patterns = [_safe_text(x) for x in patterns if str(x).strip()][:4]

    return {
        "summary": summary,
        "risk_level": risk,
        "recommended_actions": actions,
        "notable_patterns": patterns,
    }

def _call_openai(kind: str, payload: Dict[str, Any], ttl_seconds: int, fallback_summary: str) -> Dict[str, Any]:
    cached = _cache_get(kind, payload)
    if cached:
        return cached

    client = _get_openai_client()
    if client is None:
        raise RuntimeError("OPENAI_API_KEY is not set")

    response = client.responses.create(
        model=os.getenv("OPENAI_MODEL", "gpt-5.4-mini"),
        input=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ],
        max_output_tokens=300,
    )

    raw = (response.output_text or "").strip()
    if not raw:
        raise RuntimeError("Empty OpenAI response")

    parsed = json.loads(raw)
    data = _normalize_output(parsed, fallback_summary)
    data["source"] = "openai"
    data["cached"] = False

    _cache_put(kind, payload, data, ttl_seconds)
    return data

def _overview_payload(hours: int) -> Dict[str, Any]:
    data = analysis_overview(hours=hours)
    counts = data.get("counts", {})
    usage = data.get("usage", {})
    top_devices = data.get("top_devices", [])[:5]

    safe_top_devices = []
    for i, d in enumerate(top_devices, start=1):
        safe_top_devices.append({
            "device_label": f"Device {i}",
            "total_bytes": int(d.get("total_bytes", 0) or 0),
            "tx_bytes": int(d.get("tx_bytes", 0) or 0),
            "rx_bytes": int(d.get("rx_bytes", 0) or 0),
        })

    return {
        "hours": hours,
        "counts": {
            "total_devices": int(counts.get("total_devices", 0) or 0),
            "pending_devices": int(counts.get("pending_devices", 0) or 0),
            "manual_blocked_devices": int(counts.get("manual_blocked_devices", 0) or 0),
            "winner_blocked_devices": int(counts.get("winner_blocked_devices", 0) or 0),
            "warning_alerts": int(counts.get("warning_alerts", 0) or 0),
            "critical_alerts": int(counts.get("critical_alerts", 0) or 0),
            "unread_alerts": int(counts.get("unread_alerts", 0) or 0),
        },
        "usage": {
            "total_bytes": int(usage.get("total_bytes", 0) or 0),
            "total_tx_bytes": int(usage.get("total_tx_bytes", 0) or 0),
            "total_rx_bytes": int(usage.get("total_rx_bytes", 0) or 0),
            "devices_count": int(usage.get("devices_count", 0) or 0),
        },
        "top_devices": safe_top_devices,
    }

def _device_payload(mac: str, hours: int, limit: int = 20) -> Dict[str, Any]:
    data = device_activity_analysis(mac=mac, hours=hours, limit=limit)
    usage = data.get("usage_summary", {})
    activity = data.get("activity_summary", {})

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT app_name, category, COUNT(*) AS visits
        FROM activity_logs
        WHERE lower(device_mac)=lower(?) AND ts >= datetime('now', ?)
        GROUP BY app_name, category
        ORDER BY visits DESC, app_name ASC
        LIMIT 8
    """, (mac, f"-{int(hours)} hours"))
    apps = [dict(r) for r in cur.fetchall()]
    conn.close()

    safe_apps = []
    for row in apps:
        safe_apps.append({
            "app_name": _safe_text(row.get("app_name", "")),
            "category": _safe_text(row.get("category", "")),
            "visits": int(row.get("visits", 0) or 0),
        })

    return {
        "hours": hours,
        "status": _safe_text(activity.get("current_status", "unknown")),
        "usage": {
            "total_bytes": int(usage.get("total_bytes", 0) or 0),
            "tx_bytes": int(usage.get("tx_bytes", 0) or 0),
            "rx_bytes": int(usage.get("rx_bytes", 0) or 0),
        },
        "activity": {
            "alerts_count": int(activity.get("alerts_count", 0) or 0),
            "audit_count": int(activity.get("audit_count", 0) or 0),
            "estimated_minutes_online": int(activity.get("estimated_minutes_online", 0) or 0),
        },
        "top_applications": safe_apps,
    }

def _overview_fallback(hours: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    counts = payload["counts"]
    usage = payload["usage"]

    risk = "low"
    if counts["critical_alerts"] > 0:
        risk = "high"
    elif counts["warning_alerts"] > 0 or counts["pending_devices"] > 0:
        risk = "medium"

    summary = (
        f"In the last {hours} hours, the firewall tracked {counts['total_devices']} devices "
        f"and {usage['devices_count']} devices with traffic. "
        f"There are {counts['unread_alerts']} unread alerts and {counts['pending_devices']} pending devices."
    )

    actions = []
    if counts["pending_devices"] > 0:
        actions.append("Review pending devices")
    if counts["critical_alerts"] > 0 or counts["warning_alerts"] > 0:
        actions.append("Review recent alerts")
    if not actions:
        actions.append("Continue monitoring normal activity")

    patterns = []
    if payload["top_devices"]:
        patterns.append("Traffic is concentrated on a small number of active devices")
    if usage["total_bytes"] == 0:
        patterns.append("No measurable traffic was captured in this window")

    return {
        "summary": summary,
        "risk_level": risk,
        "recommended_actions": actions[:3],
        "notable_patterns": patterns[:4],
        "source": "fallback",
        "cached": False,
    }

def _device_fallback(hours: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    risk = "low"
    if payload["status"] in ("blocked", "pending"):
        risk = "medium"
    if payload["activity"]["alerts_count"] > 0:
        risk = "medium"

    top_apps = payload["top_applications"][:3]
    if top_apps:
        app_list = ", ".join(a["app_name"] for a in top_apps if a["app_name"])
    else:
        app_list = "no clear top applications"

    summary = (
        f"In the last {hours} hours, this device was {payload['status']} and transferred "
        f"{payload['usage']['total_bytes']} bytes in total. "
        f"Its most visible application pattern was {app_list}."
    )

    actions = []
    if payload["status"] == "blocked":
        actions.append("Confirm the block is intentional")
    if payload["activity"]["alerts_count"] > 0:
        actions.append("Review device-related alerts")
    if not actions:
        actions.append("Continue monitoring this device")

    patterns = [f"Top applications observed: {app_list}"] if app_list else []

    return {
        "summary": summary,
        "risk_level": risk,
        "recommended_actions": actions[:3],
        "notable_patterns": patterns[:4],
        "source": "fallback",
        "cached": False,
    }

def overview_ai_summary(hours: int = 24) -> Dict[str, Any]:
    payload = _overview_payload(hours)
    fallback = _overview_fallback(hours, payload)
    try:
        ai = _call_openai(
            kind="overview",
            payload=payload,
            ttl_seconds=600,
            fallback_summary=fallback["summary"],
        )
        ai.setdefault("source", "openai")
        return ai
    except Exception as e:
        fallback["error"] = _safe_text(str(e))
        return fallback

def device_ai_summary(mac: str, hours: int = 24, limit: int = 20) -> Dict[str, Any]:
    payload = _device_payload(mac, hours, limit=limit)
    fallback = _device_fallback(hours, payload)
    try:
        ai = _call_openai(
            kind="device",
            payload=payload,
            ttl_seconds=600,
            fallback_summary=fallback["summary"],
        )
        ai.setdefault("source", "openai")
        return ai
    except Exception as e:
        fallback["error"] = _safe_text(str(e))
        return fallback
