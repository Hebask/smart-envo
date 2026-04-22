from __future__ import annotations

import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any, Dict

from openai import OpenAI

from app.db import get_db

SYSTEM_PROMPT = """
You are writing a weekly or monthly internet-activity report for an admin dashboard.

The data belongs to one managed user and may combine multiple linked devices.
Your job is to identify the main content types and online behavior patterns.

Focus on:
- dominant content categories
- main platforms/sites/apps
- whether activity looks balanced or heavily concentrated
- time-of-day patterns when clearly visible
- concise, neutral recommendations for the admin

Return ONLY strict JSON with exactly these keys:
{
  "headline": "short title",
  "summary": "2-4 sentences",
  "content_focus": "1-2 sentences about main content types",
  "time_pattern": "1-2 sentences about timing behavior",
  "risk_level": "low|medium|high",
  "dominant_categories": ["Category"],
  "top_platforms": ["Platform"],
  "recommended_actions": ["short action"]
}
"""

def _normalize_days(days: int) -> int:
    return 30 if int(days) >= 30 else 7

def _ts_expr(col: str = "ts") -> str:
    return f"datetime(replace(substr({col},1,19),'T',' '))"

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def _get_openai_client():
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return None
    return OpenAI(api_key=api_key)

def _ensure_cache(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ai_user_report_cache (
            cache_key TEXT PRIMARY KEY,
            payload TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
    """)

def _ensure_report_store(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS managed_user_ai_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            managed_user_id INTEGER NOT NULL,
            period_days INTEGER NOT NULL,
            period_label TEXT NOT NULL,
            report_json TEXT NOT NULL,
            generated_at TEXT NOT NULL,
            UNIQUE(managed_user_id, period_days, period_label),
            FOREIGN KEY(managed_user_id) REFERENCES managed_users(id) ON DELETE CASCADE
        )
    """)

def _cache_key(user_id: int, days: int) -> str:
    return f"user:{user_id}:days:{days}"

def _period_label(days: int) -> str:
    now = datetime.now(timezone.utc)
    if days >= 30:
        return now.strftime("%Y-%m")
    iso = now.isocalendar()
    return f"{iso.year}-W{iso.week:02d}"

def _fetch_cached(user_id: int, days: int):
    conn = get_db()
    _ensure_cache(conn)
    row = conn.execute(
        "SELECT payload, expires_at FROM ai_user_report_cache WHERE cache_key=?",
        (_cache_key(user_id, days),),
    ).fetchone()
    conn.close()

    if not row:
        return None
    if int(row["expires_at"]) <= int(time.time()):
        return None

    data = json.loads(row["payload"])
    data["cached"] = True
    return data

def _save_cached(user_id: int, days: int, payload: Dict[str, Any], ttl: int = 3600):
    conn = get_db()
    _ensure_cache(conn)
    now = int(time.time())
    conn.execute(
        "INSERT OR REPLACE INTO ai_user_report_cache(cache_key, payload, created_at, expires_at) VALUES (?,?,?,?)",
        (_cache_key(user_id, days), json.dumps(payload, ensure_ascii=False), now, now + ttl),
    )
    conn.commit()
    conn.close()

def _load_latest_stored_report(user_id: int, days: int):
    conn = get_db()
    _ensure_report_store(conn)
    row = conn.execute("""
        SELECT report_json, generated_at, period_label
        FROM managed_user_ai_reports
        WHERE managed_user_id=? AND period_days=?
        ORDER BY generated_at DESC, id DESC
        LIMIT 1
    """, (user_id, days)).fetchone()
    conn.close()

    if not row:
        return None

    data = json.loads(row["report_json"])
    data["stored"] = True
    data["generated_at"] = row["generated_at"]
    data["period_label"] = row["period_label"]
    return data

def _save_stored_report(user_id: int, days: int, report: Dict[str, Any]):
    conn = get_db()
    _ensure_report_store(conn)
    period_label = _period_label(days)
    generated_at = _utc_now_iso()

    payload = dict(report)
    payload["period_days"] = days
    payload["stored"] = True
    payload["generated_at"] = generated_at
    payload["period_label"] = period_label

    conn.execute("""
        INSERT OR REPLACE INTO managed_user_ai_reports(
            managed_user_id, period_days, period_label, report_json, generated_at
        ) VALUES (?,?,?,?,?)
    """, (
        user_id,
        days,
        period_label,
        json.dumps(payload, ensure_ascii=False),
        generated_at,
    ))
    conn.commit()
    conn.close()
    return payload

def _build_payload(user_id: int, days: int) -> Dict[str, Any]:
    conn = get_db()
    cur = conn.cursor()

    user = cur.execute(
        "SELECT id, name, email, notes, created_at FROM managed_users WHERE id=?",
        (user_id,),
    ).fetchone()
    if not user:
        conn.close()
        raise ValueError("managed user not found")
    user = dict(user)

    device_rows = cur.execute("""
        SELECT d.mac, d.name, d.last_ip
        FROM managed_user_devices mud
        JOIN devices d ON d.mac = mud.device_mac
        WHERE mud.managed_user_id=?
        ORDER BY d.name ASC, d.mac ASC
    """, (user_id,)).fetchall()

    devices = [dict(r) for r in device_rows]
    macs = [d["mac"] for d in devices]

    if not macs:
        conn.close()
        return {
            "user": {"id": user["id"], "name": user["name"]},
            "window_days": days,
            "devices_count": 0,
            "total_events": 0,
            "unique_domains": 0,
            "categories": [],
            "apps": [],
            "domains": [],
            "daily": [],
            "hourly": [],
            "alerts": {"warning": 0, "critical": 0},
        }

    placeholders = ",".join(["?"] * len(macs))
    cutoff = f"-{int(days)} days"
    params = macs + [cutoff]

    categories = [dict(r) for r in cur.execute(f"""
        SELECT category, COUNT(*) AS count
        FROM activity_logs
        WHERE device_mac IN ({placeholders})
          AND {_ts_expr()} >= datetime('now', ?)
        GROUP BY category
        ORDER BY count DESC, category ASC
    """, params).fetchall()]

    total_events = sum(int(r["count"]) for r in categories)

    apps = [dict(r) for r in cur.execute(f"""
        SELECT app_name, category, COUNT(*) AS count
        FROM activity_logs
        WHERE device_mac IN ({placeholders})
          AND {_ts_expr()} >= datetime('now', ?)
          AND TRIM(COALESCE(app_name,'')) <> ''
        GROUP BY app_name, category
        ORDER BY count DESC, app_name ASC
        LIMIT 15
    """, params).fetchall()]

    domains = [dict(r) for r in cur.execute(f"""
        SELECT domain, app_name, category, COUNT(*) AS count
        FROM activity_logs
        WHERE device_mac IN ({placeholders})
          AND {_ts_expr()} >= datetime('now', ?)
          AND TRIM(COALESCE(domain,'')) <> ''
        GROUP BY domain, app_name, category
        ORDER BY count DESC, domain ASC
        LIMIT 15
    """, params).fetchall()]

    daily = [dict(r) for r in cur.execute(f"""
        SELECT date({_ts_expr()}) AS day, COUNT(*) AS visits
        FROM activity_logs
        WHERE device_mac IN ({placeholders})
          AND {_ts_expr()} >= datetime('now', ?)
        GROUP BY date({_ts_expr()})
        ORDER BY day ASC
    """, params).fetchall()]

    hourly = [dict(r) for r in cur.execute(f"""
        SELECT strftime('%H', {_ts_expr()}) AS hour, COUNT(*) AS visits
        FROM activity_logs
        WHERE device_mac IN ({placeholders})
          AND {_ts_expr()} >= datetime('now', ?)
        GROUP BY strftime('%H', {_ts_expr()})
        ORDER BY hour ASC
    """, params).fetchall()]

    unique_domains = int(cur.execute(f"""
        SELECT COUNT(DISTINCT domain) AS c
        FROM activity_logs
        WHERE device_mac IN ({placeholders})
          AND {_ts_expr()} >= datetime('now', ?)
          AND TRIM(COALESCE(domain,'')) <> ''
    """, params).fetchone()["c"] or 0)

    alert_rows = [dict(r) for r in cur.execute(f"""
        SELECT level, COUNT(*) AS count
        FROM alerts
        WHERE device_mac IN ({placeholders})
          AND {_ts_expr('ts')} >= datetime('now', ?)
        GROUP BY level
    """, params).fetchall()]

    alerts = {"warning": 0, "critical": 0}
    for r in alert_rows:
        level = (r["level"] or "").lower()
        if level in alerts:
            alerts[level] = int(r["count"] or 0)

    conn.close()

    if total_events:
        for row in categories:
            row["percentage"] = round((int(row["count"]) * 100.0) / total_events, 1)
        for row in apps:
            row["percentage"] = round((int(row["count"]) * 100.0) / total_events, 1)
        for row in domains:
            row["percentage"] = round((int(row["count"]) * 100.0) / total_events, 1)
    else:
        for seq in (categories, apps, domains):
            for row in seq:
                row["percentage"] = 0.0

    return {
        "user": {"id": user["id"], "name": user["name"]},
        "window_days": days,
        "devices_count": len(devices),
        "device_names": [d.get("name") or d.get("mac") for d in devices],
        "total_events": total_events,
        "unique_domains": unique_domains,
        "categories": categories[:10],
        "apps": apps[:12],
        "domains": domains[:12],
        "daily": daily,
        "hourly": hourly,
        "alerts": alerts,
    }

def _unavailable_report(days: int, reason: str) -> Dict[str, Any]:
    return {
        "headline": f"Last {days} days summary unavailable",
        "summary": "OpenAI analysis is currently unavailable.",
        "content_focus": "Not available.",
        "time_pattern": "Not available.",
        "risk_level": "low",
        "dominant_categories": [],
        "top_platforms": [],
        "recommended_actions": ["Check OpenAI configuration and try again."],
        "period_days": days,
        "cached": False,
        "stored": False,
        "source": "unavailable",
        "error": reason,
    }

def _fallback_shape_from_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    days = int(payload["window_days"])
    categories = payload.get("categories", [])
    apps = payload.get("apps", [])
    top_categories = [c["category"] for c in categories[:3]]
    top_apps = [a["app_name"] for a in apps[:5] if a.get("app_name")]
    top_category = top_categories[0] if top_categories else "Other"

    if payload["total_events"] == 0:
        return {
            "headline": f"No significant activity in the last {days} days",
            "summary": f"No meaningful browsing or app activity was recorded for this user in the last {days} days.",
            "content_focus": "There is not enough activity to identify dominant content types.",
            "time_pattern": "There is not enough activity to identify a time-of-day pattern.",
            "risk_level": "low",
            "dominant_categories": [],
            "top_platforms": [],
            "recommended_actions": ["Continue monitoring this user"],
        }

    return {
        "headline": f"{top_category}-led activity in the last {days} days",
        "summary": f"This user generated {payload['total_events']} categorized activity events across {payload['devices_count']} linked device(s). The most visible categories were {', '.join(top_categories) if top_categories else 'mixed'}.",
        "content_focus": f"The activity appears concentrated around {', '.join(top_categories) if top_categories else 'mixed content'} with platforms such as {', '.join(top_apps[:4]) if top_apps else 'no clear platforms'}.",
        "time_pattern": "Timing trends are based on recent recorded usage.",
        "risk_level": "low",
        "dominant_categories": top_categories[:3],
        "top_platforms": top_apps[:6],
        "recommended_actions": [
            "Review the dominant content categories",
            "Check whether the activity matches expected use"
        ],
    }

def _normalize_report(data: Dict[str, Any], fallback: Dict[str, Any]) -> Dict[str, Any]:
    headline = str(data.get("headline") or fallback["headline"]).strip()
    summary = str(data.get("summary") or fallback["summary"]).strip()
    content_focus = str(data.get("content_focus") or fallback["content_focus"]).strip()
    time_pattern = str(data.get("time_pattern") or fallback["time_pattern"]).strip()
    risk = str(data.get("risk_level") or fallback["risk_level"]).strip().lower()
    if risk not in {"low", "medium", "high"}:
        risk = fallback["risk_level"]

    dominant_categories = data.get("dominant_categories")
    if not isinstance(dominant_categories, list):
        dominant_categories = fallback["dominant_categories"]
    dominant_categories = [str(x).strip() for x in dominant_categories if str(x).strip()][:3]

    top_platforms = data.get("top_platforms")
    if not isinstance(top_platforms, list):
        top_platforms = fallback["top_platforms"]
    top_platforms = [str(x).strip() for x in top_platforms if str(x).strip()][:6]

    actions = data.get("recommended_actions")
    if not isinstance(actions, list):
        actions = fallback["recommended_actions"]
    actions = [str(x).strip() for x in actions if str(x).strip()][:3]

    return {
        "headline": headline,
        "summary": summary,
        "content_focus": content_focus,
        "time_pattern": time_pattern,
        "risk_level": risk,
        "dominant_categories": dominant_categories,
        "top_platforms": top_platforms,
        "recommended_actions": actions,
    }

def _generate_openai_report(payload: Dict[str, Any], days: int) -> Dict[str, Any]:
    fallback = _fallback_shape_from_payload(payload)

    client = _get_openai_client()
    if client is None:
        return _unavailable_report(days, "OPENAI_API_KEY is not set")

    user_prompt = {
        "task": "Generate an admin-facing user activity analysis",
        "period": "last 30 days" if days == 30 else "last 7 days",
        "data": payload,
    }

    try:
        response = client.responses.create(
            model=os.getenv("OPENAI_MODEL", "gpt-5.4-mini"),
            input=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(user_prompt, ensure_ascii=False)},
            ],
            max_output_tokens=500,
        )
        raw = (response.output_text or "").strip()
        if not raw:
            raise RuntimeError("Empty OpenAI response")

        data = json.loads(raw)
        report = _normalize_report(data, fallback)
        report.update({
            "source": "openai",
            "cached": False,
            "stored": False,
            "period_days": days,
        })
        return report
    except Exception as e:
        return _unavailable_report(days, str(e))

def generate_and_store_managed_user_report(user_id: int, days: int = 7) -> Dict[str, Any]:
    days = _normalize_days(days)
    payload = _build_payload(user_id, days)
    report = _generate_openai_report(payload, days)

    if report.get("source") == "openai":
        report = _save_stored_report(user_id, days, report)

    _save_cached(user_id, days, report, ttl=3600)
    return report

def generate_and_store_all_managed_user_reports(days: int = 7) -> Dict[str, int]:
    days = _normalize_days(days)

    conn = get_db()
    _ensure_report_store(conn)
    rows = conn.execute("SELECT id FROM managed_users ORDER BY id ASC").fetchall()
    conn.close()

    total = 0
    stored = 0
    failed = 0

    for row in rows:
        total += 1
        user_id = int(row["id"])
        try:
            report = generate_and_store_managed_user_report(user_id, days)
            if report.get("source") == "openai":
                stored += 1
            else:
                failed += 1
        except Exception:
            failed += 1

    return {"days": days, "total": total, "stored": stored, "failed": failed}

def managed_user_ai_report(user_id: int, days: int = 7) -> Dict[str, Any]:
    days = _normalize_days(days)

    cached = _fetch_cached(user_id, days)
    if cached:
        return cached

    stored = _load_latest_stored_report(user_id, days)
    if stored:
        stored["cached"] = False
        _save_cached(user_id, days, stored, ttl=3600)
        return stored

    return generate_and_store_managed_user_report(user_id, days)
