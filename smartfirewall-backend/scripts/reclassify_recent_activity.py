import argparse
import sqlite3
import time
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app
from app.categorizer import detect

VALID_CATEGORIES = {
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
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=45)
    parser.add_argument("--limit", type=int, default=0, help="0 means all recent distinct domains")
    parser.add_argument("--sleep", type=float, default=0.0)
    args = parser.parse_args()

    app = create_app()

    with app.app_context():
        db = "iot.db"
        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("PRAGMA foreign_keys=ON;")

        limit_sql = "" if args.limit <= 0 else f"LIMIT {int(args.limit)}"

        rows = cur.execute(f"""
            SELECT lower(trim(domain)) AS domain, COUNT(*) AS n
            FROM activity_logs
            WHERE trim(COALESCE(domain,'')) <> ''
              AND datetime(replace(substr(ts,1,19),'T',' ')) >= datetime('now', ?)
            GROUP BY lower(trim(domain))
            ORDER BY n DESC, domain ASC
            {limit_sql}
        """, (f"-{int(args.days)} days",)).fetchall()

        domains = [r["domain"] for r in rows if r["domain"]]
        print(f"recent_distinct_domains={len(domains)} days={args.days}")

        updated_domains = 0
        unresolved = 0

        for i, domain in enumerate(domains, start=1):
            try:
                cur.execute("DELETE FROM domain_categories WHERE domain=?", (domain,))
                conn.commit()

                app_name, category = detect(domain)

                if category not in VALID_CATEGORIES:
                    category = "Other"

                if app_name == "Unclassified" and category == "Other":
                    unresolved += 1

                cur.execute("""
                    UPDATE activity_logs
                    SET app_name=?, category=?
                    WHERE lower(trim(domain))=?
                      AND datetime(replace(substr(ts,1,19),'T',' ')) >= datetime('now', ?)
                """, (app_name, category, domain, f"-{int(args.days)} days"))
                conn.commit()

                updated_domains += 1
                print(f"[{i}/{len(domains)}] {domain} -> {app_name} / {category}")

                if args.sleep > 0:
                    time.sleep(args.sleep)

            except Exception as e:
                print(f"[{i}/{len(domains)}] ERROR {domain}: {e}")

        try:
            cur.execute("DELETE FROM ai_user_report_cache")
            conn.commit()
            print("cleared ai_user_report_cache")
        except Exception as e:
            print(f"cache clear warning: {e}")

        print(f"updated_domains={updated_domains}")
        print(f"unresolved_domains={unresolved}")

        print("\ncategory_distribution_last_window:")
        rows = cur.execute("""
            SELECT category, COUNT(*) AS n
            FROM activity_logs
            WHERE datetime(replace(substr(ts,1,19),'T',' ')) >= datetime('now', ?)
            GROUP BY category
            ORDER BY n DESC, category ASC
        """, (f"-{int(args.days)} days",)).fetchall()

        for r in rows:
            print(f'{r["category"]}: {r["n"]}')

        conn.close()


if __name__ == "__main__":
    main()
