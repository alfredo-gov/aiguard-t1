#!/usr/bin/env python3
"""
AIGuard T1 - Monthly Report Generator v1
YOUR_ORGANIZATION_NAME -- YOUR_DIVISION

Usage:
    python3 aiguard_report.py [--month YYYY-MM] [--output /path/to/report.docx]
"""

import sqlite3
import argparse
import os
import sys
import json
import subprocess
import tempfile
from datetime import datetime, date
from calendar import monthrange

DB_PATH     = "/home/aiguard/aiguard/data/events.db"
REPORTS_DIR = "/home/aiguard/aiguard/data/reports"

KEEPALIVE_MAX = 200
ACTIVE_MIN    = 2000
HEAVY_MIN     = 50000

PROVIDER_LABELS = {
    "ms_copilot":    "Microsoft Copilot",
    "google_gemini": "Google Gemini",
    "anthropic":     "Anthropic (Claude)",
    "openai":        "OpenAI (ChatGPT)",
    "huggingface":   "Hugging Face",
    "deepseek":      "DeepSeek",
    "mistral":       "Mistral AI",
    "xai_grok":      "xAI Grok",
    "perplexity":    "Perplexity AI",
    "you_ai":        "You.com",
    "poe":           "Poe",
    "character_ai":  "Character.AI",
    "groq":          "Groq",
    "meta_ai":       "Meta AI",
    "cohere":        "Cohere",
}

def get_label(p):
    return PROVIDER_LABELS.get(p, p)

def query_db(sql, params=()):
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    cur = conn.execute(sql, params)
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_month_bounds(month_str):
    year, mon = map(int, month_str.split("-"))
    start = date(year, mon, 1).isoformat()
    last  = monthrange(year, mon)[1]
    end   = date(year, mon, last).isoformat() + "T23:59:59"
    return start, end

def fmt_bytes(b):
    if b is None: return "0 B"
    b = int(b)
    if b < 1024:     return f"{b} B"
    if b < 1024**2:  return f"{b/1024:.1f} KB"
    return f"{b/1024**2:.1f} MB"

def pct(n, total):
    if not total: return "0%"
    return f"{n/total*100:.1f}%"

def collect_data(month_str):
    start, end = get_month_bounds(month_str)
    year, mon  = map(int, month_str.split("-"))
    month_name = date(year, mon, 1).strftime("%B %Y")

    total = query_db(
        "SELECT COUNT(*) as c FROM events WHERE timestamp BETWEEN ? AND ?",
        (start, end))[0]["c"]

    tiers = query_db("""
        SELECT
            SUM(CASE WHEN size < ? THEN 1 ELSE 0 END) as keepalive,
            SUM(CASE WHEN size >= ? AND size < ? THEN 1 ELSE 0 END) as small_events,
            SUM(CASE WHEN size >= ? AND size < ? THEN 1 ELSE 0 END) as active_sessions,
            SUM(CASE WHEN size >= ? THEN 1 ELSE 0 END) as heavy_sessions,
            SUM(size) as total_bytes
        FROM events WHERE timestamp BETWEEN ? AND ?
    """, (KEEPALIVE_MAX,
          KEEPALIVE_MAX, ACTIVE_MIN,
          ACTIVE_MIN, HEAVY_MIN,
          HEAVY_MIN,
          start, end))[0]

    by_provider = query_db("""
        SELECT provider,
               COUNT(*) as total_events,
               SUM(CASE WHEN size >= ? THEN 1 ELSE 0 END) as active_sessions,
               SUM(size) as total_bytes
        FROM events WHERE timestamp BETWEEN ? AND ?
        GROUP BY provider ORDER BY active_sessions DESC
    """, (ACTIVE_MIN, start, end))

    by_dept = query_db("""
        SELECT department,
               COUNT(*) as total_events,
               SUM(CASE WHEN size >= ? THEN 1 ELSE 0 END) as active_sessions,
               SUM(size) as total_bytes
        FROM events
        WHERE timestamp BETWEEN ? AND ?
          AND department IS NOT NULL AND department != 'Unknown'
        GROUP BY department ORDER BY active_sessions DESC
    """, (ACTIVE_MIN, start, end))

    dlp_summary = query_db("""
        SELECT severity, COUNT(*) as count FROM dlp_alerts
        WHERE timestamp BETWEEN ? AND ?
        GROUP BY severity
        ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END
    """, (start, end))

    dlp_top = query_db("""
        SELECT timestamp, src, provider, severity, department
        FROM dlp_alerts
        WHERE timestamp BETWEEN ? AND ? AND severity IN ('CRITICAL','HIGH')
        ORDER BY timestamp DESC LIMIT 10
    """, (start, end))

    top_sources = query_db("""
        SELECT src, department,
               COUNT(*) as total_events,
               SUM(CASE WHEN size >= ? THEN 1 ELSE 0 END) as active_sessions
        FROM events
        WHERE timestamp BETWEEN ? AND ? AND src LIKE 'YOUR_NETWORK_PREFIX.%'
        GROUP BY src ORDER BY active_sessions DESC LIMIT 10
    """, (ACTIVE_MIN, start, end))

    return {
        "month_str":   month_str,
        "month_name":  month_name,
        "generated":   datetime.now().strftime("%Y-%m-%d %H:%M CDT"),
        "total":       total,
        "keepalive":   tiers["keepalive"] or 0,
        "small":       tiers["small_events"] or 0,
        "active":      tiers["active_sessions"] or 0,
        "heavy":       tiers["heavy_sessions"] or 0,
        "total_bytes": fmt_bytes(tiers["total_bytes"]),
        "by_provider": [
            {
                "label":          get_label(p["provider"]),
                "total_events":   f"{p['total_events']:,}",
                "active_sessions":f"{p['active_sessions']:,}",
                "pct_active":     pct(p["active_sessions"], total),
                "data_volume":    fmt_bytes(p["total_bytes"]),
            } for p in by_provider
        ],
        "by_dept": [
            {
                "department":     dep["department"],
                "total_events":   f"{dep['total_events']:,}",
                "active_sessions":f"{dep['active_sessions']:,}",
                "data_volume":    fmt_bytes(dep["total_bytes"]),
            } for dep in by_dept
        ],
        "dlp_summary": [
            {"severity": r["severity"], "count": f"{r['count']:,}"}
            for r in dlp_summary
        ],
        "dlp_top": [
            {
                "timestamp": r["timestamp"][:16].replace("T", " "),
                "src":       r["src"],
                "provider":  get_label(r["provider"]),
                "severity":  r["severity"],
                "dept":      r["department"] or "Unknown",
            } for r in dlp_top
        ],
        "top_sources": [
            {
                "src":            s["src"],
                "department":     s["department"] or "Unknown",
                "total_events":   f"{s['total_events']:,}",
                "active_sessions":f"{s['active_sessions']:,}",
            } for s in top_sources
        ],
        "thresholds": {
            "keepalive_max": KEEPALIVE_MAX,
            "active_min":    ACTIVE_MIN,
            "heavy_min":     HEAVY_MIN,
        }
    }

def build_docx(data, output_path):
    js_template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aiguard_report_template.js")

    # Write data to temp JSON
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as jf:
        json.dump(data, jf)
        json_path = jf.name

    try:
        result = subprocess.run(
            ['node', js_template_path, json_path, output_path],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            print(f"[ERROR] {result.stderr}", file=sys.stderr)
            sys.exit(1)
        print(result.stdout.strip())
    finally:
        os.unlink(json_path)

def main():
    parser = argparse.ArgumentParser(description="AIGuard T1 Report Generator")
    parser.add_argument("--month",  default=date.today().strftime("%Y-%m"))
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    if args.output is None:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        args.output = os.path.join(REPORTS_DIR, f"AIGuard_Report_{args.month}.docx")

    print(f"[AIGuard] Generating report for {args.month}...")
    data = collect_data(args.month)
    print(f"[AIGuard] {data['total']:,} total events | {data['active']:,} active sessions")
    build_docx(data, args.output)

if __name__ == "__main__":
    main()
