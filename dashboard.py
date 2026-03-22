#!/usr/bin/env python3
"""
dashboard.py - Pleriguard V2 Pipeline Monitor Dashboard
Shows real-time status of each stage: Collector → Intel → Classifier
"""
import os, sys, time
from datetime import datetime, timedelta
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flask import Flask, render_template_string, jsonify
from db import get_conn

app = Flask(__name__)

# ─── Helpers ─────────────────────────────────────────────────────────────────

def dict_fetchall(cur):
    columns = [desc[0] for desc in cur.description]
    return [dict(zip(columns, row)) for row in cur.fetchall()]

def get_stats(filter_category=None):
    stats = {}
    with get_conn() as conn:
        cur = conn.cursor()

        # ── CT Collector stats ──────────────────────────────────────────────
        cur.execute("SELECT COUNT(*) as total FROM cert_domains")
        stats['ct_total'] = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM cert_domains WHERE classification_status = 'pending'")
        stats['ct_pending'] = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM cert_domains WHERE is_duplicate_24h = TRUE")
        stats['ct_duplicates_24h'] = cur.fetchone()[0]

        cur.execute("SELECT COUNT(DISTINCT domain) FROM cert_domains")
        stats['ct_unique_roots'] = cur.fetchone()[0]

        cur.execute("""
            SELECT DATE(first_seen) as day, COUNT(*) as count
            FROM cert_domains
            WHERE first_seen > NOW() - INTERVAL '7 days'
            GROUP BY DATE(first_seen)
            ORDER BY day DESC
        """)
        stats['ct_daily'] = dict_fetchall(cur)

        # ── Intel Collector stats ───────────────────────────────────────────
        cur.execute("SELECT COUNT(*) FROM intel_results")
        stats['intel_total'] = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM intel_results ir
            WHERE NOT EXISTS (
                SELECT 1 FROM classifications cls WHERE cls.intel_result_id = ir.id
            )
        """)
        stats['intel_pending'] = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM intel_results WHERE intel_status = 'unreachable'")
        stats['intel_unreachable'] = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM intel_results WHERE intel_status = 'collected'")
        stats['intel_collected'] = cur.fetchone()[0]

        # ── Classifier stats ─────────────────────────────────────────────────
        cur.execute("SELECT COUNT(*) FROM classifications")
        stats['cls_total'] = cur.fetchone()[0]

        cur.execute("""
            SELECT category, COUNT(*) as count
            FROM classifications
            GROUP BY category
            ORDER BY count DESC
        """)
        stats['cls_by_category'] = dict_fetchall(cur)

        cur.execute("""
            SELECT cls.category, COUNT(*) as count
            FROM classifications cls
            JOIN intel_results ir ON ir.id = cls.intel_result_id
            WHERE ir.first_seen > NOW() - INTERVAL '24 hours'
            GROUP BY cls.category
        """)
        stats['cls_last_24h'] = dict_fetchall(cur)

        cur.execute("""
            SELECT COUNT(*)
            FROM classifications
            WHERE next_check_at IS NOT NULL
              AND next_check_at <= NOW()
        """)
        stats['dormant_due'] = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*)
            FROM classifications
            WHERE next_check_at IS NOT NULL
        """)
        stats['dormant_monitoring'] = cur.fetchone()[0]

        # ── Recent classifications (with optional category filter) ──────────
        if filter_category:
            cur.execute("""
                SELECT ir.domain, ir.full_url, ir.brand_match, cls.category,
                       cls.probability_score, cls.confidence, cls.reason, cls.created_at
                FROM classifications cls
                JOIN intel_results ir ON ir.id = cls.intel_result_id
                WHERE cls.category = %s
                ORDER BY cls.created_at DESC
                LIMIT 50
            """, (filter_category,))
        else:
            cur.execute("""
                SELECT ir.domain, ir.full_url, ir.brand_match, cls.category,
                       cls.probability_score, cls.confidence, cls.reason, cls.created_at
                FROM classifications cls
                JOIN intel_results ir ON ir.id = cls.intel_result_id
                ORDER BY cls.created_at DESC
                LIMIT 20
            """)
        stats['recent'] = dict_fetchall(cur)

        cur.close()
    return stats

# ─── HTML Template ────────────────────────────────────────────────────────────

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="10">
<title>Pleriguard V2 — Pipeline Monitor</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0d1117; color: #e6edf3; font-size: 14px; }
h1 { padding: 20px 24px 10px; border-bottom: 1px solid #21262d; font-size: 18px; color: #58a6ff; }
h2 { font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; color: #8b949e; margin: 20px 24px 10px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; padding: 0 24px 16px; }
.card { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 16px; }
.card .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: #8b949e; margin-bottom: 6px; }
.card .value { font-size: 28px; font-weight: 600; color: #e6edf3; }
.card .sub { font-size: 11px; color: #8b949e; margin-top: 4px; }
.card.alert { border-color: #f85149; background: #f8514910; }
.card.warn { border-color: #d29922; background: #d2992210; }
.card.good { border-color: #3fb950; background: #3fb95010; }
table { width: 100%; border-collapse: collapse; margin: 0 24px 16px; }
th { text-align: left; font-size: 11px; text-transform: uppercase; color: #8b949e; padding: 8px 10px; border-bottom: 1px solid #21262d; }
td { padding: 8px 10px; border-bottom: 1px solid #161b22; font-size: 13px; }
tr:hover td { background: #161b22; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
.badge-PHISHING { background: #f8514925; color: #ff7b72; }
.badge-BEC_SCAM { background: #d2992225; color: #e3b341; }
.badge-BRAND_INFRINGEMENT { background: #a371f725; color: #bc8cff; }
.badge-DORMANT { background: #8b949e25; color: #8b949e; }
.badge-BENIGN { background: #3fb95025; color: #7ee787; }
.badge-UNCERTAIN { background: #58a6ff25; color: #58a6ff; }
.badge-ERROR { background: #f8514925; color: #ff7b72; }
.score { font-weight: 600; }
.url { font-size: 12px; color: #8b949e; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.reason { font-size: 11px; color: #6e7681; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.section { margin-bottom: 24px; }
.timestamp { text-align: right; font-size: 11px; color: #484f58; padding: 10px 24px; }
.row { display: flex; gap: 8px; flex-wrap: wrap; padding: 0 24px 16px; }
.pill { background: #21262d; border-radius: 16px; padding: 6px 12px; font-size: 12px; }
.pill .cat { font-weight: 600; }
</style>
</head>
<body>
<h1>🛡️ Pleriguard V2 — Pipeline Monitor</h1>

<div style="margin: 10px 24px;">
  <a href="http://localhost:5011" target="_blank" style="background: #238636; color: white; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-size: 13px;">
    🏷️ Manage Brands
  </a>
</div>

<div class="row">
  <div class="pill">CT Collector: <strong>{{ stats.ct_total|default(0)|int|commas }}</strong> URLs</div>
  <div class="pill">Pending Intel: <strong>{{ stats.intel_pending|default(0)|int|commas }}</strong></div>
  <div class="pill">Pending Classification: <strong>{{ stats.ct_pending|default(0)|int|commas }}</strong></div>
  <div class="pill">Dormant Monitoring: <strong>{{ stats.dormant_monitoring|default(0)|int|commas }}</strong></div>
  {% if stats.dormant_due|default(0) > 0 %}
  <div class="pill alert">⚠️ {{ stats.dormant_due }} dormant due for re-check</div>
  {% endif %}
</div>

<h2>📡 CT Stream Collector</h2>
<div class="grid">
  <div class="card">
    <div class="label">Total URLs Collected</div>
    <div class="value">{{ stats.ct_total|default(0)|int|commas }}</div>
  </div>
  <div class="card">
    <div class="label">Unique Root Domains</div>
    <div class="value">{{ stats.ct_unique_roots|default(0)|int|commas }}</div>
  </div>
  <div class="card warn">
    <div class="label">Pending Processing</div>
    <div class="value">{{ stats.ct_pending|default(0)|int|commas }}</div>
  </div>
  <div class="card">
    <div class="label">Duplicates (24h)</div>
    <div class="value">{{ stats.ct_duplicates_24h|default(0)|int|commas }}</div>
  </div>
</div>

<h2>🔍 Intel Collector</h2>
<div class="grid">
  <div class="card">
    <div class="label">Total Intel Collected</div>
    <div class="value">{{ stats.intel_total|default(0)|int|commas }}</div>
  </div>
  <div class="card warn">
    <div class="label">Pending Intel</div>
    <div class="value">{{ stats.intel_pending|default(0)|int|commas }}</div>
  </div>
  <div class="card">
    <div class="label">HTTP Collected</div>
    <div class="value">{{ stats.intel_collected|default(0)|int|commas }}</div>
  </div>
  <div class="card">
    <div class="label">Unreachable</div>
    <div class="value">{{ stats.intel_unreachable|default(0)|int|commas }}</div>
  </div>
</div>

<h2>🎯 Classifier</h2>
<div class="grid">
  <div class="card">
    <div class="label">Total Classified</div>
    <div class="value">{{ stats.cls_total|default(0)|int|commas }}</div>
  </div>
  {% for item in stats.cls_by_category|default([]) %}
  <div class="card {% if item.category == 'PHISHING' %}alert{% elif item.category == 'DORMANT' %}warn{% elif item.category == 'BENIGN' %}good{% endif %}">
    <div class="label">{{ item.category }}</div>
    <div class="value">{{ item.count|int|commas }}</div>
  </div>
  {% endfor %}
</div>

<h2>🕐 Recent Classifications 
{% if stats.filter_category %}
  - Filtered by: <span class="badge badge-{{ stats.filter_category }}">{{ stats.filter_category }}</span>
  <a href="/" style="color: #58a6ff; text-decoration: none; font-size: 12px;">[Clear Filter]</a>
{% else %}
  (Last 20)
{% endif %}
</h2>

<div class="row" style="margin-bottom: 16px;">
  <div class="pill"><a href="/category/phishing" style="color: inherit; text-decoration: none;">🎯 PHISHING</a></div>
  <div class="pill"><a href="/category/bec_scam" style="color: inherit; text-decoration: none;">💰 BEC_SCAM</a></div>
  <div class="pill"><a href="/category/brand_infringement" style="color: inherit; text-decoration: none;">🏷️ BRAND_INFRINGEMENT</a></div>
  <div class="pill"><a href="/category/dormant" style="color: inherit; text-decoration: none;">💤 DORMANT</a></div>
  <div class="pill"><a href="/category/benign" style="color: inherit; text-decoration: none;">✅ BENIGN</a></div>
  <div class="pill"><a href="/" style="color: inherit; text-decoration: none;">📋 ALL</a></div>
</div>
<table>
<thead>
<tr>
  <th>Domain / URL</th>
  <th>Brand</th>
  <th>Category</th>
  <th>Score</th>
  <th>Confidence</th>
  <th>Reason</th>
  <th>Time</th>
</tr>
</thead>
<tbody>
{% for r in stats.recent|default([]) %}
<tr>
  <td>
    <a href="https://{{ (r.full_url or r.domain)|clean_url }}" target="_blank" style="text-decoration: none; color: inherit;">
      <div class="url" title="{{ r.full_url or r.domain }}" style="cursor: pointer; color: #58a6ff;">{{ r.domain }}</div>
    </a>
  </td>
  <td>{{ r.brand_match or '—' }}</td>
  <td><span class="badge badge-{{ r.category }}">{{ r.category }}</span></td>
  <td class="score">{{ (r.probability_score or 0)|round|int }}%</td>
  <td>{{ r.confidence or '—' }}</td>
  <td><div class="reason" title="{{ r.reason }}">{{ r.reason|truncate(80) if r.reason else '—' }}</div></td>
  <td style="color:#8b949e; font-size:11px;">{{ r.created_at.strftime('%H:%M') if r.created_at else '—' }}</td>
</tr>
{% endfor %}
{% if not stats.recent %}<tr><td colspan="7" style="text-align:center; color:#8b949e; padding:30px;">No classifications yet</td></tr>{% endif %}
</tbody>
</table>

<div class="timestamp">
  Last updated: {{ now }} · Auto-refreshes every 10s
</div>
</body>
</html>
"""

# Register Jinja2 filters
def commas(value):
    return f"{value:,}"

def clean_url(url):
    """Clean URL for browser navigation - remove wildcards and fix common issues"""
    if not url:
        return ""
    
    # Remove wildcard prefixes
    cleaned = url.replace("*.", "")
    
    # Remove protocol if present to avoid double protocol
    cleaned = cleaned.replace("https://", "").replace("http://", "")
    
    # Remove any trailing slashes or paths for clean domain access
    cleaned = cleaned.split("/")[0].split("?")[0]
    
    return cleaned

app.jinja_env.filters['commas'] = commas
app.jinja_env.filters['clean_url'] = clean_url

@app.route('/')
def index():
    stats = get_stats()
    stats['now'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    stats['filter_category'] = None  # No filter
    return render_template_string(TEMPLATE, stats=stats)

@app.route('/category/<category>')
def category_filter(category):
    stats = get_stats(filter_category=category.upper())
    stats['now'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    stats['filter_category'] = category.upper()
    return render_template_string(TEMPLATE, stats=stats)

@app.route('/api/stats')
def api_stats():
    return jsonify(get_stats())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5010, debug=False)
