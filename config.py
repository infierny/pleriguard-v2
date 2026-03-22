"""
config.py - Pleriguard V2 Configuration
"""
import os

# ─── Database ─────────────────────────────────────────────────────────────────
DB_CONFIG = {
    'host': os.environ.get('PGHOST', 'localhost'),
    'port': int(os.environ.get('PGPORT', 5432)),
    'database': 'pleriguard_v2',
    'user': os.environ.get('PGUSER', 'fernandocevallos'),
}
DB_POOL_MIN = 2
DB_POOL_MAX = 10

# ─── Certstream ───────────────────────────────────────────────────────────────
CERTSTREAM_URL = "ws://localhost:4000/"
CERTSTREAM_URLS = ["ws://localhost:4000/"]
COLLECTOR_FLUSH_INTERVAL = 3.0
COLLECTOR_BUFFER_SIZE = 50
COLLECTOR_STATS_INTERVAL = 30  # seconds between stats prints

# ─── CT Stream Collector ───────────────────────────────────────────────────────
COLLECTOR_INTERVAL = 60
COLLECTOR_BATCH = 100

# ─── Intel Collection ──────────────────────────────────────────────────────────
INTEL_BATCH_SIZE = 20
INTEL_WHOIS_TIMEOUT = 10
INTEL_HTTP_TIMEOUT = 15
INTEL_SCREENSHOT_TIMEOUT = 30
INTEL_SCREENSHOT_DIR = os.path.join(os.path.dirname(__file__), "screenshots")

# ─── Classification ────────────────────────────────────────────────────────────
CLASSIFIER_BATCH_SIZE = 20
CLASSIFIER_INTERVAL = 30

# ─── DORMANT Monitoring Schedule ──────────────────────────────────────────────
# Based on WHOIS creation_date age (domain aging concept):
# New domains are more likely to activate soon → frequent checks
# Old dormant domains → rare checks, but still monitored
DORMANT_BY_DOMAIN_AGE = [
    (7,    2),    # Domain created <7 days ago: check every 2h
    (30,   6),    # 7-30 days: every 6h
    (90,   24),   # 30-90 days: every 24h
    (180,  72),   # 90-180 days: every 3 days
    (365,  168),  # 180-365 days: every week
]
# Domains older than 1 year: check once a month (720h)
DORMANT_OLD_DOMAIN_INTERVAL = 720

# ─── LLM API ──────────────────────────────────────────────────────────────────
USE_OPENROUTER = True
OPENROUTER_API_KEY = os.environ.get('OPENROUTER_API_KEY', '')
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL = "minimax/minimax-m2.7"

MINIMAX_API_KEY = os.environ.get('MINIMAX_API_KEY', 'sk-cp-cQFCJ45syrSI2VoTXjmob1acUbho_SG52fNvSA-msf3EEM5p3NLX-zDjbTX1gUTmxETu_eYSSJkDNaHzrIiCKgMQ_CGl-PHIYc0tVSEAZH-Fg7zR6TBjP48')
MINIMAX_URL = "https://api.minimax.io/v1/text/chatcompletion_v2"

# ─── PID file ─────────────────────────────────────────────────────────────────
PID_FILE = os.path.join(os.path.dirname(__file__), "logs", "collector_v2.pid")
