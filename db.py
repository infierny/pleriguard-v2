"""
db.py - Database helpers for Pleriguard V2.
Connection pool + schema migrations for the pleriguard_v2 database.
"""
import contextlib, psycopg2, psycopg2.pool, psycopg2.extras
from config import DB_CONFIG, DB_POOL_MIN, DB_POOL_MAX

_pool = None

def get_pool():
    global _pool
    if _pool is None:
        _pool = psycopg2.pool.ThreadedConnectionPool(DB_POOL_MIN, DB_POOL_MAX, **DB_CONFIG)
    return _pool

def shutdown_pool():
    global _pool
    if _pool:
        _pool.closeall()
        _pool = None

@contextlib.contextmanager
def get_conn():
    conn = get_pool().getconn()
    try:
        yield conn
    finally:
        get_pool().putconn(conn)

@contextlib.contextmanager
def get_cursor(commit=False):
    with get_conn() as conn:
        cur = conn.cursor()
        try:
            yield cur
            if commit:
                conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()

@contextlib.contextmanager
def get_dict_cursor(commit=False):
    with get_conn() as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            yield cur
            if commit:
                conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()

def ensure_schema():
    """Create all V2 tables and indexes. Idempotent."""
    with get_conn() as conn:
        cur = conn.cursor()
        
        # ── cert_domains: raw CT-discovered domains ────────────────────────────
        # Tracks FULL URL from CT stream for deduplication + subdomain-aware processing
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cert_domains (
                id SERIAL PRIMARY KEY,
                domain TEXT NOT NULL,            -- root domain: amazon.com
                subdomain TEXT,                  -- subdomain part: login (null if none)
                full_url TEXT NOT NULL UNIQUE,   -- complete URL as received from CT
                cert_provider_id TEXT,
                timestamp TIMESTAMP,             -- when first seen in CT stream
                source TEXT DEFAULT 'ct',
                seen_count INTEGER DEFAULT 1,
                first_seen TIMESTAMP DEFAULT NOW(),
                last_seen TIMESTAMP DEFAULT NOW(),
                last_checked_at TIMESTAMP,       -- when last evaluated for classification
                is_duplicate_24h BOOLEAN DEFAULT FALSE,   -- flagged as recent duplicate
                classification_status TEXT DEFAULT 'pending'  -- pending | evaluated | duplicate_skip
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cert_domain ON cert_domains(domain)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cert_seen ON cert_domains(seen_count DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cert_full_url ON cert_domains(full_url)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cert_last_seen ON cert_domains(last_seen)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cert_dup ON cert_domains(is_duplicate_24h, classification_status)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cert_pending ON cert_domains(classification_status) WHERE classification_status = 'pending'")

        # ── brands: target brands for monitoring ──────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS brands (
                id SERIAL PRIMARY KEY,
                brand TEXT NOT NULL,
                name TEXT,
                country TEXT,
                website TEXT,
                sector TEXT,
                main_domain TEXT,
                authorized_domains TEXT[],  -- additional authorized domains/resellers
                keyword TEXT,
                opportunity_score FLOAT DEFAULT 0,
                active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_brands_brand ON brands(brand)")

        # ── brand_matches: CT domain → brand association ─────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS brand_matches (
                id SERIAL PRIMARY KEY,
                cert_domain_id INTEGER REFERENCES cert_domains(id) ON DELETE CASCADE,
                brand_id INTEGER REFERENCES brands(id) ON DELETE CASCADE,
                keyword_matched TEXT,
                match_type TEXT,  -- 'exact' | 'typo' | 'keyword'
                confidence FLOAT DEFAULT 0.5,
                created_at TIMESTAMP DEFAULT NOW(),
                UNIQUE(cert_domain_id, brand_id)
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_bm_cert ON brand_matches(cert_domain_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_bm_brand ON brand_matches(brand_id)")

        # ── intel_results: enriched domain intelligence ───────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS intel_results (
                id SERIAL PRIMARY KEY,
                cert_domain_id INTEGER REFERENCES cert_domains(id) ON DELETE SET NULL,
                domain TEXT NOT NULL,          -- root domain: amazon.com
                full_url TEXT,                 -- complete URL from CT stream
                subdomain TEXT,                 -- subdomain part if any
                brand_match TEXT,
                brand_keyword_matched TEXT,
                -- WHOIS
                whois_registrar TEXT,
                whois_creation_date TIMESTAMP,
                whois_expiry_date TIMESTAMP,
                whois_nameservers TEXT[],
                whois_registrant_country TEXT,
                whois_raw JSONB,
                -- DNS
                dns_a_records TEXT[],
                dns_mx_records TEXT[],
                dns_ns_records TEXT[],
                dns_cname TEXT,
                dns_resolves BOOLEAN,
                -- HTTP
                http_status INTEGER,
                http_final_url TEXT,
                http_title TEXT,
                http_redirects TEXT[],
                http_server TEXT,
                http_content TEXT,
                -- Screenshot
                screenshot_path TEXT,
                screenshot_taken_at TIMESTAMP,
                -- Collection meta
                intel_status TEXT DEFAULT 'pending',
                error_message TEXT,
                brand_main_domain TEXT,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_intel_domain ON intel_results(domain)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_intel_status ON intel_results(intel_status)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_intel_brand ON intel_results(brand_match)")

        # ── classifications: final classification output ──────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS classifications (
                id SERIAL PRIMARY KEY,
                intel_result_id INTEGER REFERENCES intel_results(id) ON DELETE CASCADE,
                category TEXT NOT NULL,  -- PHISHING | BEC_SCAM | BRAND_INFRINGEMENT | BENIGN | DORMANT | UNCERTAIN
                subcategory TEXT,
                probability_score FLOAT,
                confidence TEXT,  -- high | medium | low
                evidence JSONB,   -- structured evidence dict
                reason TEXT,      -- human-readable reasoning
                source TEXT DEFAULT 'v2_classifier',
                reviewed BOOLEAN DEFAULT FALSE,
                review_override TEXT,
                review_reason TEXT,
                next_check_at TIMESTAMP,  -- for DORMANT monitoring queue
                check_count INTEGER DEFAULT 0,  -- how many times we've re-checked
                created_at TIMESTAMP DEFAULT NOW(),
                reviewed_at TIMESTAMP
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cls_intel ON classifications(intel_result_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cls_category ON classifications(category)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cls_reviewed ON classifications(reviewed)")

        # ── learning_examples: manual reviews for few-shot learning ───────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS learning_examples (
                id SERIAL PRIMARY KEY,
                domain TEXT NOT NULL,
                brand TEXT,
                ai_classification TEXT,
                manual_classification TEXT,
                reasoning TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_learn_active ON learning_examples(is_active)")

        conn.commit()
        cur.close()

    print("✅ pleriguard_v2 schema ready")
