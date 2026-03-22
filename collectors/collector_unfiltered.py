#!/usr/bin/env python3
"""
collector.py - CT Stream collector for Pleriguard V2.
Collects domains from Certificate Transparency logs and stores in cert_domains.
"""
import argparse, json, os, re, signal, sys, threading, time, tldextract, websocket
from datetime import datetime, timezone
import psycopg2
from psycopg2 import errors
from psycopg2.extras import execute_values

# ── V2 imports ──────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    CERTSTREAM_URL, CERTSTREAM_URLS, COLLECTOR_FLUSH_INTERVAL,
    COLLECTOR_BUFFER_SIZE, PID_FILE,
)
from db import get_conn, ensure_schema

# ── PID ──────────────────────────────────────────────────────────────────────
PID_FILE_V2 = PID_FILE.replace('.pid', '_v2.pid')

def acquire_pid_lock():
    os.makedirs(os.path.dirname(PID_FILE_V2), exist_ok=True)
    pid = str(os.getpid())
    if os.path.exists(PID_FILE_V2):
        try:
            with open(PID_FILE_V2) as f:
                existing = int(f.read().strip())
            os.kill(existing, 0)
            print(f"❌ Collector already running (PID {existing}). Kill it first.")
            return False
        except (OSError, ValueError):
            pass
    with open(PID_FILE_V2, 'w') as f:
        f.write(pid)
    return True

def release_pid_lock():
    try:
        if os.path.exists(PID_FILE_V2):
            os.remove(PID_FILE_V2)
    except Exception:
        pass

# ── Deadlock retry ──────────────────────────────────────────────────────────
def retry_on_deadlock(func, max_retries=3, base_delay=0.5):
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            if isinstance(e, (psycopg2.OperationalError,)):
                if attempt < max_retries - 1:
                    time.sleep(base_delay * (2 ** attempt))
                else:
                    raise
            else:
                raise

# ── Globals ─────────────────────────────────────────────────────────────────
_buffer = []
_buffer_lock = threading.Lock()
_stats = {"certs_seen": 0, "domains_extracted": 0, "domains_prefiltered": 0, "domains_inserted": 0, "errors": 0}
_running = True
_brand_keywords = set()

# ── Keyword set from V2 brands table ───────────────────────────────────────
def build_keyword_set():
    """Build keyword set from brands table in V2 DB."""
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT brand, keyword FROM brands WHERE active = TRUE")
        keywords = set()
        for brand, keyword in cur.fetchall():
            b = _strip_accents((brand or '').lower().strip())
            if b:
                keywords.add(re.sub(r'[^a-z0-9]', '', b))
                parts = re.split(r'\s+', b)
                for p in parts:
                    if len(p) >= 4:
                        keywords.add(p)
            if keyword:
                for kw in keyword.split(','):
                    kw = _strip_accents(kw.strip().lower())
                    if len(kw) >= 3:
                        keywords.add(re.sub(r'[^a-z0-9]', '', kw))
        cur.close()
    return keywords

def _strip_accents(text):
    replacements = {'á':'a','é':'e','í':'i','ó':'o','ú':'u','ñ':'n','ü':'u','ã':'a','õ':'o','ç':'c'}
    for k, v in replacements.items():
        text = text.replace(k, v)
    return text

def url_matches_any_brand(full_url):
    """
    Check if full URL contains any brand keyword.
    Evaluates against the complete URL string (domain + subdomain + path).
    """
    # Strip protocol and path for matching, but keep subdomain structure
    url_clean = full_url.lower()
    url_alnum = re.sub(r'[^a-z0-9]', '', url_clean)
    tokens = set(re.split(r'[^a-z0-9]+', url_clean))

    for kw in _brand_keywords:
        if len(kw) <= 3:
            if kw in tokens:
                return True
        elif len(kw) == 4:
            if kw in tokens:
                return True
            if re.search(r'(?:^|[.\-_/])' + re.escape(kw) + r'(?:[.\-_/]|$)', url_clean):
                return True
        else:
            if kw in url_alnum or kw in url_clean:
                return True
    return False

# ── Domain extraction ───────────────────────────────────────────────────────
def extract_domains_from_message(msg):
    domains = set()
    try:
        data = msg.get("data", {})
        leaf_cert = data.get("leaf_cert", {})
        all_domains = data.get("all_domains") or leaf_cert.get("all_domains") or []
        for d in all_domains:
            cleaned = _clean_domain(d)
            if cleaned:
                domains.add(cleaned)
        subject = leaf_cert.get("subject", {})
        cn = subject.get("CN", "")
        if cn:
            cleaned = _clean_domain(cn)
            if cleaned:
                domains.add(cleaned)
    except Exception:
        pass
    return domains

def _clean_domain(raw):
    d = raw.strip().lower()
    if d.startswith("*."):
        d = d[2:]
    d = re.sub(r'^https?://', '', d)
    d = d.split('/')[0].split(':')[0].strip('.')
    if not d or '.' not in d or len(d) < 4:
        return None
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', d):
        return None
    if len(d) > 253:
        return None
    return d

# ── Buffer flush ────────────────────────────────────────────────────────────
def flush_buffer():
    """
    Flush domain buffer to DB with full URL tracking + 24h deduplication.

    Logic:
    - full_url is UNIQUE — each URL from CT is tracked individually
    - If full_url seen <24h ago → is_duplicate_24h = TRUE, skip processing
    - If full_url seen >24h ago → update and mark as pending re-evaluation
    - Subdomain variants (login.amazon.com vs amazon.com) → treated as different URLs
    """
    global _buffer
    with _buffer_lock:
        if not _buffer:
            return
        batch = _buffer[:]
        _buffer = []

    if not batch:
        return

    def _do_flush():
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        cutoff_24h = now - timedelta(hours=24)

        with get_conn() as conn:
            cur = conn.cursor()
            processed = 0
            skipped = 0

            for raw_url in batch:
                ext = tldextract.extract(raw_url)
                if not ext.domain or not ext.suffix:
                    continue
                root_domain = f"{ext.domain}.{ext.suffix}"
                subdomain = ext.subdomain or None

                cur.execute("""
                    SELECT id, seen_count, last_seen, is_duplicate_24h
                    FROM cert_domains WHERE full_url = %s
                """, (raw_url,))
                existing = cur.fetchone()

                if existing:
                    cert_id, seen_count, last_seen, is_dup_24h = existing
                    if is_dup_24h and last_seen and last_seen > cutoff_24h:
                        # Exact URL seen <24h ago → skip
                        cur.execute("UPDATE cert_domains SET seen_count = seen_count + 1 WHERE id = %s", (cert_id,))
                        skipped += 1
                        continue
                    # Seen >24h ago → update and mark for re-processing
                    cur.execute("""
                        UPDATE cert_domains
                        SET seen_count = seen_count + 1,
                            last_seen = NOW(),
                            is_duplicate_24h = FALSE,
                            classification_status = 'pending'
                        WHERE id = %s
                    """, (cert_id,))
                    processed += 1
                else:
                    # New URL
                    cur.execute("""
                        INSERT INTO cert_domains (domain, subdomain, full_url, source, timestamp, seen_count, classification_status)
                        VALUES (%s, %s, %s, 'certstream_v2', NOW(), 1, 'pending')
                        ON CONFLICT (full_url) DO NOTHING
                    """, (root_domain, subdomain, raw_url))
                    processed += 1

            conn.commit()
            _stats["domains_inserted"] += processed
            print(f"  💾 Inserted {processed} URLs, {skipped} duplicates skipped. "
                  f"Total: certs={_stats['certs_seen']:,} | collected={_stats['domains_inserted']:,}")

    try:
        retry_on_deadlock(_do_flush)
    except Exception as e:
        _stats["errors"] += 1
        print(f"❌ Flush error: {e}")
        with _buffer_lock:
            _buffer.extend(batch)

def flush_loop():
    while _running:
        time.sleep(COLLECTOR_FLUSH_INTERVAL)
        with _buffer_lock:
            if _buffer:
                threading.Thread(target=flush_buffer, daemon=True).start()

# ── WebSocket ───────────────────────────────────────────────────────────────
_debug_msg_count = 0

def on_message(ws, raw_msg):
    global _debug_msg_count
    print(f"  💬 on_message called! raw_len={len(raw_msg)}")
    try:
        msg = json.loads(raw_msg)
        msg_type = msg.get("message_type", "unknown")
        _debug_msg_count += 1
        # Print first few message types for debugging
        if _debug_msg_count <= 10:
            print(f"  📨 msg #{_debug_msg_count}: type={msg_type}, keys={list(msg.keys())[:5]}")
        if msg_type != "certificate_update":
            if _debug_msg_count <= 3:
                print(f"  ⚠️ Not certificate_update, skipping")
            return
        _stats["certs_seen"] += 1

        # Extract full URLs (before cleaning) for brand matching
        data = msg.get("data", {})
        leaf_cert = data.get("leaf_cert", {})
        all_domains = data.get("all_domains") or leaf_cert.get("all_domains") or []

        for raw_url in all_domains:
            _stats["domains_extracted"] += 1
            # Debug: show first few URLs
            if _stats["domains_extracted"] <= 5:
                print(f"  📍 URL: {raw_url[:80]}")
            # Use FULL URL for brand matching (Fernando's requirement)
            if _brand_keywords and url_matches_any_brand(raw_url):
                _stats["domains_prefiltered"] += 1
                print(f"  ✅ Brand match: {raw_url}")
                # Clean and store full URL
                cleaned = _clean_domain(raw_url)
                if cleaned:
                    with _buffer_lock:
                        _buffer.append(raw_url)  # store full URL, not just cleaned domain
                        print(f"  📝 Buffer: {len(_buffer)}")
                        if len(_buffer) >= COLLECTOR_BUFFER_SIZE:
                            threading.Thread(target=flush_buffer, daemon=True).start()
            elif _stats["certs_seen"] % 100 == 0:
                # Debug: show we're receiving data
                print(f"  🔍 Seen {_stats['certs_seen']} certs, prefiltered: {_stats['domains_prefiltered']}")
    except json.JSONDecodeError:
        _stats["errors"] += 1
    except Exception as e:
        _stats["errors"] += 1

def on_error(ws, error):
    print(f"❌ WS error: {error}")

def on_close(ws, close_status_code, close_msg):
    print(f"🔌 Closed: {close_status_code} {close_msg}")

def _ws_listener(url):
    while _running:
        try:
            print(f"🟢 Connecting to {url}")
            ws = websocket.WebSocketApp(
                url,
                on_message=on_message,
                on_error=on_error,
                on_close=on_close,
                on_open=lambda ws: print(f"🟢 [{url}] connected"),
            )
            ws.run_forever(ping_interval=30, ping_timeout=10)
        except Exception as e:
            print(f"❌ [{url}] Connection failed: {e}")
        if _running:
            print(f"🔄 Reconnecting in 5s...")
            time.sleep(5)

def run_collector(url=None):
    global _running, _brand_keywords
    if not acquire_pid_lock():
        sys.exit(1)

    urls = CERTSTREAM_URLS if CERTSTREAM_URLS else [url or CERTSTREAM_URL]
    print("🚀 Pleriguard V2 Collector starting...")
    ensure_schema()

    _brand_keywords = build_keyword_set()
    print(f"🔑 {len(_brand_keywords)} brand keywords loaded")

    threading.Thread(target=flush_loop, daemon=True).start()

    ws_threads = []
    for u in urls:
        t = threading.Thread(target=_ws_listener, args=(u,), daemon=True)
        t.start()
        ws_threads.append(t)

    try:
        _last_stats_print = time.time()
        while _running:
            time.sleep(1)
            # Print stats every 10 seconds
            if time.time() - _last_stats_print >= 10:
                print(f"📊 Stats: msgs={_debug_msg_count} | certs={_stats['certs_seen']:,} | extracted={_stats['domains_extracted']:,} | matched={_stats['domains_prefiltered']:,} | inserted={_stats['domains_inserted']:,} | errors={_stats['errors']}")
                _last_stats_print = time.time()
    except KeyboardInterrupt:
        _running = False
    flush_buffer()
    release_pid_lock()
    print("🏁 Collector shutdown complete")

def main():
    parser = argparse.ArgumentParser(description="Pleriguard V2 CT Collector")
    parser.add_argument("--url", default=CERTSTREAM_URL)
    args = parser.parse_args()
    run_collector(url=args.url)

if __name__ == "__main__":
    main()
