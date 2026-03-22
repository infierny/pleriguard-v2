#!/usr/bin/env python3
"""
intel_collector.py - Intel collection for Pleriguard V2.
Collects WHOIS, DNS, HTTP, screenshots for domains in cert_domains.
"""
import argparse, json, os, re, signal, sys, time
from datetime import datetime, timezone

def _json_safe(obj):
    """Handle datetime and other non-serializable objects in JSON."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)

# Brand matching cache (loaded once)
_BRAND_CACHE = None

def _load_brand_cache():
    """Load brands into a cache for fast URL matching."""
    global _BRAND_CACHE
    if _BRAND_CACHE is not None:
        return _BRAND_CACHE
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, brand, keyword, main_domain FROM brands WHERE active = TRUE OR active IS NULL")
        _BRAND_CACHE = [
            {"id": r[0], "brand": r[1], "keyword": r[2], "main_domain": r[3]}
            for r in cur.fetchall()
        ]
    return _BRAND_CACHE

def _find_brand_from_url(full_url, domain):
    """Find brand match from URL string. Returns (brand_id, brand_name, keyword, main_domain)."""
    import tldextract
    brands = _load_brand_cache()
    url_lower = (full_url or domain or "").lower()
    ext = tldextract.extract(full_url or domain)
    # Also check domain parts
    domain_lower = (domain or "").lower()
    for b in brands:
        kw = (b["keyword"] or "").lower()
        if not kw:
            continue
        # Check if keyword appears as whole token in URL or domain
        # Use word boundaries to avoid partial matches
        import re
        pattern = r'(^|[\.\-_/])' + re.escape(kw) + r'($|[\.\-_/])'
        if re.search(pattern, url_lower) or re.search(pattern, domain_lower):
            return b["id"], b["brand"], b["keyword"], b["main_domain"]
    return None, None, None, None

import dns.resolver
import requests
import whois as python_whois

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    INTEL_BATCH_SIZE, INTEL_WHOIS_TIMEOUT, INTEL_HTTP_TIMEOUT,
    INTEL_SCREENSHOT_TIMEOUT, INTEL_SCREENSHOT_DIR,
)
from db import get_conn, get_cursor, ensure_schema

_running = True

def _signal_handler(sig, frame):
    global _running
    _running = False
    print("\n⛔ Intel collector shutting down...")

signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)

# ── WHOIS ───────────────────────────────────────────────────────────────────
def collect_whois(domain):
    try:
        w = python_whois.whois(domain)
        if w is None:
            return {"error": "WHOIS returned None"}
        registrar = w.get("registrar") or None
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else None
        creation = w.get("creation_date")
        if isinstance(creation, list):
            creation = creation[0]
        if creation and not isinstance(creation, datetime):
            creation = None
        expiry = w.get("expiration_date") or w.get("expiry_date")
        if isinstance(expiry, list):
            expiry = expiry[0]
        if expiry and not isinstance(expiry, datetime):
            expiry = None
        ns = w.get("name_servers") or []
        if isinstance(ns, str):
            ns = [ns]
        ns = [str(n).lower().rstrip('.') for n in ns if n]
        country = w.get("country") or w.get("registrant_country") or None
        if isinstance(country, list):
            country = country[0]
        raw = {}
        for key in getattr(w, 'keys', lambda: [])():
            val = w.get(key)
            if isinstance(val, datetime):
                val = val.isoformat()
            raw[key] = val
        return {
            "registrar": registrar,
            "creation_date": creation,
            "expiry_date": expiry,
            "nameservers": list(set(ns)),
            "country": country,
            "raw": raw,
        }
    except Exception as e:
        return {"error": str(e)}

# ── DNS ─────────────────────────────────────────────────────────────────────
def collect_dns(domain):
    result = {"a": [], "mx": [], "ns": [], "cname": None, "resolves": False}
    try:
        a = dns.resolver.resolve(domain, 'A')
        result["a"] = [str(r) for r in a]
        result["resolves"] = True
    except Exception:
        pass
    try:
        mx = dns.resolver.resolve(domain, 'MX')
        result["mx"] = [str(r).split()[-1] for r in mx]
    except Exception:
        pass
    try:
        ns = dns.resolver.resolve(domain, 'NS')
        result["ns"] = [str(r).rstrip('.') for r in ns]
    except Exception:
        pass
    try:
        cname = dns.resolver.resolve(domain, 'CNAME')
        result["cname"] = str(cname[0]).rstrip('.')
    except Exception:
        pass
    return result

# ── HTTP ────────────────────────────────────────────────────────────────────
def collect_http(domain):
    result = {"status": None, "final_url": None, "title": None, "server": None, "redirects": [], "content": None}
    session = requests.Session()
    session.max_redirects = 5
    try:
        r = session.get(f"http://{domain}", timeout=INTEL_HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
        result["status"] = r.status_code
        result["final_url"] = r.url
        result["redirects"] = [str(h.url) for h in r.history]
        result["title"] = None
        result["server"] = r.headers.get("Server")
        # Try to get title from content
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(r.text, 'html.parser')
            if soup.title:
                result["title"] = soup.title.string
            result["content"] = soup.get_text()[:5000]  # first 5k chars
        except Exception:
            result["content"] = r.text[:5000]
    except requests.exceptions.TooManyRedirects:
        result["status"] = 599
        result["error"] = "Too many redirects"
    except Exception as e:
        result["status"] = None
        result["error"] = str(e)
    return result

# ── Pending domains ──────────────────────────────────────────────────────────
def get_pending_domains(batch_size):
    """
    Get domains from cert_domains that are pending classification.
    Only fetches URLs that:
    - Are not duplicates seen <24h ago (classification_status != 'duplicate_skip')
    - Haven't been processed yet for intel
    Returns full_url + domain + subdomain for evaluation.
    """
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT cd.id, cd.domain, cd.subdomain, cd.full_url,
                   bm.brand_id, b.brand, b.keyword, b.main_domain
            FROM cert_domains cd
            LEFT JOIN brand_matches bm ON bm.cert_domain_id = cd.id
            LEFT JOIN brands b ON b.id = bm.brand_id
            WHERE cd.classification_status = 'pending'
              AND cd.id NOT IN (SELECT cert_domain_id FROM intel_results WHERE cert_domain_id IS NOT NULL)
            ORDER BY cd.seen_count DESC, cd.first_seen DESC
            LIMIT %s
        """, (batch_size,))
        rows = cur.fetchall()
        cur.close()
        return rows

def process_domain(cert_domain_id, domain, subdomain, full_url, brand_id, brand, keyword, main_domain=None):
    # If no brand info from brand_matches, try to find brand from URL
    if brand_id is None:
        brand_id, brand, keyword, main_domain = _find_brand_from_url(full_url, domain)

    whois = collect_whois(domain)
    dns = collect_dns(domain)
    http = collect_http(domain)

    status = 'collected' if http.get('status') else 'unreachable'
    error = http.get('error')

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO intel_results (
                cert_domain_id, domain, full_url, subdomain, brand_match, brand_keyword_matched,
                whois_registrar, whois_creation_date, whois_expiry_date,
                whois_nameservers, whois_registrant_country, whois_raw,
                dns_a_records, dns_mx_records, dns_ns_records, dns_cname, dns_resolves,
                http_status, http_final_url, http_title, http_redirects, http_server, http_content,
                intel_status, error_message, brand_main_domain
            ) VALUES (
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
            )
        """, (
            cert_domain_id, domain, full_url, subdomain, brand,
            keyword if keyword else None,
            whois.get("registrar"),
            whois.get("creation_date"),
            whois.get("expiry_date"),
            whois.get("nameservers"),
            whois.get("country"),
            json.dumps(whois.get("raw", {}), default=_json_safe),
            dns.get("a"),
            dns.get("mx"),
            dns.get("ns"),
            dns.get("cname"),
            dns.get("resolves"),
            http.get("status"),
            http.get("final_url"),
            http.get("title"),
            http.get("redirects"),
            http.get("server"),
            http.get("content"),
            status,
            error,
            main_domain,
        ))

        # Update cert_domains to mark intel as done
        cur.execute("""
            UPDATE cert_domains
            SET classification_status = 'intel_done'
            WHERE id = %s
        """, (cert_domain_id,))

        # Update intel_status to 'done' so classifier can pick it up
        cur.execute("SELECT lastval()")
        intel_id = cur.fetchone()[0]
        cur.execute("UPDATE intel_results SET intel_status = 'done' WHERE id = %s", (intel_id,))

        conn.commit()
        cur.close()

def process_batch():
    domains = get_pending_domains(INTEL_BATCH_SIZE)
    if not domains:
        return 0
    print(f"📡 Processing {len(domains)} URLs...")
    for row in domains:
        cert_domain_id, domain, subdomain, full_url, brand_id, brand, keyword, main_domain = row
        print(f"  {full_url}...", end=" ", flush=True)
        try:
            process_domain(cert_domain_id, domain, subdomain, full_url, brand_id, brand, keyword, main_domain)
            print("✅")
        except Exception as e:
            print(f"❌ {e}")
    return len(domains)

def main():
    parser = argparse.ArgumentParser(description="Pleriguard V2 Intel Collector")
    parser.add_argument("--loop", action="store_true")
    args = parser.parse_args()

    ensure_schema()
    print("🎯 Pleriguard V2 Intel Collector starting...")

    if args.loop:
        while _running:
            count = process_batch()
            if count == 0:
                print("💤 No pending domains, waiting 30s...")
                for i in range(30):
                    if not _running:
                        break
                    time.sleep(1)
    else:
        process_batch()

if __name__ == "__main__":
    main()
