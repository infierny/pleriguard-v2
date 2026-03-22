#!/usr/bin/env python3
"""
classifier.py - Pleriguard V2 Classification Engine
Rule-based scoring using structured LLM evidence extraction.

Flow:
  intel_results (enriched domain)
    → LLM extracts structured EVIDENCE (JSON)
    → Python scorer applies PHISHING_SPEC rules → classification + score
    → Store in classifications table
"""
import argparse, json, os, re, signal, sys, time
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import MINIMAX_API_KEY, MINIMAX_URL, CLASSIFIER_BATCH_SIZE, CLASSIFIER_INTERVAL
from db import get_conn, get_cursor, ensure_schema

_running = True

def _signal_handler(sig, frame):
    global _running
    _running = False

signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)

# ─── Evidence Extraction Prompt ───────────────────────────────────────────────

SYSTEM_PROMPT = """You are a phishing detection analyst. Your job is to extract STRUCTURED EVIDENCE from a domain's intel data. Output ONLY a valid JSON object — no explanation, no markdown, no text outside the JSON."""

USER_PROMPT_TEMPLATE = """Extract evidence from this domain's intel data.

Domain: {domain}
Brand target: {brand}
HTTP Title: {title}
HTTP Status: {http_status}
HTTP Final URL: {final_url}
Registrar: {registrar}
Creation Date: {creation_date}
Registrant Country: {country}
DNS Resolves: {resolves}
DNS A records: {a_records}
DNS MX records: {mx_records}
Page Content (first 3000 chars): {content}

Output JSON with these exact fields — all booleans or strings:
{{{{
  "has_login_form": true/false,
  "has_login_button": true/false,
  "has_payment_form": true/false,
  "domain_uses_brand_in_subdomain": true/false,
  "domain_uses_brand_in_domain": true/false,
  "domain_has_confusion_keyword": true/false,
  "content_copies_brand_assets": true/false,
  "links_point_to_real_brand": true/false,
  "favicon_copied": true/false,
  "page_is_shallow": true/false,
  "ssl_issuer_is_risky": true/false,
  "registrar_is_retail": true/false,
  "domain_age_days": <number or null>,
  "ip_differs_from_brand": true/false,
  "content_suspicious": "none"/"low"/"medium"/"high",
  "additional_notes": "<brief note if suspicious, else empty string>"
}}}}"""

# Registrars
CORPORATE_REGISTRARS = {
    'markmonitor', 'csc corporate', 'safenames', 'network solutions',
    'domain protect', 'brand protection', 'corporation service company',
    'enom', 'register.com', 'fastdomain',
}
RETAILED_REGISTRARS = {
    'markmonitor', 'csc corporate', 'safenames', 'network solutions',
    'domain protect', 'brand protection', 'corporation service company',
    'enom', 'register.com', 'fastdomain',
}
RETAIL_REGISTRARS = {
    'namecheap', 'godaddy', 'hostinger', 'public domain registry',
    'goDaddy', 'namesilo', 'dynadot', 'uniregistry', 'KeySystems',
    'Cloudflare', 'Google Domains', ' Porkbun', ' Squarespace',
}
FREE_TLDS = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click', 'link'}

CONFUSION_KEYWORDS = {
    'login', 'account', 'secure', 'verify', 'update', 'confirm',
    'payment', 'billing', 'invoice', 'order', 'cancellation', 'refund',
    'support', 'help', 'password', 'signin', 'auth', 'token',
    'mobile', 'app', 'mobileapp', 'customer', 'client', 'profile',
    'password-reset', 'reset', 'recovery', 'access', 'sign-in',
}

RISKY_SSL_ISSUERS = {
    'let\'s encrypt', 'encrypt', 'ssl', 'startcom', 'certum',
    'comodo positive ssl', 'rapidssl', 'geotrust rapid',
}

# ─── LLM Evidence Extraction ──────────────────────────────────────────────────

def extract_evidence(domain_data: dict) -> dict:
    """
    Call LLM to extract structured evidence.
    The model outputs reasoning text — we parse key fields from it.
    """
    payload = {
        "model": "minimax-portal/MiniMax-M2.7",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": USER_PROMPT_TEMPLATE.format(
                domain=domain_data.get('full_url') or domain_data.get('domain', ''),
                brand=domain_data.get('brand_match', 'Unknown'),
                title=domain_data.get('http_title', 'N/A'),
                http_status=domain_data.get('http_status', 'N/A'),
                final_url=domain_data.get('http_final_url', 'N/A'),
                registrar=domain_data.get('whois_registrar', 'N/A'),
                creation_date=str(domain_data.get('whois_creation_date', 'N/A')),
                country=domain_data.get('whois_registrant_country', 'N/A'),
                resolves=str(domain_data.get('dns_resolves', False)),
                a_records=', '.join(domain_data.get('dns_a_records') or []),
                mx_records=', '.join(domain_data.get('dns_mx_records') or []),
                content=(domain_data.get('http_content') or '')[:3000],
            )}
        ],
        "temperature": 0.1,
        "max_tokens": 800,
    }
    headers = {
        "Authorization": f"Bearer {MINIMAX_API_KEY}",
        "Content-Type": "application/json"
    }
    try:
        resp = requests.post(MINIMAX_URL, json=payload, headers=headers, timeout=30)
        if resp.status_code != 200:
            return {"error": f"API {resp.status_code}"}
        result = resp.json()
        
        # Robust response parsing with multiple fallbacks
        choices = result.get("choices") if result else None
        if not choices or len(choices) == 0:
            # Try alternative response structures
            if result and "reply" in result:
                text = str(result["reply"]).strip()
            elif result and "response" in result:
                text = str(result["response"]).strip()
            else:
                return {"error": f"No choices in response. Keys: {list(result.keys()) if result else 'None'}"}
        else:
            choice = choices[0] if choices else {}
            msg = choice.get("message", {}) if isinstance(choice, dict) else {}
            text = msg.get("content", "").strip() or msg.get("reasoning_content", "").strip()
        
        if not text or text == "None":
            return {"error": "Empty response text"}
        if not text:
            return {"error": "Empty response"}
        return _parse_evidence_from_text(text)
    except json.JSONDecodeError as e:
        return {"error": f"JSON parse error: {str(e)[:100]}"}
    except KeyError as e:
        return {"error": f"Missing key in response: {str(e)}"}
    except Exception as e:
        return {"error": f"LLM error: {str(e)[:100]}"}


def _parse_evidence_from_text(text: str) -> dict:
    """
    Parse structured evidence fields from free-text LLM reasoning.
    Looks for patterns like 'has_login_form: true' or '- has_login_form: true'
    """
    text_lower = text.lower()
    evidence = {}

    # Boolean field patterns
    bool_fields = [
        'has_login_form', 'has_login_button', 'has_payment_form',
        'domain_uses_brand_in_subdomain', 'domain_uses_brand_in_domain',
        'domain_has_confusion_keyword', 'content_copies_brand_assets',
        'links_point_to_real_brand', 'favicon_copied', 'page_is_shallow',
        'ssl_issuer_is_risky', 'registrar_is_retail', 'ip_differs_from_brand',
    ]
    for field in bool_fields:
        # Look for "field_name: true/false/yes/no" patterns
        patterns = [
            rf'{field}:\s*(true|false|yes|no|1|0)',
            rf'- {field}:\s*(true|false|yes|no|1|0)',
            rf'\*\* {field} \*\*:\s*(true|false|yes|no|1|0)',
        ]
        for pat in patterns:
            m = re.search(pat, text_lower)
            if m:
                val = m.group(1).lower()
                evidence[field] = val in ('true', 'yes', '1')
                break
        if field not in evidence:
            evidence[field] = False  # default to False if not mentioned

    # Domain age
    m = re.search(r'domain_age_days:?\s*(\d+)', text_lower)
    if m:
        evidence['domain_age_days'] = int(m.group(1))
    else:
        evidence['domain_age_days'] = None

    # Content suspicious level
    for level in ['high', 'medium', 'low']:
        if re.search(rf'content_suspicious.*?{level}', text_lower):
            evidence['content_suspicious'] = level
            break
    if 'content_suspicious' not in evidence:
        evidence['content_suspicious'] = 'none'

    # Additional notes — capture last paragraph or "notes:" section
    notes_m = re.search(r'additional_notes:?\s*(.+)', text, re.IGNORECASE)
    if notes_m:
        evidence['additional_notes'] = notes_m.group(1).strip()[:200]
    else:
        # Capture last sentence as notes if suspicious keywords found
        susp_kw = ['suspicious', 'concerning', 'phishing', 'fake', ' fraudulent']
        for kw in susp_kw:
            if kw in text_lower:
                sentences = re.split(r'[.\n]', text)
                for sent in reversed(sentences):
                    if kw in sent.lower():
                        evidence['additional_notes'] = sent.strip()[:200]
                        break
                break
        if 'additional_notes' not in evidence:
            evidence['additional_notes'] = ''

    return evidence

# ─── Evidence Scoring ─────────────────────────────────────────────────────────

def score_phishing_indicators(evidence: dict, domain_data: dict) -> dict:
    """
    Score evidence against PHISHING_SPEC rules.
    Uses BOTH LLM-extracted evidence AND automatic rules from domain data.
    """
    indicators = []
    score = 0

    domain = domain_data.get('domain', '').lower()
    brand = (domain_data.get('brand_keyword_matched') or domain_data.get('brand_match') or '').lower()
    content = (domain_data.get('http_content') or '').lower()
    title = (domain_data.get('http_title') or '').lower()
    registrar = (domain_data.get('whois_registrar') or '').lower()

    # ── AUTOMATIC RULES (always applied) ──────────────────────────────────

    # ── BENIGN overrides ──────────────────────────────────────────────────
    # NOTE: Disabled "official brand domain" check - phishing domains can exist as subdomains
    # of legitimate brand domains. Let the phishing indicators determine classification.
    # Example: operadoresperfis-hom.cloud.itau.com.br is NOT itau.com.br, it's a phishing subdomain.
    pass

    # Track if we've seen a real phishing indicator (for gating brand-domain scoring)
    has_real_phishing_signal = (
        evidence.get('has_login_form') or
        evidence.get('has_payment_form') or
        evidence.get('domain_uses_brand_in_subdomain') or
        evidence.get('content_copies_brand_assets') or
        evidence.get('links_point_to_real_brand')
    )

    # ── Rule A: Brand in domain (only score if real phishing signal present, or very strong brand match)
    # Only flag if brand appears as a proper subdomain or hyphenated word
    # (avoid false positives like "inspiringdeclarations.com" containing "clara" inside "declarations")
    brand_found = False
    # Check: brand as subdomain (e.g. clara-login.com) or brand as full domain token
    domain_tokens = re.split(r'[\.\-]', domain)
    for token in domain_tokens:
        if token == brand:  # exact token match (clara in clara-login.com)
            brand_found = True
            break
        # Also check if brand appears at subdomain start: claraanything.com
        if token.startswith(brand) or token.endswith(brand):
            brand_found = True
            break
    # Check brand + confusion keyword combo (brand is subdomain or separate token)
    for kw in CONFUSION_KEYWORDS:
        for token in domain_tokens:
            if brand in token and kw in token:
                brand_found = True
                break
        if brand_found:
            break

    if brand_found:
        indicators.append('brand_in_domain_auto')
        # Brand impersonation is a phishing signal by itself
        # Banks/fintech brands in suspicious subdomains or typosquatting = phishing
        score += 25
        # Confusion keyword in domain adds to score
        for kw in CONFUSION_KEYWORDS:
            if kw in domain:
                indicators.append('brand_plus_confusion_keyword_auto')
                score += 20
                break

    # Rule B: Login keywords in content
    login_content_kw = ['login', 'sign in', 'signin', 'ingresar', 'acceso', 'contraseña', 'password']
    if any(kw in content for kw in login_content_kw):
        indicators.append('login_content_auto')
        score += 15
    if any(kw in title for kw in login_content_kw):
        indicators.append('login_title_auto')
        score += 10

    # Rule C: Form fields in content (email, password, etc.)
    form_kw = ['<form', '<input', 'type="password"', 'type="email"', 'name="password"']
    if any(kw in content for kw in form_kw):
        indicators.append('form_fields_auto')
        score += 20

    # Rule D: Registrar retail check
    is_retail = any(r in registrar for r in RETAIL_REGISTRARS)
    if is_retail:
        indicators.append('retail_registrar_auto')
        score += 15

    # Rule E: TLD free
    tld = domain.split('.')[-1] if '.' in domain else ''
    if tld in FREE_TLDS:
        indicators.append('free_tld_auto')
        score += 10

    # Rule F: Additional notes signal (LLM text analysis)
    notes = (evidence.get('additional_notes') or '').lower()
    if notes:
        phishing_note_keywords = ['suspicious', 'phishing', 'fake', ' impersonat', 'staging', 'homolog', 'unusual', 'concern']
        for kw in phishing_note_keywords:
            if kw in notes:
                indicators.append(f'notes_{kw}_auto')
                score += 15
                break

    # ── LLM EVIDENCE (overrides/adds to automatic rules) ───────────────────

    # 1. Login form → 40 pts
    if evidence.get('has_login_form'):
        indicators.append('login_form')
        score += 40

    # 2. Payment form → 35 pts
    if evidence.get('has_payment_form'):
        indicators.append('payment_form')
        score += 35

    # 3. Login button → 25 pts
    if evidence.get('has_login_button'):
        indicators.append('login_button')
        score += 25

    # 4. Brand in subdomain → 30 pts
    if evidence.get('domain_uses_brand_in_subdomain'):
        indicators.append('brand_in_subdomain')
        score += 30

    # 5. Confusion keyword in domain → 20 pts
    if evidence.get('domain_has_confusion_keyword'):
        indicators.append('confusion_keyword')
        score += 20

    # 6. Content copies brand assets → 20 pts
    if evidence.get('content_copies_brand_assets'):
        indicators.append('copies_brand_assets')
        score += 20

    # 7. Links point to real brand → 10 pts
    if evidence.get('links_point_to_real_brand'):
        indicators.append('links_to_real_brand')
        score += 10

    # 8. Favicon copied → 10 pts
    if evidence.get('favicon_copied'):
        indicators.append('favicon_copied')
        score += 10

    # 9. Page is shallow → 15 pts
    if evidence.get('page_is_shallow'):
        indicators.append('shallow_page')
        score += 15

    # 10. Domain age
    age = evidence.get('domain_age_days')
    if age is not None:
        if age < 30:
            indicators.append('very_new_domain')
            score += 20
        elif age < 180:
            indicators.append('new_domain')
            score += 15
        elif age < 365:
            indicators.append('moderately_new_domain')
            score += 10

    # 11. Registrar retail (LLM) → 15 pts
    if evidence.get('registrar_is_retail'):
        if not is_retail:  # don't double-count if already counted
            indicators.append('retail_registrar')
            score += 15

    # 12. SSL issuer risky → 10 pts
    if evidence.get('ssl_issuer_is_risky'):
        indicators.append('risky_ssl')
        score += 10

    # 13. Content suspicious level
    susp = evidence.get('content_suspicious', 'none')
    if susp == 'high':
        indicators.append('high_suspicion_content')
        score += 20
    elif susp == 'medium':
        indicators.append('medium_suspicion_content')
        score += 10

    # 14. IP differs from brand → 10 pts
    if evidence.get('ip_differs_from_brand'):
        indicators.append('ip_differs')
        score += 10

    # ─── Classification Decision ────────────────────────────────────────────
    notes = evidence.get('additional_notes', '')

    # Direct phishing indicators: these alone can make PHISHING
    has_login = evidence.get('has_login_form')
    has_payment = evidence.get('has_payment_form')
    has_brand_subdomain = evidence.get('domain_uses_brand_in_subdomain')
    has_copied_assets = evidence.get('content_copies_brand_assets')
    has_links_to_brand = evidence.get('links_point_to_real_brand')
    has_form_fields_auto = any('form_fields' in i for i in indicators)

    real_phishing_signal = (
        has_login or has_payment or has_brand_subdomain or
        has_copied_assets or has_links_to_brand or has_form_fields_auto or
        any('brand_in_domain' in i for i in indicators) or
        any('notes_' in i for i in indicators)
    )

    if score >= 70:
        category = 'PHISHING'
        confidence = 'high'
    elif score >= 40:
        if real_phishing_signal:
            category = 'PHISHING'
            confidence = 'medium'
        else:
            category = 'UNCERTAIN'
            confidence = 'low'
    else:
        # Score < 40: let classify_non_phishing decide (DORMANT/BEC_SCAM/BENIGN)
        category = 'UNCERTAIN'
        confidence = 'low'

    reason = f"Score:{min(score,100)} | Indicators: {', '.join(indicators) if indicators else 'none'}"
    if notes:
        reason += f" | Notes: {notes[:100]}"

    return {
        'category': category,
        'score': min(score, 100),
        'confidence': confidence,
        'indicators': indicators,
        'reason': reason,
    }

# ─── DORMANT Monitoring Schedule ───────────────────────────────────────────────

def get_next_dormant_check(whois_creation_date: datetime = None) -> tuple:
    """
    Calculate next check time based on domain's WHOIS creation_date (domain aging).
    Younger domains → more frequent checks. Older domains → less frequent.

    Returns (next_check_at, should_continue_monitoring).
    """
    from config import DORMANT_BY_DOMAIN_AGE, DORMANT_OLD_DOMAIN_INTERVAL
    from datetime import timedelta

    now = datetime.now(timezone.utc)

    if whois_creation_date is None:
        # No creation date — assume moderate age, use 30-90 day tier
        interval = 24
        return now + timedelta(hours=interval), True

    domain_age_days = (now - whois_creation_date).days

    for max_days, interval_hours in DORMANT_BY_DOMAIN_AGE:
        if domain_age_days < max_days:
            next_check = now + timedelta(hours=interval_hours)
            return next_check, True

    # Domain older than 1 year → monthly
    next_check = now + timedelta(hours=DORMANT_OLD_DOMAIN_INTERVAL)
    return next_check, True

    # Beyond all tiers: monthly
    next_check = now + timedelta(hours=DORMANT_FINAL_INTERVAL_HOURS)
    return next_check, True  # Always continue monitoring monthly


# ─── DORMANT Detection ────────────────────────────────────────────────────────

PARKED_MX_PATTERNS = {
    'mail.attorney.com',  # Namecheap parking
    'mail.your-domain.',
    'mx.parking.',
}
PARKED_TLDS = {'xyz', 'top', 'buzz', 'work', 'click', 'link', 'loan', 'date', 'win', 'download', 'review', 'science', 'party', 'cricket', 'faith', 'racing', 'online', 'site', 'info'}


def is_parked_page(domain: str, title: str, content: str, registrar: str) -> bool:
    """
    Detect registrar parked/placeholder page.
    Requires stronger evidence than just 'Coming Soon' — generic placeholder text alone is not enough.
    """
    title_lower = title.lower() if title else ''
    content_lower = content.lower() if content else ''
    registrar_lower = registrar.lower() if registrar else ''

    # Strong parking indicators — require multiple signals
    parking_phrases = [
        'for sale', 'buy this domain', 'send an offer', 'make an offer',
        'domain is for sale', 'send offers', 'domain name for sale',
        'premium domain', ' стоит',
        'parked page —', 'domain parking',
    ]

    parked_title_kw = [
        'parking', 'domain not found', 'this domain is parked',
        'page has been', 'is premium domain',
    ]

    # Check title
    title_match = any(kw in title_lower for kw in parked_title_kw)
    # Check content — require parking-specific phrases
    content_match = any(phrase in content_lower for phrase in parking_phrases)

    # Namecheap parking pattern
    if 'namecheap' in registrar_lower and ('domain names' in content_lower or 'page has been' in content_lower):
        return True

    # Require BOTH title AND content parking signals, or very strong content signal
    if title_match and content_match:
        return True
    if content_match and any(k in title_lower for k in ['parking', 'domain', 'sale', 'offer']):
        return True
    if title_match and ('domain names' in content_lower or 'send offers' in content_lower):
        return True

    return False


def is_brand_in_domain(domain: str, brand: str) -> bool:
    """
    Check if domain contains the brand name as a recognizable token.
    Handles: exact match, typo-squat (different TLD), homoglyphs, brand+keyword subdomain.
    Returns the matched token or None.
    """
    if not brand:
        return False
    domain_lower = domain.lower()
    brand_lower = brand.lower()
    domain_tokens = re.split(r'[\.\-]', domain_lower)

    for token in domain_tokens:
        if not token:
            continue
        # Exact match
        if token == brand_lower:
            return True
        # Brand at start of token (e.g. "clara-login" contains "clara")
        if token.startswith(brand_lower) and len(token) > len(brand_lower):
            return True
        # Homoglyph check: substitute common homoglyphs and compare
        homoglyphs = {'0': 'o', '1': 'l', '5': 's', '3': 'e', '4': 'a', '7': 't', '8': 'b'}
        for fake, real in homoglyphs.items():
            attempt = brand_lower.replace(real, fake)
            if token == attempt:
                return True

    return False


def classify_non_phishing(evidence: dict, domain_data: dict) -> dict:
    """
    For domains that are NOT classified as PHISHING,
    determine: BENIGN | BRAND_INFRINGEMENT | BEC_SCAM | DORMANT | UNCERTAIN
    """
    domain = domain_data.get('domain', '').lower()
    brand = (domain_data.get('brand_keyword_matched') or domain_data.get('brand_match') or '').lower()
    main_domain = (domain_data.get('brand_main_domain') or '').lower()
    mx_records = domain_data.get('dns_mx_records') or []
    http_status = domain_data.get('http_status')
    resolves = domain_data.get('dns_resolves', False)
    content = (domain_data.get('http_content') or '').lower()
    title = (domain_data.get('http_title') or '').lower()
    registrar = (domain_data.get('whois_registrar') or '').lower()
    a_records = domain_data.get('dns_a_records') or []
    dns_cname = domain_data.get('dns_cname')

    brand_in_domain = brand and is_brand_in_domain(domain, brand)

    # ── BENIGN overrides (official brand domains) ────────────────────────────
    # NOTE: Disabled - phishing can use subdomains of legitimate brands
    # Let phishing indicators determine classification

    # ── DORMANT checks ──────────────────────────────────────────────────────

    # Case 1: Empty DNS — registered but no A, CNAME, or MX
    if resolves and not a_records and not dns_cname and not mx_records:
        return {
            'category': 'DORMANT',
            'confidence': 'high',
            'reason': 'Registered domain with empty DNS (no A, CNAME, or MX)'
        }

    # Case 2: No HTTP response
    if not resolves or http_status is None:
        return {'category': 'DORMANT', 'confidence': 'high', 'reason': 'DNS unresolved or HTTP unreachable'}

    # Case 3: Parked page
    if is_parked_page(domain, title, content, registrar):
        return {'category': 'DORMANT', 'confidence': 'high', 'reason': 'Registrar parked/placeholder page'}

    # Case 4: Default registrar parking MX
    if mx_records:
        is_parking_mx = any(
            any(p in mx.lower() for p in PARKED_MX_PATTERNS)
            for mx in mx_records
        )
        if is_parking_mx:
            return {'category': 'DORMANT', 'confidence': 'high', 'reason': 'Default registrar parking MX'}

    # Case 5: Brand typo-squat on suspicious TLD — even if DNS resolves
    # (atttacker registered brand.xyz for future use, DNS may resolve but page is empty/minimal)
    if brand_in_domain:
        domain_tld = domain.split('.')[-1] if '.' in domain else ''
        main_tld = main_domain.split('.')[-1] if '.' in main_domain else ''
        suspicious_tld = domain_tld in PARKED_TLDS
        tld_mismatch = main_tld and domain_tld != main_tld
        if suspicious_tld or tld_mismatch:
            # Additional signal: content is minimal or HTTP title is generic
            is_minimal = (not content or len(content) < 100) and (
                not title or any(kw in title.lower() for kw in ['coming soon', 'welcome', 'index of', 'nginx', 'apache']))
            if is_minimal:
                return {
                    'category': 'DORMANT',
                    'confidence': 'high',
                    'reason': f'Brand typo-squat on suspicious/different TLD (.{domain_tld}), minimal content'
                }

    # ── BEC_SCAM checks (brand in domain + active MX, no login form) ────────
    # Must check before DORMANT because MX makes it active infrastructure
    if brand_in_domain and mx_records:
        # Has brand in domain + active (non-parking) MX → BEC_SCAM
        if not any(p in mx.lower() for mx in mx_records for p in PARKED_MX_PATTERNS):
            return {
                'category': 'BEC_SCAM',
                'confidence': 'medium',
                'reason': f'Brand in domain with active MX — email spoofing infrastructure'
            }

    # ── DORMANT: brand typo-squat on suspicious TLD ─────────────────────────
    if brand_in_domain:
        domain_tld = domain.split('.')[-1] if '.' in domain else ''
        main_tld = main_domain.split('.')[-1] if '.' in main_domain else ''
        is_suspicious_tld = (main_tld and domain_tld != main_tld and domain_tld in PARKED_TLDS)
        if is_suspicious_tld:
            return {
                'category': 'DORMANT',
                'confidence': 'high',
                'reason': f'Brand typo-squat on suspicious TLD (.{domain_tld})'
            }

    # ── BRAND_INFRINGEMENT ─────────────────────────────────────────────────
    # Brand Infringement: e-commerce content selling unauthorized brand products
    # Key: content has e-commerce patterns + brand references (domain may or may not have brand)
    ecom_kw = ['shop', 'store', 'buy', 'sell', 'discount', 'oferta', 'tienda', 'loja',
                'product', 'price', 'cart', 'checkout', 'add to cart', 'comprar', 'precio',
                'buy now', 'order now', 'storefront', 'marketplace']
    auth_kw = ['official', 'authorized', 'authentic', 'genuine', 'authorized dealer',
               'authorized seller', 'official store', 'official partner']

    has_ecom = any(pk in content for pk in ecom_kw)
    has_auth_claim = any(pk in content for pk in auth_kw)

    # If brand_in_domain + e-commerce content → strong brand infringement signal
    if brand_in_domain and has_ecom:
        return {
            'category': 'BRAND_INFRINGEMENT',
            'confidence': 'high' if has_auth_claim else 'medium',
            'reason': f'Brand in domain with e-commerce content (auth claim: {has_auth_claim})'
        }

    # Even without brand in domain: e-commerce + authorization claims → potential infringement
    # This requires LLM evidence for brand detection in content
    if has_ecom and has_auth_claim:
        # Let LLM evidence determine if brand content is present
        if evidence.get('content_copies_brand_assets'):
            return {
                'category': 'BRAND_INFRINGEMENT',
                'confidence': 'medium',
                'reason': 'E-commerce with authorization claims and brand content'
            }

    # ── Default ────────────────────────────────────────────────────────────
    return {'category': 'BENIGN', 'confidence': 'low', 'reason': 'No phishing, dormant, or brand infringement indicators'}

# ─── Main Classification ───────────────────────────────────────────────────────

def classify_intel_result(intel_result_id: int, domain_data: dict) -> dict:
    """Full classification pipeline for one domain."""
    # Step 1: Extract evidence via LLM
    evidence = extract_evidence(domain_data)

    if 'error' in evidence:
        return {
            'category': 'ERROR',
            'score': 0,
            'confidence': 'low',
            'reason': f"LLM error: {evidence['error']}",
            'evidence': evidence
        }

    # Step 2: Score phishing indicators
    phishing_result = score_phishing_indicators(evidence, domain_data)

    if phishing_result['category'] == 'PHISHING':
        return {**phishing_result, 'evidence': evidence}

    # Step 3: Not phishing — check other categories
    other = classify_non_phishing(evidence, domain_data)
    return {
        'category': other['category'],
        'score': phishing_result['score'],
        'confidence': other['confidence'],
        'reason': other['reason'],
        'evidence': evidence
    }

# ─── DB Operations ────────────────────────────────────────────────────────────

def get_pending_intel(batch_size: int):
    """Get intel_results that need classification."""
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT ir.id, ir.domain, ir.full_url, ir.brand_match, ir.brand_keyword_matched,
                   ir.whois_registrar, ir.whois_creation_date, ir.whois_expiry_date,
                   ir.whois_registrant_country,
                   ir.dns_a_records, ir.dns_mx_records, ir.dns_ns_records, ir.dns_resolves,
                   ir.http_status, ir.http_final_url, ir.http_title, ir.http_redirects,
                   ir.http_server, ir.http_content,
                   ir.intel_status, ir.screenshot_path, ir.brand_main_domain
            FROM intel_results ir
            WHERE id NOT IN (
                SELECT intel_result_id FROM classifications WHERE intel_result_id IS NOT NULL
            )
            AND (http_status IS NOT NULL OR dns_resolves = TRUE)
            ORDER BY id
            LIMIT %s
        """, (batch_size,))
        columns = [desc[0] for desc in cur.description]
        return [dict(zip(columns, row)) for row in cur.fetchall()]

def save_classification(intel_result_id: int, result: dict):
    """
    Store classification result in DB. Schedule next dormant re-check based on WHOIS creation_date.
    Returns True if saved, False otherwise.
    """
    conn = get_conn()
    cur = conn.cursor()

    # Get existing classification if re-classifying
    cur.execute(
        "SELECT id, check_count FROM classifications WHERE intel_result_id = %s ORDER BY id DESC LIMIT 1",
        (intel_result_id,)
    )
    existing = cur.fetchone()
    check_count = (existing[1] or 0) + 1 if existing else 1

    # Get WHOIS creation_date for schedule calculation
    cur.execute(
        "SELECT whois_creation_date FROM intel_results WHERE id = %s",
        (intel_result_id,)
    )
    row = cur.fetchone()
    whois_creation = row[0] if row else None
    cur.close()

    # Schedule next check for dormant domains based on domain age (WHOIS creation)
    next_check = None
    if result.get('category') == 'DORMANT':
        next_check, _ = get_next_dormant_check(whois_creation)

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO classifications (
                intel_result_id, category, probability_score, confidence,
                evidence, reason, next_check_at, check_count
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            intel_result_id,
            result['category'],
            result.get('score', 0),
            result.get('confidence', 'low'),
            json.dumps(result.get('evidence', {})),
            result.get('reason', ''),
            next_check,
            check_count,
        ))
        conn.commit()
        cur.close()
    return True


def get_due_dormant_checks(batch_size: int):
    """Get DORMANT classifications due for re-check."""
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT ir.id, ir.domain, ir.brand_match, ir.brand_keyword_matched,
                   ir.whois_registrar, ir.whois_creation_date, ir.whois_expiry_date,
                   ir.whois_registrant_country,
                   ir.dns_a_records, ir.dns_mx_records, ir.dns_ns_records, ir.dns_resolves,
                   ir.http_status, ir.http_final_url, ir.http_title, ir.http_redirects,
                   ir.http_server, ir.http_content,
                   ir.intel_status, ir.screenshot_path, ir.brand_main_domain,
                   cls.id as cls_id, cls.check_count
            FROM classifications cls
            JOIN intel_results ir ON ir.id = cls.intel_result_id
            WHERE cls.category = 'DORMANT'
              AND cls.next_check_at <= NOW()
            ORDER BY cls.next_check_at
            LIMIT %s
        """, (batch_size,))
        columns = [desc[0] for desc in cur.description]
        return [dict(zip(columns, row)) for row in cur.fetchall()]


def recheck_dormant_domain(cls_id: int, intel_id: int, domain_data: dict):
    """
    Re-check a DORMANT domain. If DNS changed significantly, re-classify.
    If still dormant, update next_check_at using decaying schedule.
    """
    # Get stored previous evidence for comparison
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT evidence FROM classifications WHERE id = %s
        """, (cls_id,))
        row = cur.fetchone()
        prev_evidence = json.loads(row[0]) if row else {}
        cur.close()

    # Re-collect HTTP/DNS (quick check, no WHOIS)
    from collectors.intel_collector import collect_dns, collect_http

    current_dns = collect_dns(domain_data['domain'])
    current_http = collect_http(domain_data['domain'])

    # Compare with previous state
    prev_a = set(prev_evidence.get('prev_a_records', []))
    prev_mx = set(prev_evidence.get('prev_mx_records', []))
    curr_a = set(current_dns.get('a', []))
    curr_mx = set(current_dns.get('mx', []))

    dns_changed = (curr_a != prev_a) or (curr_mx != prev_mx)

    if not dns_changed:
        # Still dormant — schedule next check based on WHOIS creation_date
        next_check, _ = get_next_dormant_check(domain_data.get('whois_creation_date'))
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                UPDATE classifications
                SET next_check_at = %s, check_count = check_count + 1
                WHERE id = %s
            """, (next_check, cls_id))
            conn.commit()
            cur.close()

        # Also update intel_results with current DNS
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                UPDATE intel_results SET
                    dns_a_records = %s, dns_mx_records = %s, dns_ns_records = %s,
                    dns_resolves = %s,
                    http_status = %s, http_final_url = %s, http_title = %s,
                    http_redirects = %s, http_server = %s, http_content = %s,
                    updated_at = NOW()
                WHERE id = %s
            """, (
                current_dns.get('a'), current_dns.get('mx'), current_dns.get('ns'),
                current_dns.get('resolves'),
                current_http.get('status'), current_http.get('final_url'),
                current_http.get('title'), current_http.get('redirects'),
                current_http.get('server'), current_http.get('content'),
                intel_id,
            ))
            conn.commit()
            cur.close()

        interval_h = (next_check - datetime.now(timezone.utc)).total_seconds() / 3600
        print(f"  💤 {domain_data['domain']}: still dormant, next check in {interval_h:.1f}h")
        return

    # DNS changed — update intel_results with new data and re-classify
    print(f"  ⚠️  {domain_data['domain']}: DNS changed! Re-classifying...")

    # Update intel_results with new DNS/HTTP
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            UPDATE intel_results SET
                dns_a_records = %s, dns_mx_records = %s, dns_ns_records = %s,
                dns_resolves = %s,
                http_status = %s, http_final_url = %s, http_title = %s,
                http_redirects = %s, http_server = %s, http_content = %s,
                updated_at = NOW()
            WHERE id = %s
        """, (
            current_dns.get('a'), current_dns.get('mx'), current_dns.get('ns'),
            current_dns.get('resolves'),
            current_http.get('status'), current_http.get('final_url'),
            current_http.get('title'), current_http.get('redirects'),
            current_http.get('server'), current_http.get('content'),
            intel_id,
        ))
        conn.commit()
        cur.close()

    # Re-fetch with updated data
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT ir.id, ir.domain, ir.brand_match, ir.brand_keyword_matched,
                   ir.whois_registrar, ir.whois_creation_date, ir.whois_expiry_date,
                   ir.whois_registrant_country,
                   ir.dns_a_records, ir.dns_mx_records, ir.dns_ns_records, ir.dns_resolves,
                   ir.http_status, ir.http_final_url, ir.http_title, ir.http_redirects,
                   ir.http_server, ir.http_content,
                   ir.intel_status, ir.screenshot_path, ir.brand_main_domain
            FROM intel_results ir WHERE ir.id = %s
        """, (intel_id,))
        columns = [desc[0] for desc in cur.description]
        updated_data = dict(zip(columns, cur.fetchone()))
        cur.close()

    # Pass WHOIS creation_date so schedule stays consistent (we don't reset based on time in our system)
    result = classify_intel_result(intel_id, updated_data)
    save_classification(intel_id, result)
    print(f"  → {result['category']} (score:{result.get('score', 0)})")

# ─── Batch Processing ─────────────────────────────────────────────────────────

def save_classification(intel_result_id: int, result: dict):
    """Store classification result in DB."""
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO classifications (
                intel_result_id, category, probability_score, confidence,
                evidence, reason
            ) VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            intel_result_id,
            result['category'],
            result.get('score', 0),
            result.get('confidence', 'low'),
            json.dumps(result.get('evidence', {})),
            result.get('reason', ''),
        ))
        conn.commit()
        cur.close()
    return True


def process_batch():
    pending = get_pending_intel(CLASSIFIER_BATCH_SIZE)
    if not pending:
        return 0

    print(f"🔍 Processing {len(pending)} domains...")
    for intel in pending:
        print(f"  {intel['domain']}...", end=" ", flush=True)
        try:
            result = classify_intel_result(intel['id'], intel)
            save_result = save_classification(intel['id'], result)
            print(f"→ {result['category']} (score:{result.get('score', 0)}) saved={save_result}")
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"❌ SAVE ERROR: {e}")
        except Exception as e:
            print(f"❌ {e}")
    return len(pending)

# ─── Main ─────────────────────────────────────────────────────────────────────

def check_dormant_queue():
    """Check and re-classify dormant domains due for re-check."""
    from config import CLASSIFIER_BATCH_SIZE
    due = get_due_dormant_checks(CLASSIFIER_BATCH_SIZE)
    if not due:
        return 0
    print(f"🔄 Re-checking {len(due)} dormant domains...")
    for item in due:
        print(f"  {item['domain']}...", end=" ", flush=True)
        try:
            recheck_dormant_domain(item['cls_id'], item['id'], item)
        except Exception as e:
            print(f"❌ {e}")
    return len(due)


def main():
    parser = argparse.ArgumentParser(description="Pleriguard V2 Classifier")
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--dormant-only", action="store_true", help="Only run dormant re-check")
    args = parser.parse_args()

    ensure_schema()
    print("🎯 Pleriguard V2 Classifier starting...")

    if args.dormant_only:
        check_dormant_queue()
        return

    if args.loop:
        dormant_check_counter = 0
        while _running:
            count = process_batch()
            if count == 0:
                # Every ~5 minutes check dormant queue
                dormant_check_counter += 1
                if dormant_check_counter >= 10:  # ~5 min at 30s intervals
                    check_dormant_queue()
                    dormant_check_counter = 0
                print(f"💤 No pending domains, sleeping {CLASSIFIER_INTERVAL}s...")
                for i in range(CLASSIFIER_INTERVAL):
                    if not _running:
                        break
                    time.sleep(1)
    else:
        process_batch()

if __name__ == "__main__":
    main()
