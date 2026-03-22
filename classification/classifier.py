#!/usr/bin/env python3
"""
classifier_emergency.py - Pure Rule-Based Classification
NO LLM calls - just uses available data to classify threats
"""
import argparse, json, os, sys, time
import re
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from db import get_conn, get_cursor
from config import CLASSIFIER_BATCH_SIZE, CLASSIFIER_INTERVAL

def extract_evidence_ruleBased(domain_data):
    """Pure rule-based evidence extraction from domain data"""
    evidence = {}
    
    domain = (domain_data.get('domain') or '').lower()
    full_url = (domain_data.get('full_url') or '').lower()
    content = (domain_data.get('http_content') or '').lower()[:2000]
    title = (domain_data.get('http_title') or '').lower()
    
    # Safe string handling for all fields
    brand_match = (domain_data.get('brand_match') or '').lower()
    registrar = (domain_data.get('whois_registrar') or '').lower()
    
    # Check for brand in domain/subdomain (already defined above)
    evidence['domain_uses_brand_in_domain'] = brand_match in domain if brand_match else False
    evidence['domain_uses_brand_in_subdomain'] = brand_match in full_url if brand_match else False
    
    # Check for confusion keywords
    confusion_words = ['login', 'account', 'secure', 'verify', 'update', 'payment', 'billing']
    evidence['domain_has_confusion_keyword'] = any(word in full_url for word in confusion_words)
    
    # Check for login/payment indicators
    evidence['has_login_form'] = any(term in content for term in ['password', 'login', 'sign-in', 'username'])
    evidence['has_login_button'] = 'login' in content or 'sign in' in content
    evidence['has_payment_form'] = any(term in content for term in ['payment', 'credit card', 'billing', 'checkout'])
    
    # Check registrar (already defined above)
    retail_registrars = ['godaddy', 'namecheap', 'hostinger']
    evidence['registrar_is_retail'] = any(reg in registrar for reg in retail_registrars)
    
    # Page analysis
    evidence['page_is_shallow'] = len(content) < 500
    
    # Domain age
    creation_date = domain_data.get('whois_creation_date')
    if creation_date:
        try:
            from datetime import datetime
            if isinstance(creation_date, str):
                creation = datetime.strptime(creation_date[:10], '%Y-%m-%d')
            else:
                creation = creation_date
            age_days = (datetime.now() - creation).days
            evidence['domain_age_days'] = age_days
        except:
            evidence['domain_age_days'] = None
    else:
        evidence['domain_age_days'] = None
    
    # Set defaults for other fields
    evidence.update({
        'content_copies_brand_assets': False,
        'links_point_to_real_brand': False,
        'favicon_copied': False,
        'ssl_issuer_is_risky': False,
        'ip_differs_from_brand': False,
        'content_suspicious': 'none',
        'additional_notes': ''
    })
    
    return evidence

def calculate_phishing_score(evidence, domain_data):
    """Calculate phishing score based on evidence"""
    score = 0
    indicators = []
    
    # Brand impersonation (high weight)
    if evidence.get('domain_uses_brand_in_domain'):
        score += 30
        indicators.append('brand_in_domain_auto')
    
    if evidence.get('domain_uses_brand_in_subdomain'):
        score += 25  
        indicators.append('brand_in_subdomain_auto')
    
    # Confusion keywords
    if evidence.get('domain_has_confusion_keyword'):
        score += 15
        indicators.append('confusion_keywords_auto')
    
    # Login/payment forms (credential harvesting)
    if evidence.get('has_login_form'):
        score += 20
        indicators.append('login_form_auto')
    
    if evidence.get('has_payment_form'):
        score += 25
        indicators.append('payment_form_auto')
    
    # Retail registrar (easier to abuse)
    if evidence.get('registrar_is_retail'):
        score += 10
        indicators.append('retail_registrar_auto')
    
    # Shallow page (likely landing page)
    if evidence.get('page_is_shallow'):
        score += 10
        indicators.append('shallow_page_auto')
    
    # New domain
    domain_age = evidence.get('domain_age_days')
    if domain_age is not None and domain_age < 30:
        score += 15
        indicators.append('new_domain_auto')
    
    # Determine category
    if score >= 50:
        category = 'PHISHING'
        confidence = 'high' if score >= 70 else 'medium'
    elif score >= 30:
        category = 'BEC_SCAM'
        confidence = 'medium'
    elif score >= 15:
        category = 'DORMANT'
        confidence = 'low'
    else:
        category = 'BENIGN'
        confidence = 'low'
    
    reason = f"Score:{score} | Indicators: {', '.join(indicators) if indicators else 'none'}"
    
    return {
        'category': category,
        'probability_score': float(score),
        'confidence': confidence,
        'evidence': evidence,
        'reason': reason
    }

def process_domains():
    """Main processing loop"""
    processed_count = 0
    
    with get_cursor(commit=True) as cur:
        # Get pending intel results
        cur.execute('''
            SELECT ir.id, ir.domain, ir.full_url, ir.brand_match, ir.brand_keyword_matched,
                   ir.whois_registrar, ir.whois_creation_date, ir.whois_registrant_country,
                   ir.http_status, ir.http_title, ir.http_content,
                   ir.dns_a_records, ir.dns_mx_records
            FROM intel_results ir
            LEFT JOIN classifications c ON ir.id = c.intel_result_id
            WHERE c.id IS NULL
            AND ir.intel_status = 'done'
            ORDER BY ir.created_at ASC
            LIMIT %s
        ''', (CLASSIFIER_BATCH_SIZE,))
        
        domains = cur.fetchall()
        
        for row in domains:
            domain_data = {
                'id': row[0],
                'domain': row[1],
                'full_url': row[2],
                'brand_match': row[3],
                'brand_keyword_matched': row[4],
                'whois_registrar': row[5],
                'whois_creation_date': row[6],
                'whois_registrant_country': row[7],
                'http_status': row[8],
                'http_title': row[9],
                'http_content': row[10],
                'dns_a_records': row[11],
                'dns_mx_records': row[12],
            }
            
            try:
                # Rule-based classification
                evidence = extract_evidence_ruleBased(domain_data)
                result = calculate_phishing_score(evidence, domain_data)
                
                # Save classification
                cur.execute('''
                    INSERT INTO classifications (
                        intel_result_id, category, subcategory, probability_score,
                        confidence, evidence, reason, source, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                ''', (
                    domain_data['id'],
                    result['category'],
                    None,
                    result['probability_score'],
                    result['confidence'],
                    json.dumps(result['evidence']),
                    result['reason'],
                    'rule_based_v2'
                ))
                
                processed_count += 1
                print(f"  {domain_data['full_url'][:40]:40} → {result['category']} (score:{result['probability_score']:.0f}) saved=True")
                
            except Exception as e:
                print(f"  {domain_data['full_url'][:40]:40} → ERROR: {str(e)[:50]}")
                continue
    
    return processed_count

def main():
    print("🎯 Pleriguard V2 Emergency Rule-Based Classifier starting...")
    
    while True:
        try:
            processed = process_domains()
            if processed > 0:
                print(f"✅ Processed {processed} domains")
            else:
                print("💤 No pending domains, sleeping 30s...")
                time.sleep(30)
        except KeyboardInterrupt:
            print("\n🛑 Stopping classifier...")
            break
        except Exception as e:
            print(f"❌ Error in main loop: {e}")
            time.sleep(10)

if __name__ == '__main__':
    main()
