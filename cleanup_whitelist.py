#!/usr/bin/env python3
"""
Automated whitelist cleanup script
Removes legitimate domains from collection to focus on threats
"""
import psycopg2
import re
from datetime import datetime

def cleanup_whitelist_domains():
    """Remove whitelisted domains from cert_domains and related tables"""
    conn = psycopg2.connect(host='localhost', port=5432, database='pleriguard_v2', user='fernandocevallos')
    conn.autocommit = True
    cur = conn.cursor()
    
    # Count before
    cur.execute('SELECT COUNT(*) FROM cert_domains')
    before = cur.fetchone()[0]
    
    print(f"🧹 Starting cleanup of {before:,} domains...")
    
    # Clean AWS domains
    aws_patterns = ['amazonaws.com', 'amazongamelift.com', 'amazonaws.eu', 'amazonaws.com.cn']
    for pattern in aws_patterns:
        cur.execute("DELETE FROM cert_domains WHERE domain LIKE %s OR full_url LIKE %s", (f'%{pattern}', f'%{pattern}'))
        
    # Clean Azure domains  
    azure_patterns = ['azure.com', 'azurecontainerapps.io', 'cloudapp.azure.com']
    for pattern in azure_patterns:
        cur.execute("DELETE FROM cert_domains WHERE domain LIKE %s OR full_url LIKE %s", (f'%{pattern}', f'%{pattern}'))
    
    # Clean Google Cloud
    gcp_patterns = ['googleapis.com', 'google.com', 'googleusercontent.com']
    for pattern in gcp_patterns:
        cur.execute("DELETE FROM cert_domains WHERE domain LIKE %s OR full_url LIKE %s", (f'%{pattern}', f'%{pattern}'))
    
    # Clean legitimate brand domains (exact matches only)
    legitimate_domains = [
        'itau.com.br', 'nubank.com.br', 'amazon.com', 'uber.com',
        'mercadolibre.com', 'americanas.com.br', 'ifood.com.br',
        'clara.com', 'bancolombia.com', 'bbva.mx', 'amazon.dev',
        'amazon-ah.com'
    ]
    for domain in legitimate_domains:
        cur.execute("DELETE FROM cert_domains WHERE domain = %s", (domain,))
    
    # Clean development/staging domains
    dev_patterns = ['localhost', '127.0.0.1', '.local', '.dev', '.test', '.staging']
    for pattern in dev_patterns:
        cur.execute("DELETE FROM cert_domains WHERE full_url LIKE %s", (f'%{pattern}%',))
    
    # Clean CDN/hosting providers
    hosting_patterns = ['cloudflare.com', 'fastly.com', 'akamai.net', 'netlify.com', 'vercel.app']
    for pattern in hosting_patterns:
        cur.execute("DELETE FROM cert_domains WHERE domain LIKE %s", (f'%{pattern}',))
    
    # Count after
    cur.execute('SELECT COUNT(*) FROM cert_domains')
    after = cur.fetchone()[0]
    
    removed = before - after
    removal_pct = (removed / before * 100) if before > 0 else 0
    
    print(f"✅ Cleanup completed:")
    print(f"   Removed: {removed:,} domains ({removal_pct:.1f}%)")
    print(f"   Remaining: {after:,} domains")
    
    # Show sample of remaining domains
    cur.execute('SELECT DISTINCT domain FROM cert_domains ORDER BY domain LIMIT 15')
    samples = [row[0] for row in cur.fetchall()]
    print(f"\\n🎯 REMAINING DOMAINS (potential threats):")
    for domain in samples:
        print(f"   {domain}")
    
    return removed, after

if __name__ == '__main__':
    cleanup_whitelist_domains()
