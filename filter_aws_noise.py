"""
Filter to remove AWS test/canary domains from collection
These domains are internal AWS infrastructure, not phishing targets
"""
import psycopg2

# Keywords that indicate AWS internal/test domains (not phishing targets)
AWS_NOISE_KEYWORDS = [
    'canary',
    'vpce-',
    'mrap.accesspoint',
    's3-global.amazonaws',
    'internal.aws',
    'test.amazonaws',
    '.internal.',
    'elasticloadbalancing.amazonaws',
    'amazongamelift.com'
]

def filter_aws_noise():
    conn = psycopg2.connect(host='localhost', port=5432, database='pleriguard_v2', user='fernandocevallos')
    conn.autocommit = True
    cur = conn.cursor()
    
    # Count domains before filtering
    cur.execute("SELECT COUNT(*) FROM cert_domains WHERE full_url LIKE '%amazonaws.com%' OR full_url LIKE '%amazongamelift.com%'")
    aws_before = cur.fetchone()[0]
    
    # Delete AWS noise domains
    delete_conditions = []
    for keyword in AWS_NOISE_KEYWORDS:
        delete_conditions.append(f"full_url LIKE '%{keyword}%'")
    
    delete_query = f"DELETE FROM cert_domains WHERE ({' OR '.join(delete_conditions)})"
    
    print(f"🧹 Removing AWS noise domains...")
    print(f"   AWS domains before: {aws_before:,}")
    
    cur.execute(delete_query)
    deleted = cur.rowcount
    
    cur.execute("SELECT COUNT(*) FROM cert_domains")
    remaining = cur.fetchone()[0]
    
    print(f"   Deleted: {deleted:,}")
    print(f"   Remaining total: {remaining:,}")
    
    # Also clean up related intel_results if any exist
    cur.execute("DELETE FROM intel_results WHERE full_url LIKE '%canary%' OR full_url LIKE '%vpce-%' OR full_url LIKE '%internal.aws%'")
    intel_cleaned = cur.rowcount
    print(f"   Intel cleaned: {intel_cleaned}")
    
    return deleted, remaining

if __name__ == '__main__':
    filter_aws_noise()
