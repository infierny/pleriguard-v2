"""
Add whitelist functionality to collector
"""
import re

with open('collectors/collector.py', 'r') as f:
    content = f.read()

# Add whitelist cache and check function
whitelist_functions = '''
# Whitelist cache for performance
_whitelist_cache = set()
_whitelist_loaded = False

def load_whitelist():
    """Load whitelist domains into memory cache"""
    global _whitelist_cache, _whitelist_loaded
    if _whitelist_loaded:
        return
    
    try:
        from db import get_conn
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute('SELECT domain FROM domain_whitelist')
            _whitelist_cache = {row[0].lower() for row in cur.fetchall()}
        _whitelist_loaded = True
        print(f"✅ Loaded {len(_whitelist_cache)} whitelist domains")
    except Exception as e:
        print(f"⚠️  Failed to load whitelist: {e}")
        _whitelist_cache = set()

def is_whitelisted(domain, full_url):
    """Check if domain is in whitelist"""
    load_whitelist()
    
    # Extract root domain
    domain_lower = domain.lower()
    full_url_lower = full_url.lower()
    
    # Direct whitelist check
    if domain_lower in _whitelist_cache:
        return True
    
    # Check if any whitelist domain is a suffix of the current domain
    for whitelist_domain in _whitelist_cache:
        if domain_lower.endswith('.' + whitelist_domain) or domain_lower == whitelist_domain:
            return True
    
    return False
'''

# Find the imports section and add whitelist functions
import_end = content.find('from db import')
if import_end != -1:
    next_line = content.find('\n', import_end)
    content = content[:next_line] + '\n' + whitelist_functions + content[next_line:]

# Find the domain processing logic and add whitelist check
if 'if is_aws_noise(' in content:
    # Add whitelist check before AWS noise check
    old_logic = '''            # Skip AWS noise domains
            if is_aws_noise(extracted_domain, full_url):
                continue'''
    
    new_logic = '''            # Skip whitelisted domains (legitimate brands/services)
            if is_whitelisted(extracted_domain, full_url):
                continue
                
            # Skip AWS noise domains
            if is_aws_noise(extracted_domain, full_url):
                continue'''
    
    content = content.replace(old_logic, new_logic)
    
with open('collectors/collector_with_whitelist.py', 'w') as f:
    f.write(content)

print("✅ Added whitelist functionality to collector")
