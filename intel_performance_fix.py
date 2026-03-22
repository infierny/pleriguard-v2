"""
Performance fixes for intel_collector.py
- Reduce delays
- Increase batch processing
- Better error handling
"""
import re

# Read original file
with open('collectors/intel_collector.py', 'r') as f:
    content = f.read()

# Fix 1: Reduce sleep delays
content = re.sub(r'time\.sleep\(30\)', 'time.sleep(5)', content)  # 30s -> 5s
content = re.sub(r'time\.sleep\(10\)', 'time.sleep(2)', content)  # 10s -> 2s

# Fix 2: Increase batch size
content = re.sub(r'LIMIT 10', 'LIMIT 50', content)  # Process more domains per batch

# Fix 3: Add timeout configs
if 'requests.get(' in content:
    content = re.sub(
        r'requests\.get\(([^,]+)\)',
        r'requests.get(\1, timeout=10)',
        content
    )
    content = re.sub(
        r'timeout=\d+, timeout=10',
        'timeout=10',
        content
    )

# Fix 4: Better error handling
error_fix = """
        except Exception as e:
            error_msg = str(e)[:200]  # Truncate long errors
            logging.error(f"Intel collection error for {full_url}: {error_msg}")
            cur.execute('''
                UPDATE intel_results 
                SET intel_status = 'failed', error_message = %s, updated_at = NOW()
                WHERE id = %s
            ''', (error_msg, result_id))
            continue  # Skip to next domain
"""

if 'except Exception as e:' in content and 'error_msg = str(e)' not in content:
    content = re.sub(
        r'except Exception as e:\s*\n\s*logging\.error\([^)]+\)\s*\n\s*continue',
        error_fix.strip(),
        content,
        flags=re.MULTILINE
    )

# Write optimized file
with open('collectors/intel_collector_optimized.py', 'w') as f:
    f.write(content)

print("✅ Intel collector optimized")
print("Changes made:")
print("  - Reduced sleep delays: 30s->5s, 10s->2s") 
print("  - Increased batch size: 10->50 domains")
print("  - Added request timeouts: 10s")
print("  - Improved error handling")
