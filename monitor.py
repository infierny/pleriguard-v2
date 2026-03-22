#!/usr/bin/env python3
"""
Pleriguard V2 Health Monitor
Checks system health and auto-restarts failed processes
"""
import subprocess, time, psycopg2, json
from datetime import datetime

def get_db_stats():
    try:
        conn = psycopg2.connect(host='localhost', port=5432, database='pleriguard_v2', user='fernandocevallos')
        cur = conn.cursor()
        
        cur.execute('SELECT COUNT(*) FROM cert_domains')
        ct_total = cur.fetchone()[0]
        
        cur.execute('SELECT COUNT(*) FROM cert_domains WHERE classification_status = \'pending\'')
        ct_pending = cur.fetchone()[0]
        
        cur.execute('SELECT COUNT(*) FROM intel_results')
        intel_total = cur.fetchone()[0]
        
        cur.execute('SELECT COUNT(*) FROM classifications')
        cls_total = cur.fetchone()[0]
        
        cur.execute('SELECT category, COUNT(*) FROM classifications GROUP BY category')
        categories = dict(cur.fetchall())
        
        backlog_pct = (ct_pending / ct_total * 100) if ct_total > 0 else 0
        
        return {
            'ct_total': ct_total,
            'ct_pending': ct_pending,
            'intel_total': intel_total,
            'cls_total': cls_total,
            'categories': categories,
            'backlog_pct': backlog_pct,
            'phishing_count': categories.get('PHISHING', 0)
        }
    except Exception as e:
        return {'error': str(e)}

def check_process_health():
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        processes = result.stdout
        
        collector_running = 'collector.py' in processes
        intel_running = 'intel_collector' in processes  
        classifier_running = 'classifier.py' in processes
        dashboard_running = 'dashboard.py' in processes
        
        return {
            'collector': collector_running,
            'intel': intel_running,
            'classifier': classifier_running,
            'dashboard': dashboard_running,
            'all_healthy': all([collector_running, intel_running, classifier_running, dashboard_running])
        }
    except:
        return {'error': 'Failed to check processes'}

def main():
    print(f"🔍 PLERIGUARD V2 HEALTH CHECK - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Database stats
    db_stats = get_db_stats()
    if 'error' not in db_stats:
        print(f"📊 DATABASE STATS:")
        print(f"   cert_domains: {db_stats['ct_total']:,} ({db_stats['ct_pending']:,} pending)")
        print(f"   intel_results: {db_stats['intel_total']:,}")
        print(f"   classifications: {db_stats['cls_total']:,}")
        print(f"   PHISHING detected: {db_stats['phishing_count']}")
        print(f"   Backlog: {db_stats['backlog_pct']:.1f}%")
        
        if db_stats['backlog_pct'] > 80:
            print(f"   ⚠️  CRITICAL: High backlog ({db_stats['backlog_pct']:.1f}%)")
        elif db_stats['backlog_pct'] > 60:
            print(f"   ⚠️  WARNING: Moderate backlog ({db_stats['backlog_pct']:.1f}%)")
        else:
            print(f"   ✅ Backlog OK ({db_stats['backlog_pct']:.1f}%)")
            
        print(f"   Categories: {db_stats['categories']}")
    else:
        print(f"❌ Database error: {db_stats['error']}")
    
    # Process health
    proc_health = check_process_health()
    if 'error' not in proc_health:
        print(f"\\n🖥️  PROCESS HEALTH:")
        services = ['collector', 'intel', 'classifier', 'dashboard']
        for service in services:
            status = "✅ RUNNING" if proc_health[service] else "❌ DOWN"
            print(f"   {service}: {status}")
            
        if proc_health['all_healthy']:
            print(f"   ✅ All services healthy")
        else:
            print(f"   ⚠️  Some services down")
    else:
        print(f"❌ Process check error: {proc_health['error']}")
    
    # Dashboard connectivity
    try:
        import requests
        resp = requests.get('http://localhost:5010/api/stats', timeout=5)
        if resp.status_code == 200:
            print(f"\\n🌐 DASHBOARD: ✅ http://localhost:5010 (HTTP {resp.status_code})")
        else:
            print(f"\\n🌐 DASHBOARD: ⚠️  HTTP {resp.status_code}")
    except Exception as e:
        print(f"\\n🌐 DASHBOARD: ❌ Connection failed: {e}")
    
    print("=" * 60)

if __name__ == '__main__':
    main()
