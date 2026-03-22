#!/usr/bin/env python3
"""
brands_manager.py - Pleriguard V2 Brands Management Interface
Manage brands database with full CRUD operations
"""
import os, sys
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flask import Flask, render_template_string, request, jsonify, redirect, url_for
from db import get_conn

app = Flask(__name__)

def dict_fetchall(cur):
    columns = [desc[0] for desc in cur.description]
    return [dict(zip(columns, row)) for row in cur.fetchall()]

def get_brands():
    """Get all brands from database"""
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, brand, name, country, sector, main_domain, keyword, 
                   opportunity_score, active, created_at, authorized_domains
            FROM brands 
            ORDER BY brand
        """)
        brands = dict_fetchall(cur)
        cur.close()
    return brands

def get_brand_stats():
    """Get brand statistics"""
    with get_conn() as conn:
        cur = conn.cursor()
        
        cur.execute('SELECT COUNT(*) FROM brands')
        total = cur.fetchone()[0]
        
        cur.execute('SELECT COUNT(*) FROM brands WHERE active = true')
        active = cur.fetchone()[0]
        
        cur.execute('SELECT COUNT(DISTINCT country) FROM brands WHERE country IS NOT NULL')
        countries = cur.fetchone()[0]
        
        cur.execute('SELECT COUNT(DISTINCT sector) FROM brands WHERE sector IS NOT NULL')
        sectors = cur.fetchone()[0]
        
        cur.close()
    return {
        'total': total,
        'active': active,
        'countries': countries,
        'sectors': sectors
    }

# HTML Template
TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Pleriguard V2 — Brands Manager</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0d1117; color: #e6edf3; font-size: 14px; }
.header { padding: 20px 24px; border-bottom: 1px solid #21262d; display: flex; justify-content: space-between; align-items: center; }
h1 { font-size: 18px; color: #58a6ff; }
.btn { background: #238636; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; display: inline-block; }
.btn:hover { background: #2ea043; }
.btn-secondary { background: #21262d; }
.btn-secondary:hover { background: #30363d; }

.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; padding: 24px; }
.stat-card { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 16px; text-align: center; }
.stat-value { font-size: 24px; font-weight: 600; color: #58a6ff; }
.stat-label { font-size: 12px; color: #8b949e; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.05em; }

.search-bar { padding: 0 24px 16px; }
.search-input { width: 100%; padding: 12px; background: #161b22; border: 1px solid #21262d; border-radius: 6px; color: #e6edf3; font-size: 14px; }

table { width: 100%; border-collapse: collapse; margin: 0 24px; }
th { text-align: left; font-size: 11px; text-transform: uppercase; color: #8b949e; padding: 12px; border-bottom: 1px solid #21262d; }
td { padding: 12px; border-bottom: 1px solid #161b22; font-size: 13px; }
tr:hover td { background: #161b22; }

.brand-name { font-weight: 600; color: #58a6ff; }
.country-flag { display: inline-block; margin-right: 6px; }
.sector { color: #8b949e; font-size: 12px; }
.status-active { color: #3fb950; }
.status-inactive { color: #f85149; }
.keyword { background: #21262d; padding: 2px 6px; border-radius: 3px; font-size: 11px; color: #58a6ff; }

/* Modal */
.modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); }
.modal-content { background-color: #161b22; margin: 5% auto; padding: 0; border: 1px solid #21262d; border-radius: 8px; width: 90%; max-width: 600px; }
.modal-header { padding: 20px; border-bottom: 1px solid #21262d; }
.modal-title { font-size: 16px; font-weight: 600; color: #e6edf3; }
.close { color: #8b949e; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
.close:hover { color: #e6edf3; }

.modal-body { padding: 20px; }
.form-group { margin-bottom: 16px; }
.form-label { display: block; margin-bottom: 6px; font-size: 13px; color: #8b949e; }
.form-input { width: 100%; padding: 10px; background: #0d1117; border: 1px solid #21262d; border-radius: 4px; color: #e6edf3; font-size: 14px; }
.form-input:focus { border-color: #58a6ff; outline: none; }
.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.form-textarea { min-height: 80px; resize: vertical; }
</style>
</head>
<body>

<div class="header">
  <h1>🏷️ Pleriguard V2 — Brands Manager</h1>
  <button class="btn" onclick="openModal()">+ Add New Brand</button>
</div>

<div class="stats">
  <div class="stat-card">
    <div class="stat-value">{{ stats.total }}</div>
    <div class="stat-label">Total Brands</div>
  </div>
  <div class="stat-card">
    <div class="stat-value">{{ stats.active }}</div>
    <div class="stat-label">Active Brands</div>
  </div>
  <div class="stat-card">
    <div class="stat-value">{{ stats.countries }}</div>
    <div class="stat-label">Countries</div>
  </div>
  <div class="stat-card">
    <div class="stat-value">{{ stats.sectors }}</div>
    <div class="stat-label">Sectors</div>
  </div>
</div>

<div class="search-bar">
  <input type="text" class="search-input" placeholder="Search brands, countries, sectors..." id="searchInput" onkeyup="filterTable()">
</div>

<table id="brandsTable">
<thead>
<tr>
  <th>Brand</th>
  <th>Name</th>
  <th>Country</th>
  <th>Sector</th>
  <th>Domain</th>
  <th>Keywords</th>
  <th>Score</th>
  <th>Status</th>
  <th>Actions</th>
</tr>
</thead>
<tbody>
{% for brand in brands %}
<tr>
  <td><span class="brand-name">{{ brand.brand }}</span></td>
  <td>{{ brand.name or '—' }}</td>
  <td>
    {% if brand.country %}
      <span class="country-flag">{{ {
        'US':'🇺🇸', 'CA':'🇨🇦', 'MX':'🇲🇽', 'GT':'🇬🇹', 'BZ':'🇧🇿', 'SV':'🇸🇻', 'HN':'🇭🇳', 'NI':'🇳🇮', 'CR':'🇨🇷', 'PA':'🇵🇦',
        'CU':'🇨🇺', 'JM':'🇯🇲', 'HT':'🇭🇹', 'DO':'🇩🇴', 'PR':'🇵🇷', 'TT':'🇹🇹', 'BB':'🇧🇧', 'LC':'🇱🇨', 'GD':'🇬🇩', 'VC':'🇻🇨', 'AG':'🇦🇬', 'KN':'🇰🇳', 'DM':'🇩🇲', 'BS':'🇧🇸',
        'BR':'🇧🇷', 'AR':'🇦🇷', 'CL':'🇨🇱', 'CO':'🇨🇴', 'PE':'🇵🇪', 'VE':'🇻🇪', 'EC':'🇪🇨', 'BO':'🇧🇴', 'PY':'🇵🇾', 'UY':'🇺🇾', 'GY':'🇬🇾', 'SR':'🇸🇷', 'GF':'🇬🇫',
        'LATAM':'🌎', 'GLOBAL':'🌍'
      }.get(brand.country, '🏁') }}</span>{{ brand.country }}
    {% else %}
      —
    {% endif %}
  </td>
  <td><span class="sector">{{ brand.sector or '—' }}</span></td>
  <td>{{ brand.main_domain or '—' }}</td>
  <td>
    {% if brand.keyword %}
      <span class="keyword">{{ brand.keyword }}</span>
    {% else %}
      —
    {% endif %}
  </td>
  <td>{{ brand.opportunity_score or 0 }}</td>
  <td>
    {% if brand.active %}
      <span class="status-active">✅ Active</span>
    {% else %}
      <span class="status-inactive">❌ Inactive</span>
    {% endif %}
  </td>
  <td>
    <button class="btn btn-secondary" onclick="editBrand({{ brand.id }})">Edit</button>
  </td>
</tr>
{% endfor %}
</tbody>
</table>

<!-- Add/Edit Brand Modal -->
<div id="brandModal" class="modal">
  <div class="modal-content">
    <div class="modal-header">
      <span class="close" onclick="closeModal()">&times;</span>
      <h2 class="modal-title" id="modalTitle">Add New Brand</h2>
    </div>
    <div class="modal-body">
      <form id="brandForm" onsubmit="saveBrand(event)">
        <input type="hidden" id="brandId" value="">
        
        <div class="form-row">
          <div class="form-group">
            <label class="form-label" for="brand">Brand Name *</label>
            <input type="text" class="form-input" id="brand" required>
          </div>
          <div class="form-group">
            <label class="form-label" for="name">Full Organization Name</label>
            <input type="text" class="form-input" id="name">
          </div>
        </div>
        
        <div class="form-row">
          <div class="form-group">
            <label class="form-label" for="country">Country</label>
            <select class="form-input" id="country">
              <option value="">Select Country</option>
              <!-- North America -->
              <option value="US">🇺🇸 United States</option>
              <option value="CA">🇨🇦 Canada</option>
              <option value="MX">🇲🇽 Mexico</option>
              <!-- Central America -->
              <option value="GT">🇬🇹 Guatemala</option>
              <option value="BZ">🇧🇿 Belize</option>
              <option value="SV">🇸🇻 El Salvador</option>
              <option value="HN">🇭🇳 Honduras</option>
              <option value="NI">🇳🇮 Nicaragua</option>
              <option value="CR">🇨🇷 Costa Rica</option>
              <option value="PA">🇵🇦 Panama</option>
              <!-- Caribbean -->
              <option value="CU">🇨🇺 Cuba</option>
              <option value="JM">🇯🇲 Jamaica</option>
              <option value="HT">🇭🇹 Haiti</option>
              <option value="DO">🇩🇴 Dominican Republic</option>
              <option value="PR">🇵🇷 Puerto Rico</option>
              <option value="TT">🇹🇹 Trinidad and Tobago</option>
              <option value="BB">🇧🇧 Barbados</option>
              <option value="LC">🇱🇨 Saint Lucia</option>
              <option value="GD">🇬🇩 Grenada</option>
              <option value="VC">🇻🇨 Saint Vincent and the Grenadines</option>
              <option value="AG">🇦🇬 Antigua and Barbuda</option>
              <option value="KN">🇰🇳 Saint Kitts and Nevis</option>
              <option value="DM">🇩🇲 Dominica</option>
              <option value="BS">🇧🇸 Bahamas</option>
              <!-- South America -->
              <option value="BR">🇧🇷 Brazil</option>
              <option value="AR">🇦🇷 Argentina</option>
              <option value="CL">🇨🇱 Chile</option>
              <option value="CO">🇨🇴 Colombia</option>
              <option value="PE">🇵🇪 Peru</option>
              <option value="VE">🇻🇪 Venezuela</option>
              <option value="EC">🇪🇨 Ecuador</option>
              <option value="BO">🇧🇴 Bolivia</option>
              <option value="PY">🇵🇾 Paraguay</option>
              <option value="UY">🇺🇾 Uruguay</option>
              <option value="GY">🇬🇾 Guyana</option>
              <option value="SR">🇸🇷 Suriname</option>
              <option value="GF">🇬🇫 French Guiana</option>
              <!-- Global/Regional -->
              <option value="LATAM">🌎 Latin America</option>
              <option value="GLOBAL">🌍 Global</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label" for="sector">Sector</label>
            <select class="form-input" id="sector">
              <option value="">Select Sector</option>
              <option value="banking">Banking</option>
              <option value="fintech">Fintech</option>
              <option value="ecommerce">E-commerce</option>
              <option value="transport">Transport</option>
              <option value="government">Government</option>
              <option value="telecom">Telecom</option>
              <option value="retail">Retail</option>
              <option value="healthcare">Healthcare</option>
              <option value="education">Education</option>
              <option value="other">Other</option>
            </select>
          </div>
        </div>
        
        <div class="form-row">
          <div class="form-group">
            <label class="form-label" for="main_domain">Main Domain</label>
            <input type="text" class="form-input" id="main_domain" placeholder="example.com">
          </div>
          <div class="form-group">
            <label class="form-label" for="keyword">Detection Keyword *</label>
            <input type="text" class="form-input" id="keyword" required placeholder="Brand keyword for detection">
          </div>
        </div>
        
        <div class="form-group">
          <label class="form-label" for="opportunity_score">Opportunity Score (0-100)</label>
          <input type="number" class="form-input" id="opportunity_score" min="0" max="100" value="50">
        </div>
        
        <div class="form-group">
          <label class="form-label" for="authorized_domains">Authorized Domains (one per line)</label>
          <textarea class="form-input form-textarea" id="authorized_domains" placeholder="domain1.com
domain2.com
subdomain.domain.com"></textarea>
        </div>
        
        <div class="form-row" style="margin-top: 24px;">
          <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
          <button type="submit" class="btn">Save Brand</button>
        </div>
      </form>
    </div>
  </div>
</div>

<script>
function openModal() {
  document.getElementById('modalTitle').textContent = 'Add New Brand';
  document.getElementById('brandForm').reset();
  document.getElementById('brandId').value = '';
  document.getElementById('brandModal').style.display = 'block';
}

function closeModal() {
  document.getElementById('brandModal').style.display = 'none';
}

function editBrand(id) {
  document.getElementById('modalTitle').textContent = 'Edit Brand';
  document.getElementById('brandId').value = id;
  
  // Load brand data
  console.log('Loading brand ID:', id);
  fetch('/brands/' + id)
    .then(response => {
      console.log('Response status:', response.status);
      return response.json();
    })
    .then(data => {
      console.log('Response data:', data);
      if (data.success) {
        const brand = data.brand;
        console.log('Loading brand:', brand.brand);
        
        // Populate form fields
        document.getElementById('brand').value = brand.brand || '';
        document.getElementById('name').value = brand.name || '';
        document.getElementById('country').value = brand.country || '';
        document.getElementById('sector').value = brand.sector || '';
        document.getElementById('main_domain').value = brand.main_domain || '';
        document.getElementById('keyword').value = brand.keyword || '';
        document.getElementById('opportunity_score').value = brand.opportunity_score || 50;
        
        // Handle authorized domains array
        if (brand.authorized_domains && Array.isArray(brand.authorized_domains)) {
          document.getElementById('authorized_domains').value = brand.authorized_domains.join('\\n');
        } else {
          document.getElementById('authorized_domains').value = '';
        }
        
        console.log('Form populated, showing modal');
        // Show modal
        document.getElementById('brandModal').style.display = 'block';
      } else {
        console.error('API error:', data.error);
        alert('Error loading brand data: ' + data.error);
      }
    })
    .catch(error => {
      console.error('Fetch error:', error);
      alert('Error loading brand: ' + error);
    });
}

function saveBrand(event) {
  event.preventDefault();
  
  const formData = {
    brand: document.getElementById('brand').value,
    name: document.getElementById('name').value,
    country: document.getElementById('country').value,
    sector: document.getElementById('sector').value,
    main_domain: document.getElementById('main_domain').value,
    keyword: document.getElementById('keyword').value,
    opportunity_score: document.getElementById('opportunity_score').value,
    authorized_domains: document.getElementById('authorized_domains').value.split('\\n').filter(d => d.trim())
  };
  
  const brandId = document.getElementById('brandId').value;
  const method = brandId ? 'PUT' : 'POST';
  const url = brandId ? '/brands/' + brandId : '/brands';
  
  fetch(url, {
    method: method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(formData)
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      location.reload();
    } else {
      alert('Error: ' + data.error);
    }
  })
  .catch(error => {
    alert('Error saving brand: ' + error);
  });
}

function filterTable() {
  const input = document.getElementById('searchInput').value.toLowerCase();
  const table = document.getElementById('brandsTable');
  const rows = table.getElementsByTagName('tr');
  
  for (let i = 1; i < rows.length; i++) {
    const row = rows[i];
    const text = row.textContent.toLowerCase();
    row.style.display = text.includes(input) ? '' : 'none';
  }
}

// Close modal when clicking outside
window.onclick = function(event) {
  const modal = document.getElementById('brandModal');
  if (event.target == modal) {
    closeModal();
  }
}
</script>

</body>
</html>
"""

@app.route('/')
def index():
    brands = get_brands()
    stats = get_brand_stats()
    return render_template_string(TEMPLATE, brands=brands, stats=stats)

@app.route('/brands', methods=['POST'])
def add_brand():
    """Add new brand"""
    try:
        data = request.get_json()
        
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO brands (brand, name, country, sector, main_domain, keyword, 
                                  opportunity_score, authorized_domains, active)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                data['brand'],
                data.get('name') or None,
                data.get('country') or None,
                data.get('sector') or None,
                data.get('main_domain') or None,
                data['keyword'],
                float(data.get('opportunity_score', 50)),
                data.get('authorized_domains', []),
                True
            ))
            brand_id = cur.fetchone()[0]
            conn.commit()
            
        return jsonify({'success': True, 'id': brand_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/brands/<int:brand_id>', methods=['GET'])
def get_brand(brand_id):
    """Get specific brand data for editing"""
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT id, brand, name, country, sector, main_domain, keyword, 
                       opportunity_score, active, authorized_domains
                FROM brands 
                WHERE id = %s
            """, (brand_id,))
            brand_data = cur.fetchone()
            
            if not brand_data:
                return jsonify({'success': False, 'error': 'Brand not found'})
            
            # Convert to dict
            brand = {
                'id': brand_data[0],
                'brand': brand_data[1],
                'name': brand_data[2],
                'country': brand_data[3],
                'sector': brand_data[4],
                'main_domain': brand_data[5],
                'keyword': brand_data[6],
                'opportunity_score': brand_data[7],
                'active': brand_data[8],
                'authorized_domains': brand_data[9] or []
            }
            
            return jsonify({'success': True, 'brand': brand})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/brands/<int:brand_id>', methods=['PUT'])
def update_brand(brand_id):
    """Update existing brand"""
    try:
        data = request.get_json()
        
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                UPDATE brands 
                SET brand = %s, name = %s, country = %s, sector = %s, 
                    main_domain = %s, keyword = %s, opportunity_score = %s, 
                    authorized_domains = %s
                WHERE id = %s
            """, (
                data['brand'],
                data.get('name') or None,
                data.get('country') or None,
                data.get('sector') or None,
                data.get('main_domain') or None,
                data['keyword'],
                float(data.get('opportunity_score', 50)),
                data.get('authorized_domains', []),
                brand_id
            ))
            conn.commit()
            
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5011, debug=False)