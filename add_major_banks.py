#!/usr/bin/env python3
"""
Add the top 3 banks from each American country to the brands database
"""
import psycopg2
from db import get_conn

# Top 3 banks by country (by assets/market presence)
MAJOR_BANKS = {
    # North America
    'US': [
        {'brand': 'JPMorgan Chase', 'name': 'JPMorgan Chase & Co.', 'keyword': 'chase', 'domain': 'chase.com'},
        {'brand': 'Bank of America', 'name': 'Bank of America Corporation', 'keyword': 'bofa', 'domain': 'bankofamerica.com'},
        {'brand': 'Wells Fargo', 'name': 'Wells Fargo & Company', 'keyword': 'wellsfargo', 'domain': 'wellsfargo.com'},
    ],
    'CA': [
        {'brand': 'Royal Bank of Canada', 'name': 'RBC Royal Bank', 'keyword': 'rbc', 'domain': 'rbc.com'},
        {'brand': 'Toronto-Dominion Bank', 'name': 'TD Bank Group', 'keyword': 'td', 'domain': 'td.com'},
        {'brand': 'Bank of Nova Scotia', 'name': 'Scotiabank', 'keyword': 'scotiabank', 'domain': 'scotiabank.com'},
    ],
    'MX': [
        {'brand': 'BBVA México', 'name': 'BBVA México', 'keyword': 'bbva', 'domain': 'bbva.mx'},  # Already exists
        {'brand': 'Banorte', 'name': 'Grupo Financiero Banorte', 'keyword': 'banorte', 'domain': 'banorte.com'},  # Already exists
        {'brand': 'Santander México', 'name': 'Banco Santander México', 'keyword': 'santander', 'domain': 'santander.com.mx'},
    ],
    
    # Central America
    'GT': [
        {'brand': 'Banco Industrial', 'name': 'Banco Industrial de Guatemala', 'keyword': 'bi', 'domain': 'bi.com.gt'},
        {'brand': 'BAC Guatemala', 'name': 'BAC Credomatic Guatemala', 'keyword': 'bac', 'domain': 'baccredomatic.com'},
        {'brand': 'Bantrab', 'name': 'Banco de los Trabajadores', 'keyword': 'bantrab', 'domain': 'bantrab.com.gt'},
    ],
    'CR': [
        {'brand': 'Banco Nacional', 'name': 'Banco Nacional de Costa Rica', 'keyword': 'bncr', 'domain': 'bncr.fi.cr'},
        {'brand': 'Banco de Costa Rica', 'name': 'Banco de Costa Rica', 'keyword': 'bcr', 'domain': 'bancobcr.com'},
        {'brand': 'BAC San José', 'name': 'BAC Credomatic Costa Rica', 'keyword': 'bacsan', 'domain': 'bac.net'},
    ],
    'PA': [
        {'brand': 'Banco General', 'name': 'Banco General S.A.', 'keyword': 'bgeneral', 'domain': 'bgeneral.com'},
        {'brand': 'Banistmo', 'name': 'Banco Istmeño', 'keyword': 'banistmo', 'domain': 'banistmo.com'},
        {'brand': 'Global Bank', 'name': 'Global Bank Corporation', 'keyword': 'globalbank', 'domain': 'gbcpanama.com'},
    ],
    
    # Caribbean
    'DO': [
        {'brand': 'Banco Popular Dominicano', 'name': 'Banco Popular Dominicano', 'keyword': 'popularenlinea', 'domain': 'popularenlinea.com'},
        {'brand': 'Banco BHD León', 'name': 'Banco BHD León', 'keyword': 'bhdleon', 'domain': 'bhdleon.com.do'},
        {'brand': 'Banco de Reservas', 'name': 'Banco de Reservas de la República Dominicana', 'keyword': 'banreservas', 'domain': 'banreservas.com'},
    ],
    'JM': [
        {'brand': 'NCB Jamaica', 'name': 'National Commercial Bank Jamaica', 'keyword': 'ncbonline', 'domain': 'jncb.com'},
        {'brand': 'Scotiabank Jamaica', 'name': 'Scotiabank Jamaica Limited', 'keyword': 'scotia', 'domain': 'scotiabank.com'},
        {'brand': 'JMMB Bank', 'name': 'JMMB Bank (Jamaica) Limited', 'keyword': 'jmmb', 'domain': 'jmmb.com'},
    ],
    'TT': [
        {'brand': 'Republic Bank', 'name': 'Republic Bank (Trinidad) Limited', 'keyword': 'republictt', 'domain': 'republicbank.com'},
        {'brand': 'RBC Royal Bank', 'name': 'RBC Royal Bank (Trinidad)', 'keyword': 'rbctt', 'domain': 'rbcroyalbank.com'},
        {'brand': 'Scotiabank Trinidad', 'name': 'Scotiabank Trinidad and Tobago', 'keyword': 'scotiatt', 'domain': 'tt.scotiabank.com'},
    ],
    
    # South America
    'AR': [
        {'brand': 'Banco Nación', 'name': 'Banco de la Nación Argentina', 'keyword': 'bna', 'domain': 'bna.com.ar'},
        {'brand': 'Banco Santander Río', 'name': 'Banco Santander Río', 'keyword': 'santanderrio', 'domain': 'santander.com.ar'},
        {'brand': 'BBVA Argentina', 'name': 'BBVA Argentina', 'keyword': 'bbva', 'domain': 'bbva.com.ar'},
    ],
    'CL': [
        {'brand': 'Banco de Chile', 'name': 'Banco de Chile', 'keyword': 'chile', 'domain': 'bancochile.cl'},  # Already exists
        {'brand': 'BCI', 'name': 'Banco de Crédito e Inversiones', 'keyword': 'bci', 'domain': 'bci.cl'},  # Already exists
        {'brand': 'Banco Santander Chile', 'name': 'Banco Santander Chile', 'keyword': 'santander', 'domain': 'banco.santander.cl'},
    ],
    'CO': [
        {'brand': 'Bancolombia', 'name': 'Bancolombia S.A.', 'keyword': 'bancolombia', 'domain': 'bancolombia.com'},  # Already exists
        {'brand': 'Davivienda', 'name': 'Banco Davivienda', 'keyword': 'davivienda', 'domain': 'davivienda.com'},  # Already exists
        {'brand': 'Banco de Bogotá', 'name': 'Banco de Bogotá', 'keyword': 'bancodebogota', 'domain': 'bancodebogota.com'},
    ],
    'PE': [
        {'brand': 'BCP', 'name': 'Banco de Crédito del Perú', 'keyword': 'bcp', 'domain': 'viabcp.com'},
        {'brand': 'BBVA Perú', 'name': 'BBVA Perú', 'keyword': 'bbva', 'domain': 'bbva.pe'},
        {'brand': 'Scotiabank Perú', 'name': 'Scotiabank Perú', 'keyword': 'scotia', 'domain': 'scotiabank.com.pe'},
    ],
    'VE': [
        {'brand': 'Banco de Venezuela', 'name': 'Banco de Venezuela', 'keyword': 'bdv', 'domain': 'bancodevenezuela.com'},
        {'brand': 'Banesco Venezuela', 'name': 'Banesco Banco Universal', 'keyword': 'banesco', 'domain': 'banesco.com'},
        {'brand': 'Banco Provincial', 'name': 'Banco Provincial BBVA', 'keyword': 'provincial', 'domain': 'provincial.com'},
    ],
    'EC': [
        {'brand': 'Banco Pichincha', 'name': 'Banco Pichincha C.A.', 'keyword': 'pichincha', 'domain': 'pichincha.com'},
        {'brand': 'Banco del Pacífico', 'name': 'Banco del Pacífico S.A.', 'keyword': 'pacifico', 'domain': 'bancodelpacifico.com'},
        {'brand': 'Produbanco', 'name': 'Produbanco Grupo Promerica', 'keyword': 'produbanco', 'domain': 'produbanco.com'},
    ],
    'BO': [
        {'brand': 'Banco Nacional de Bolivia', 'name': 'Banco Nacional de Bolivia S.A.', 'keyword': 'bnb', 'domain': 'bnb.com.bo'},
        {'brand': 'Banco Mercantil Santa Cruz', 'name': 'Banco Mercantil Santa Cruz S.A.', 'keyword': 'bmsc', 'domain': 'bmsc.com.bo'},
        {'brand': 'Banco de Crédito de Bolivia', 'name': 'Banco de Crédito de Bolivia S.A.', 'keyword': 'bcp', 'domain': 'bcp.com.bo'},
    ],
    'PY': [
        {'brand': 'Banco Continental', 'name': 'Banco Continental SAECA', 'keyword': 'continental', 'domain': 'bancontinental.com.py'},
        {'brand': 'Itaú Paraguay', 'name': 'Banco Itaú Paraguay S.A.', 'keyword': 'itau', 'domain': 'itau.com.py'},
        {'brand': 'Banco Nacional de Fomento', 'name': 'Banco Nacional de Fomento', 'keyword': 'bnf', 'domain': 'bnf.gov.py'},
    ],
    'UY': [
        {'brand': 'Banco República', 'name': 'Banco de la República Oriental del Uruguay', 'keyword': 'brou', 'domain': 'brou.com.uy'},
        {'brand': 'Banco Itaú Uruguay', 'name': 'Banco Itaú Uruguay S.A.', 'keyword': 'itau', 'domain': 'itau.com.uy'},
        {'brand': 'Banco Santander Uruguay', 'name': 'Banco Santander Uruguay S.A.', 'keyword': 'santander', 'domain': 'santander.com.uy'},
    ],
}

def add_banks():
    """Add major banks to the database"""
    with get_conn() as conn:
        cur = conn.cursor()
        
        # Get existing banks to avoid duplicates
        cur.execute('SELECT brand, country FROM brands WHERE sector = %s', ('banking',))
        existing = {f"{row[0]}_{row[1]}" for row in cur.fetchall()}
        
        added_count = 0
        skipped_count = 0
        
        for country, banks in MAJOR_BANKS.items():
            print(f'\n🏦 Processing {country}:')
            
            for bank in banks:
                bank_key = f"{bank['brand']}_{country}"
                
                if bank_key in existing:
                    print(f'   ⚠️  {bank["brand"]} - Already exists')
                    skipped_count += 1
                    continue
                
                try:
                    cur.execute("""
                        INSERT INTO brands (
                            brand, name, country, sector, main_domain, keyword, 
                            opportunity_score, active, authorized_domains
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        bank['brand'],
                        bank['name'],
                        country,
                        'banking',
                        bank.get('domain'),
                        bank['keyword'],
                        75,  # High opportunity score for major banks
                        True,
                        [bank.get('domain')] if bank.get('domain') else []
                    ))
                    
                    print(f'   ✅ {bank["brand"]} - Added')
                    added_count += 1
                    
                except Exception as e:
                    print(f'   ❌ {bank["brand"]} - Error: {e}')
        
        conn.commit()
        
        print(f'\n📊 SUMMARY:')
        print(f'   Banks added: {added_count}')
        print(f'   Banks skipped (existing): {skipped_count}')
        print(f'   Countries processed: {len(MAJOR_BANKS)}')
        
        # Show final count
        cur.execute('SELECT COUNT(*) FROM brands WHERE sector = %s', ('banking',))
        total_banks = cur.fetchone()[0]
        print(f'   Total banks in database: {total_banks}')

if __name__ == '__main__':
    add_banks()