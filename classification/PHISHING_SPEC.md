# Phishing Definition - Pleriguard V2

## Qué es Phishing

Una página de phishing es una página creada por un atacante que intenta robar información personal de sus víctimas. Utiliza el layout, texto e imágenes de una empresa real para confundir a las víctimas y hacerles creer que es la página oficial. Las urgen a ingresar sus credenciales para luego realizar desfalcos económicos, robos de identidad y fraudes.

## Tácticas de Dominio Usadas por Phishers

1. **Typo-squatting**: netflix.com → netfilx.com, paypa1.com
2. **Homoglyphs**: arnazon.com (rn vs m), g00gle.com
3. **Homophones**: paypal.com → paypai.com
4. **Cousin domains**: amazon-login.com, paypal-secure.com
5. **International characters (IDN)**: amazοn.com (gráfico omicron vs o)
6. **Brand + keyword en subdomain**: customeraccount.netflix.com, netflix-account.org
7. **Brand en sub-dominio**: www.netflix.com-account.org (brand en subdominio)
8. **Aprovechan viewport móvil**: URL largas que no se ven completas en celular

## Indicadores de Phishing (Evidence Rules)

### 1. Dominio nuevo (< 1 año)
- WHOIS creation_date < 365 días → sospechoso
- WHOIS creation_date < 30 días → muy sospechoso

### 2. IP diferente al dominio real
- Comparar IP del dominio falso vs IP del dominio oficial
- Si son diferentes → sospechoso (no concluyente solo)

### 3. Registrar no corporativo (retail)
- Registrars corporativos: MarkMonitor, CSC Corporate, SafeNames, Network Solutions
- Retail registrars: Namecheap, GoDaddy, Hostinger, Public Domain Registry → sospechoso
- Free subdomain providers (tk, ml, ga, cf, gq) → muy sospechoso

### 4. Contenido similar al sitio real
- Page title similar al sitio oficial
- Imágenes / logos copiados
- CSS / diseño copiado
- Requiere screenshot analysis

### 5. Login form o login button ★ (INDICADOR PRINCIPAL)
- Si hay un login form → phishing altamente probable
- Si hay un login button que lleva a login → phishing probable
- Campos típicos: email/username, password, sometimes phone/OTP

### 6. SSL de proveedor riesgoso o recién adquirido
- SSL issuers de riesgo: Let's Encrypt (gratuito, común en phishing), Certum, Comodo (si es gratuito)
- SSL nuevo (createdate reciente) → sospechoso

### 7. Página shallow (sin profundidad)
- Pocas páginas internas funcionan
- Solo el landing page tiene contenido
- Links internos muertos o llevan al real

### 8. Links que referencian al dominio real
- Algunos links en la página apuntan al sitio oficial
- El formulario de login apunta a un endpoint del atacante

### 9. Favicon similar al real
- Favicon copiado del sitio oficial
- Requiere screenshot analysis

### 10. Brand name + confusion keywords en dominio ★
Keywords que buscan confundir víctimas:
- login, account, secure, verify, update, confirm
- payment, billing, invoice, order
- cancellation, refund, support, help
- password, signin, auth, token
- mobile, app, mobileapp

Ejemplos: netflix-login.com, paypal-verify.com, amazon-payment.com

### 11. Brand en sub-dominio ★
- customeraccount.clara.tech
- www.netflix.com-account.org
- El brand está en la parte izquierda del dominio principal

## Clasificación

### PHISHING
≥ 3 indicadores de los arriba, incluyendo al menos uno de los marcados ★

### BENIGN
- Dominio oficial (comparar con main_domain de la brand)
- Dominio viejo (>1 año) + registrar corporativo + sin login form
- Contenido legítimo sin indicadores de confusión

### BRAND_INFRINGEMENT
**Sells unauthorized products/services using a brand's identity.**

Key differentiator from PHISHING: phishing pages **steal credentials**. Brand infringement pages **sell products/services**.

**Detection:**
1. Content contains e-commerce patterns: product listings, prices, "buy now", shopping cart
2. Claims to sell "official", "authorized", "genuine" brand products
3. Domain NOT in the brand's authorized domain list
4. Brand name may or may not be in the domain — detection is CONTENT-based

**Content signals:**
- Product listings with brand name in titles/descriptions
- E-commerce language: "buy", "price", "discount", "add to cart", "checkout"
- Claims: "official store", "authorized dealer", "100% authentic"
- Brand logos/mottos copied from official site

**Examples:**
- `clara-outlet.com` selling "discounted Clara products"
- `nubank-loans.com` offering financial services "affiliated with Nubank"
- `mercadolibre.shop` listing items "guaranteed by MercadoLibre"

**Note:** Domain containing brand name = strong signal but NOT required. Content determines category.

### BEC_SCAM
**Business Email Compromise via typo-squat domain + MX**

Domain contains the brand name (typo-squat or brand + keyword) BUT its purpose is email spoofing, not credential theft.

**Detection rules:**
1. Domain has brand typo-squat pattern (like DORMANT)
2. **MX record is active** — the defining differentiator from DORMANT
3. No login/payment form on the page (if page exists)
4. May redirect to the real brand site (victim visits domain → gets redirected → attacker already sent emails)

**Examples:**
- `paypa1.com` with MX configured to send fake PayPal invoices
- `netfliix.com` with MX pointing to attacker mail server

**Why MX matters:** Attackers set up MX so they can send emails from `support@paypa1.com` — emails that look like they come from the real brand. Recipients see the domain and trust it.

**Key differentiator from PHISHING:** BEC_SCAM = email attack vector. PHISHING = web credential capture.

### DORMANT
Domain name that has the target brand in the domain text but is NOT yet active as phishing — it's parked, empty, or has no DNS.

**Characteristics:**
1. Domain name contains the target brand (typo-squatting: netflix.xyz, netflix.top, etc.)
2. TLD differs from the official domain (.xyz, .top, .buzz, .work vs .com)
3. **Parked page** — default registrar parking layout with generic links
   - Common parked page providers: Namecheap parking, Sedo, Afternic, ParkLogic, etc.
   - IP addresses known to host parked pages
   - Links on page relate to domain topic (banking links for bank typos)
4. **Empty DNS** — registered but NO A record, NO CNAME, NO MX record
5. **WHOIS**: shows registered, limited info (creation date, registrar, registrant ref but no detailed data)
6. **MX**: either no MX at all, OR default registrar parking MX (e.g., mail.attorney.com for Namecheap parking)

**Monitoring Queue:**
- Domains flagged DORMANT enter a monitoring queue
- Every N days (configurable, e.g., 7 days), re-check DNS configuration
- If DNS changes detected (A record appears, MX changes, content changes) → re-run scoring
- If new DNS shows landing page with login form → PHISHING (score immediately)
- If remains dormant → update last_checked timestamp, continue monitoring
