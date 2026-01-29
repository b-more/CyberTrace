# 🔬 Threat Intelligence - Technical Deep Dive & Testing Guide

## 📋 Table of Contents
1. [System Architecture](#architecture)
2. [Data Flow Explained](#data-flow)
3. [Integration Details](#integrations)
4. [Test Data & Scenarios](#test-data)
5. [API Testing Guide](#api-testing)
6. [Troubleshooting](#troubleshooting)

---

## 🏗️ System Architecture {#architecture}

### Overview
The threat intelligence system operates on a **dual-source model**:

```
┌─────────────────────────────────────────────────────────────┐
│                    USER SUBMITS QUERY                       │
│              (Phone/Email/Domain/IP/URL)                    │
└────────────────────────┬────────────────────────────────────┘
                         │
         ┌───────────────┴───────────────┐
         │                               │
    ┌────▼─────┐                   ┌────▼──────┐
    │  LOCAL   │                   │ EXTERNAL  │
    │ DATABASE │                   │   APIs    │
    │(SQLite)  │                   │ (5 sources)│
    └────┬─────┘                   └────┬──────┘
         │                              │
         │ Zambian Reports              │ Global Threats
         │ Police Cases                 │ Real-time Feeds
         │ Public Reports               │ Community Data
         │                              │
         └────────────┬─────────────────┘
                      │
              ┌───────▼────────┐
              │   AGGREGATION  │
              │   & SCORING    │
              └───────┬────────┘
                      │
              ┌───────▼────────┐
              │    RESULTS     │
              │  (JSON/HTML)   │
              └────────────────┘
```

---

## 🔄 Data Flow Explained {#data-flow}

### Step 1: Query Reception
**What Happens:**
- User enters indicator (e.g., +260xxxxxxxxx)
- System validates format
- Auto-detects indicator type (phone/email/domain/IP/URL)

**Code Location:** `app/routes/threat_intel.py:89-170` (search route)

### Step 2: Local Database Query
**What Happens:**
- Searches SQLite database table `threat_intel`
- Matches against all 7 indicator types
- Returns all matching records

**SQL Query:**
```sql
SELECT * FROM threat_intel
WHERE phone_number = '+260xxxxxxxxx'
   OR email_address = '+260xxxxxxxxx'
   OR domain = '+260xxxxxxxxx'
   -- ... checks all fields
AND status = 'active'
```

**Code Location:** `app/models/threat_intel.py:300-315` (find_by_indicator method)

**Data Source:**
- Police investigations
- Public reports (via /threat-intel/public/report)
- Manual entries by investigators
- Verified threats

### Step 3: External API Queries (Parallel)
**What Happens:**
- 5 APIs queried simultaneously using ThreadPoolExecutor
- Each API returns threat data independently
- Timeout protection (30 seconds max per API)
- Errors handled gracefully (failed API doesn't break system)

**Code Location:** `app/modules/threat_intelligence/unified_service.py:80-150`

**Parallel Execution:**
```python
with ThreadPoolExecutor(max_workers=5) as executor:
    futures = {
        executor.submit(check_alienvault, indicator),
        executor.submit(check_urlhaus, indicator),
        executor.submit(check_threatfox, indicator),
        executor.submit(check_abuseipdb, indicator),
        executor.submit(check_cisco_talos, indicator)
    }
    # Wait for all to complete
```

### Step 4: Score Aggregation
**What Happens:**
- Each source returns threat score (0-100)
- Maximum score is taken as overall threat score
- Risk level determined based on score
- Findings compiled into single result

**Scoring Algorithm:**
```python
max_score = max(all_threat_scores)

if max_score >= 80: risk_level = 'critical'
elif max_score >= 60: risk_level = 'high'
elif max_score >= 40: risk_level = 'medium'
elif max_score >= 20: risk_level = 'low'
else: risk_level = 'clean'
```

**Code Location:** `app/modules/threat_intelligence/unified_service.py:200-230`

### Step 5: Results Display
**What Happens:**
- Results rendered in two sections:
  1. Local Database Results (Zambian data)
  2. External API Results (Global data)
- Each section expandable for details
- Color-coded by risk level

**Template:** `app/templates/threat_intel/search.html:84-274`

---

## 🔌 Integration Details {#integrations}

### 1. AlienVault OTX (Open Threat Exchange)
**URL:** https://otx.alienvault.com/
**Coverage:** 19+ million threat indicators
**API Key Required:** Yes (FREE)
**Rate Limit:** 10 requests/second

**What it checks:**
- IP addresses (malicious IPs, botnets, C2 servers)
- Domains (phishing sites, malware distribution)
- URLs (malicious links)
- File hashes (malware signatures)

**Code:** `app/modules/threat_intelligence/alienvault_otx.py`

**API Endpoints Used:**
```
GET /api/v1/indicators/IPv4/{ip}/general
GET /api/v1/indicators/domain/{domain}/general
GET /api/v1/indicators/url/{url}/general
```

**Response Format:**
```json
{
  "pulse_info": {
    "count": 3,
    "pulses": [
      {
        "name": "Mobile Money Scam Campaign 2025",
        "description": "Zambian mobile money scams",
        "tags": ["scam", "fraud", "zambia"],
        "created": "2025-01-15T10:30:00"
      }
    ]
  }
}
```

**How to Get API Key:**
1. Visit https://otx.alienvault.com/
2. Click "Sign Up" (FREE)
3. Verify email
4. Go to Settings → API Integration
5. Copy your API key

**How to Configure:**
```bash
export ALIENVAULT_OTX_API_KEY="your_key_here"
```

---

### 2. URLhaus (abuse.ch)
**URL:** https://urlhaus.abuse.ch/
**Coverage:** Malicious URLs and phishing sites
**API Key Required:** No (completely free)
**Rate Limit:** 60 requests/minute

**What it checks:**
- URLs (phishing, malware distribution)
- Domains (hosting malicious content)
- Malware families
- Online/offline status

**Code:** `app/modules/threat_intelligence/abuse_ch.py:20-100`

**API Endpoint:**
```
POST https://urlhaus-api.abuse.ch/v1/url/
POST https://urlhaus-api.abuse.ch/v1/host/
```

**Request:**
```json
{
  "url": "http://phishing-site.com"
}
```

**Response:**
```json
{
  "query_status": "ok",
  "url": "http://phishing-site.com",
  "url_status": "online",
  "threat": "malware_download",
  "tags": ["emotet", "phishing"],
  "date_added": "2025-01-20"
}
```

**No Setup Required** - Works immediately!

---

### 3. ThreatFox (abuse.ch)
**URL:** https://threatfox.abuse.ch/
**Coverage:** Indicators of Compromise (IoCs)
**API Key Required:** No (completely free)
**Rate Limit:** 60 requests/minute

**What it checks:**
- Malware IoCs
- C2 servers
- Botnet infrastructure
- Threat actor campaigns

**Code:** `app/modules/threat_intelligence/abuse_ch.py:100-196`

**API Endpoint:**
```
POST https://threatfox-api.abuse.ch/api/v1/
```

**Request:**
```json
{
  "query": "search_ioc",
  "search_term": "192.168.1.1"
}
```

**Response:**
```json
{
  "query_status": "ok",
  "data": [
    {
      "ioc": "192.168.1.1",
      "threat_type": "botnet_cc",
      "malware": "emotet",
      "confidence_level": 100,
      "first_seen": "2025-01-10",
      "tags": ["emotet", "banking_trojan"]
    }
  ]
}
```

**No Setup Required** - Works immediately!

---

### 4. AbuseIPDB
**URL:** https://www.abuseipdb.com/
**Coverage:** IP abuse reports
**API Key Required:** Yes (FREE - 1,000 checks/day)
**Rate Limit:** 1,000 requests/day (free tier)

**What it checks:**
- IP addresses (spam, hacking attempts, DDoS)
- Abuse confidence score
- Report history
- ISP information

**Code:** `app/modules/threat_intelligence/abuseipdb.py`

**API Endpoint:**
```
GET https://api.abuseipdb.com/api/v2/check?ipAddress=X
```

**Headers:**
```
Key: your_api_key_here
Accept: application/json
```

**Response:**
```json
{
  "data": {
    "ipAddress": "192.168.1.1",
    "abuseConfidenceScore": 85,
    "totalReports": 42,
    "numDistinctUsers": 18,
    "lastReportedAt": "2025-01-25T14:30:00+00:00",
    "usageType": "Data Center/Web Hosting/Transit",
    "isWhitelisted": false
  }
}
```

**How to Get API Key:**
1. Visit https://www.abuseipdb.com/
2. Click "Register" (FREE)
3. Verify email
4. Go to Account → API
5. Generate API key (v2)

**How to Configure:**
```bash
export ABUSEIPDB_API_KEY="your_key_here"
```

---

### 5. Cisco Talos Intelligence
**URL:** https://talosintelligence.com/
**Coverage:** Email/domain reputation
**API Key Required:** No (web scraping)
**Rate Limit:** 30 requests/minute (conservative)

**What it checks:**
- Email sender reputation
- Domain reputation
- IP reputation
- Threat categories

**Code:** `app/modules/threat_intelligence/cisco_talos.py`

**How it Works:**
- Uses BeautifulSoup4 to scrape reputation page
- Parses HTML for reputation scores
- No API key needed

**URL Format:**
```
https://talosintelligence.com/reputation_center/lookup?search=example.com
```

**Parsed Data:**
- Reputation: Good/Neutral/Poor/Untrusted
- Threat categories (if any)
- Email volume
- Web reputation

**No Setup Required** - Works immediately!

---

## 🧪 Test Data & Scenarios {#test-data}

### Creating Test Data in Local Database

Let me create a Python script to add sample test data:

```python
# Add sample threats to database
from app import create_app, db
from app.models.threat_intel import ThreatIntel
from datetime import datetime, timedelta

app = create_app()
with app.app_context():
    # Test 1: Scam Phone Number (HIGH severity)
    threat1 = ThreatIntel(
        phone_number='+260971234567',
        threat_type='scam',
        severity='high',
        confidence_score=85,
        status='active',
        verified=True,
        description='MTN mobile money scam. Caller claims to be MTN staff and requests PIN.',
        source='investigation',
        report_count=8,
        financial_loss=45000.00,
        country_code='ZM',
        region='Lusaka',
        first_seen=datetime.utcnow() - timedelta(days=15),
        last_seen=datetime.utcnow()
    )

    # Test 2: Phishing Email (CRITICAL severity)
    threat2 = ThreatIntel(
        email_address='support@zanaco-secure.com',
        domain='zanaco-secure.com',
        threat_type='phishing',
        severity='critical',
        confidence_score=95,
        status='active',
        verified=True,
        description='Fake Zanaco banking email requesting account credentials.',
        source='investigation',
        report_count=12,
        financial_loss=120000.00,
        country_code='ZM',
        region='Lusaka',
        first_seen=datetime.utcnow() - timedelta(days=5),
        last_seen=datetime.utcnow() - timedelta(hours=2)
    )

    # Test 3: Clean Number (LOW severity)
    threat3 = ThreatIntel(
        phone_number='+260977777777',
        threat_type='spam',
        severity='low',
        confidence_score=20,
        status='resolved',
        verified=False,
        description='Telemarketing calls. Not malicious.',
        source='public_report',
        report_count=2,
        financial_loss=0.00,
        country_code='ZM',
        region='Ndola',
        first_seen=datetime.utcnow() - timedelta(days=30),
        last_seen=datetime.utcnow() - timedelta(days=25)
    )

    # Test 4: Malicious Domain (HIGH severity)
    threat4 = ThreatIntel(
        domain='free-airtel-data.com',
        url='http://free-airtel-data.com/claim',
        threat_type='phishing',
        severity='high',
        confidence_score=80,
        status='active',
        verified=True,
        description='Fake Airtel promotion site. Steals personal information.',
        source='investigation',
        report_count=6,
        financial_loss=15000.00,
        country_code='ZM',
        region='Copperbelt',
        first_seen=datetime.utcnow() - timedelta(days=10),
        last_seen=datetime.utcnow() - timedelta(days=1)
    )

    # Test 5: Suspicious IP (MEDIUM severity)
    threat5 = ThreatIntel(
        ip_address='41.222.45.10',
        threat_type='fraud',
        severity='medium',
        confidence_score=60,
        status='investigating',
        verified=False,
        description='Multiple failed login attempts from this IP.',
        source='investigation',
        report_count=3,
        financial_loss=0.00,
        country_code='ZM',
        first_seen=datetime.utcnow() - timedelta(days=7),
        last_seen=datetime.utcnow() - timedelta(hours=12)
    )

    db.session.add_all([threat1, threat2, threat3, threat4, threat5])
    db.session.commit()

    print("✅ 5 test threats added successfully!")
```

---

## 📝 Testing Scenarios {#test-data}

### Scenario 1: Scam Phone Number (Local Database Hit)

**Test Indicator:** `+260971234567`

**Expected Results:**

**Local Database:**
```
⚠️ Found 1 local threat(s)

Indicator: +260971234567
Type: scam
Severity: HIGH
Confidence: 85%
Reports: 8
Financial Loss: K45,000
Status: Verified
Region: Lusaka, Zambia

Description:
MTN mobile money scam. Caller claims to be MTN staff and requests PIN.

First Seen: 15 days ago
Last Seen: Today
```

**External APIs:**
- AlienVault OTX: Likely no results (unless someone reported it globally)
- URLhaus: No results (not a URL)
- ThreatFox: No results (not malware IoC)
- AbuseIPDB: No results (not an IP)
- Cisco Talos: No results (not a domain)

**Risk Assessment:**
- Threat Score: 85/100
- Risk Level: HIGH
- Sources Found: 1 (local database)

---

### Scenario 2: Phishing Domain (Local + Global Hit)

**Test Indicator:** `zanaco-secure.com`

**Expected Results:**

**Local Database:**
```
⚠️ Found 1 local threat(s)

Indicator: zanaco-secure.com
Type: phishing
Severity: CRITICAL
Confidence: 95%
Reports: 12
Financial Loss: K120,000
Status: Verified
```

**External APIs:**
- **AlienVault OTX:** Likely found in phishing campaigns
- **URLhaus:** HIGH chance of being listed (fake banking site)
- **ThreatFox:** Possible match if used in malware campaigns
- **AbuseIPDB:** No results (not an IP)
- **Cisco Talos:** Poor reputation (phishing domain)

**Risk Assessment:**
- Threat Score: 95/100
- Risk Level: CRITICAL
- Sources Found: 3-4 sources

---

### Scenario 3: Known Malicious URL (Global Hit)

**Test Indicator:** `malware.com` or `http://malware.com`

**Expected Results:**

**Local Database:**
```
✓ No threats found in Zambian database
```

**External APIs:**
- **AlienVault OTX:** Multiple pulses, known malware distribution
- **URLhaus:** Listed as malware distribution site
- **ThreatFox:** IoCs associated with domain
- **Cisco Talos:** Poor/Untrusted reputation

**Risk Assessment:**
- Threat Score: 90-100/100
- Risk Level: CRITICAL
- Sources Found: 3-4 sources

---

### Scenario 4: Clean Indicator (No Hits)

**Test Indicator:** `google.com` or `+1234567890`

**Expected Results:**

**Local Database:**
```
✓ No threats found in Zambian database
```

**External APIs:**
- AlienVault OTX: Clean
- URLhaus: Not found
- ThreatFox: Not found
- AbuseIPDB: Clean (if IP)
- Cisco Talos: Good reputation

**Risk Assessment:**
- Threat Score: 0/100
- Risk Level: CLEAN
- Sources Found: 0 sources

---

### Scenario 5: Malicious IP Address (Global Hit)

**Test Indicator:** `185.220.101.1` (known Tor exit node)

**Expected Results:**

**Local Database:**
```
✓ No threats found in Zambian database
```

**External APIs:**
- **AlienVault OTX:** Listed in threat intelligence
- **URLhaus:** Possible malware hosting
- **ThreatFox:** Possible C2 server
- **AbuseIPDB:** HIGH abuse confidence score (80+)
- **Cisco Talos:** Poor reputation

**Risk Assessment:**
- Threat Score: 70-90/100
- Risk Level: HIGH to CRITICAL
- Sources Found: 2-4 sources

---

## 🧪 API Testing Guide {#api-testing}

### Testing Without API Keys (Works Now)

**Available Sources:**
1. ✅ Local Database - Always works
2. ✅ URLhaus - No API key needed
3. ✅ ThreatFox - No API key needed
4. ✅ Cisco Talos - No API key needed
5. ❌ AlienVault OTX - Needs API key
6. ❌ AbuseIPDB - Needs API key

**Test Command:**
```bash
# Test URLhaus (no key needed)
curl -X POST https://urlhaus-api.abuse.ch/v1/url/ \
  -d "url=http://malware.com"

# Test ThreatFox (no key needed)
curl -X POST https://threatfox-api.abuse.ch/api/v1/ \
  -H "Content-Type: application/json" \
  -d '{"query":"search_ioc","search_term":"malware.com"}'
```

### Testing With API Keys (Full System)

**Step 1: Get Free API Keys**
```bash
# AlienVault OTX (5 minutes)
1. Visit: https://otx.alienvault.com/
2. Sign up (free)
3. Go to Settings → API Integration
4. Copy API key

# AbuseIPDB (5 minutes)
1. Visit: https://www.abuseipdb.com/
2. Register (free)
3. Go to Account → API
4. Generate API key (v2)
```

**Step 2: Configure Environment**
```bash
export ALIENVAULT_OTX_API_KEY="your_otx_key_here"
export ABUSEIPDB_API_KEY="your_abuseipdb_key_here"
```

**Step 3: Restart Application**
```bash
pkill -f "python run.py"
source venv/bin/activate
export FLASK_APP=run.py
python run.py
```

**Step 4: Test with Known Threats**
```bash
# Test AlienVault
curl -H "X-OTX-API-KEY: your_key" \
  https://otx.alienvault.com/api/v1/indicators/domain/malware.com/general

# Test AbuseIPDB
curl -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=185.220.101.1" \
  -H "Key: your_key" \
  -H "Accept: application/json"
```

---

## 🔍 Visual Indicators in Results

### Result Display Format

```
═══════════════════════════════════════════════
📊 SEARCH RESULTS FOR: +260971234567
═══════════════════════════════════════════════

🇿🇲 ZAMBIAN THREAT DATABASE
───────────────────────────────────────────────
⚠️ Found 1 local threat(s)

┌─────────────────────────────────────────────┐
│ Indicator: +260971234567                    │
│ Type: scam                                  │
│ Severity: ⚠️ HIGH                          │
│ Confidence: 85%                             │
│ Reports: 8 reports                          │
│ Financial Loss: K45,000                     │
│ Status: ✅ Verified                        │
│ Region: Lusaka, Zambia 🇿🇲                 │
│                                             │
│ First Seen: 2025-10-13                      │
│ Last Seen: 2025-10-28 (TODAY)               │
│ Days Active: 15 days                        │
│                                             │
│ [View Full Report]                          │
└─────────────────────────────────────────────┘

Data Source: Local police database
Source Quality: ✅ Verified by investigators

───────────────────────────────────────────────

🌍 GLOBAL THREAT INTELLIGENCE
───────────────────────────────────────────────

┌──────────────┬──────────────┬──────────────┬──────────────┐
│ Risk Level   │ Threat Score │   Sources    │   Found In   │
│              │              │   Checked    │              │
├──────────────┼──────────────┼──────────────┼──────────────┤
│   🟠 HIGH    │   85/100     │      5       │      1       │
└──────────────┴──────────────┴──────────────┴──────────────┘

⚠️ WARNING: This indicator is flagged as MALICIOUS!

🔎 Detailed Findings:

▼ Local Zambian Database - ✅ Threat Detected - Score: 85
  ├─ Source: Local police investigation
  ├─ Reports: 8 reports from victims
  ├─ Financial Impact: K45,000 total losses
  ├─ Verification: ✅ Verified by Officer #ZP-1234
  └─ Status: Active investigation ongoing

▼ AlienVault OTX - ❌ No Results
  └─ Not found in global threat database

▼ URLhaus (abuse.ch) - ❌ No Results
  └─ Not applicable (phone number, not URL)

▼ ThreatFox (abuse.ch) - ❌ No Results
  └─ Not found in IoC database

▼ AbuseIPDB - ❌ No Results
  └─ Not applicable (phone number, not IP)

▼ Cisco Talos - ❌ No Results
  └─ Not applicable (phone number, not domain)

═══════════════════════════════════════════════
RECOMMENDATION: HIGH RISK
This number is confirmed in Zambian scam database.
Investigate immediately and warn potential victims.
═══════════════════════════════════════════════
```

---

## 🐛 Troubleshooting {#troubleshooting}

### Issue: "No external results"

**Possible Causes:**
1. API keys not configured (AlienVault OTX, AbuseIPDB)
2. Network connectivity issue
3. API rate limits exceeded

**How to Check:**
```bash
# Check if API keys are set
echo $ALIENVAULT_OTX_API_KEY
echo $ABUSEIPDB_API_KEY

# Test network connectivity
curl -I https://otx.alienvault.com/
curl -I https://urlhaus-api.abuse.ch/

# Check application logs
tail -f app.log | grep -i "threat"
```

**Solution:**
- Configure missing API keys
- Check firewall/network settings
- Wait if rate limited (resets daily/hourly)

---

### Issue: "CSRF token error"

**Solution:**
1. Hard refresh page (Ctrl+Shift+R)
2. Clear browser cache
3. Enable cookies
4. Don't open form in new tab without refreshing

---

### Issue: "Database query slow"

**Possible Causes:**
1. No indexes on indicator fields
2. Large database without optimization

**Solution:**
```python
# Add indexes (should already exist)
from app import create_app, db
app = create_app()
with app.app_context():
    db.session.execute('CREATE INDEX IF NOT EXISTS idx_phone ON threat_intel(phone_number)')
    db.session.execute('CREATE INDEX IF NOT EXISTS idx_email ON threat_intel(email_address)')
    db.session.execute('CREATE INDEX IF NOT EXISTS idx_domain ON threat_intel(domain)')
    db.session.execute('CREATE INDEX IF NOT EXISTS idx_ip ON threat_intel(ip_address)')
    db.session.commit()
```

---

## 📈 Performance Metrics

### Expected Response Times

| Operation | Expected Time | Notes |
|-----------|--------------|-------|
| Local database query | < 100ms | Instant |
| Single external API | 500ms - 2s | Depends on API |
| All 5 APIs (parallel) | 2-5s | Max timeout: 30s |
| Full threat check | 2-5s | Local + External |
| Dashboard load | < 500ms | Statistics only |

### API Quotas

| Source | Free Tier | Rate Limit |
|--------|-----------|------------|
| AlienVault OTX | Unlimited | 10/second |
| URLhaus | Unlimited | 60/minute |
| ThreatFox | Unlimited | 60/minute |
| AbuseIPDB | 1,000/day | 1,000/day |
| Cisco Talos | Unlimited | ~30/minute (scraped) |

---

## 🎯 Summary

### What You Get With Threat Intelligence

1. **Instant Local Threat Detection**
   - Check against Zambian police database
   - See verified scams and frauds
   - View financial losses and victim counts

2. **Global Threat Coverage**
   - 19M+ indicators from AlienVault OTX
   - Real-time malware URLs from URLhaus
   - C2 servers and IoCs from ThreatFox
   - IP abuse reports from AbuseIPDB
   - Domain reputation from Cisco Talos

3. **Automatic Integration**
   - Phone OSINT automatically checks threats
   - No extra steps for investigators
   - Results in standard investigation report

4. **Public Engagement**
   - Citizens can report scams
   - Builds community threat database
   - Anonymous reporting available

5. **Case Linking**
   - Identifies related victims
   - Links multiple investigations
   - Shows scam patterns

### Data Sources At a Glance

| Source | Type | Free | API Key | Coverage |
|--------|------|------|---------|----------|
| Local DB | Zambian | ✅ | No | ZM-specific |
| AlienVault OTX | Global | ✅ | Yes | 19M+ |
| URLhaus | Global | ✅ | No | Malware URLs |
| ThreatFox | Global | ✅ | No | IoCs |
| AbuseIPDB | Global | ✅ | Yes | IP abuse |
| Cisco Talos | Global | ✅ | No | Reputation |

---

**Last Updated:** 2025-10-28
**Version:** 1.0.0
**Status:** ✅ Complete
