# 🧪 Threat Intelligence - Complete Testing Guide

## ✅ Test Data Successfully Loaded!

10 realistic threat scenarios have been added to your database covering all severity levels and use cases.

---

## 🎯 Quick Test Scenarios

### Critical Threats (Test These First!)

#### 1. SIM Swap Fraud - **CRITICAL**
```
Search: +260978888888
Expected: CRITICAL risk (92/100)
```
**What You'll See:**
- ⚠️ ACTIVE SIM SWAP FRAUD warning
- 7 reports, K185,000 losses
- Last seen: 15 minutes ago
- Verified by Cyber Crimes Unit
- **Data Source:** Local Zambian database

**Why This Matters:** Shows how system identifies urgent, active threats

---

#### 2. Zanaco Banking Phishing - **CRITICAL**
```
Search: zanaco-secure.com
Expected: CRITICAL risk (95/100)
```
**What You'll See:**
- Sophisticated phishing campaign
- 12 reports, K120,000 losses
- Fake HTTPS site (appears legitimate)
- Domain registered 5 days ago
- **Data Source:** Local database

**Why This Matters:** Demonstrates financial fraud detection

---

#### 3. Ransomware Campaign - **CRITICAL**
```
Search: secure-payment-zm.com
Expected: CRITICAL risk (98/100)
```
**What You'll See:**
- Active ransomware email campaign
- 15 reports, K250,000 losses
- CryptoLocker variant
- 4 businesses affected
- **Data Source:** Local database

**Why This Matters:** Shows malware/ransomware tracking

---

### Active Scams (High Priority)

#### 4. MTN Mobile Money Scam - **HIGH**
```
Search: +260971234567
Expected: HIGH risk (85/100)
```
**What You'll See:**
- Caller impersonates MTN staff
- Requests mobile money PIN
- 8 reports, K45,000 losses
- First seen 15 days ago
- Still active today
- **Data Source:** Local database

**Why This Matters:** Common scam pattern in Zambia

---

#### 5. WhatsApp Account Takeover - **HIGH**
```
Search: +260965432109
Expected: HIGH risk (90/100)
```
**What You'll See:**
- WhatsApp account hacking
- Emergency money requests
- 11 accounts compromised
- K67,000 losses
- **Data Source:** Local database

**Why This Matters:** Social engineering fraud

---

#### 6. Fake Airtel Promotion - **HIGH**
```
Search: free-airtel-data.com
Expected: HIGH risk (80/100)
```
**What You'll See:**
- Fake "Free 50GB data" promotion
- Collects personal information
- 6 reports from Copperbelt region
- Airtel confirmed it's fake
- **Data Source:** Local database

**Why This Matters:** Regional threat tracking

---

### Under Investigation (Medium Risk)

#### 7. Suspicious IP Address - **MEDIUM**
```
Search: 41.222.45.10
Expected: MEDIUM risk (60/100)
```
**What You'll See:**
- Multiple failed login attempts (147)
- Targets government websites
- Possible credential stuffing
- Investigation ongoing
- **Data Source:** Local database

**Why This Matters:** Cyber attack detection

---

#### 8. Job Scam (Needs Verification) - **MEDIUM**
```
Search: zambia-mining-jobs.com
Expected: MEDIUM risk (55/100)
```
**What You'll See:**
- Suspicious job offers
- Requires upfront payment (K500)
- 4 reports, K8,000 losses
- Status: investigating (unverified)
- **Data Source:** Public reports

**Why This Matters:** Shows unverified threats

---

### Low Risk (Educational Examples)

#### 9. Telemarketing Spam - **LOW**
```
Search: +260977777777
Expected: LOW risk (20/100)
```
**What You'll See:**
- Telemarketing calls
- Not malicious, just annoying
- 2 reports, no financial loss
- Status: resolved
- **Data Source:** Public reports

**Why This Matters:** Non-malicious nuisance calls

---

#### 10. False Positive - **LOW**
```
Search: +260955555555
Expected: LOW risk (15/100)
```
**What You'll See:**
- Marked as false positive
- Initially reported as spam
- Actually legitimate MTN business SMS
- Investigation confirmed legitimate
- **Data Source:** Public reports

**Why This Matters:** Shows false positive handling

---

## 📊 What to Look For During Testing

### 1. Local Database Results Section
**Shows:** Zambian threat database findings

Look for:
- ✅ Number of threats found
- ⚠️ Severity badges (Critical/High/Medium/Low)
- 📊 Confidence scores (0-100%)
- 📍 Region/location in Zambia
- 💰 Financial losses in Kwacha
- ✅ Verification status
- 📅 First seen / Last seen dates
- 👮 Investigating officer details
- 📋 Case numbers

**Data Source Indicator:** "🇿🇲 Zambian Threat Database"

---

### 2. External API Results Section
**Shows:** Global threat intelligence (5 sources)

Look for:
- 🎯 Overall threat score (0-100)
- 🚨 Risk level badge
- 🌍 Sources checked (5 total)
- ✅ Sources found (how many detected it)
- 📑 Expandable detailed findings per source

**Sources:**
1. **AlienVault OTX** (19M+ indicators) - Requires API key
2. **URLhaus** (Malicious URLs) - Works without API key
3. **ThreatFox** (IoC Database) - Works without API key
4. **AbuseIPDB** (IP Abuse) - Requires API key
5. **Cisco Talos** (Reputation) - Works without API key

**Data Source Indicators:**
- "🌍 Global Threat Intelligence"
- Separate cards for each API source
- Shows which APIs found the threat

---

## 🔍 Understanding Data Sources

### Local Zambian Database (Always Works)
**What it contains:**
- Police investigations (with case numbers)
- Citizen reports via public form
- Verified threats by investigators
- Financial loss tracking in ZMW
- Geographic data (region, city)
- Verification status

**When you see this:**
```
Data Source: Local police investigation
Case Number: ZPS-2025-0089
Verified by: Officer Mwamba (ZP-5678)
```

**This means:** The threat was identified through Zambian police work, not external APIs.

---

### External APIs (Requires Configuration)

#### Without API Keys (3 sources work now):
1. ✅ **URLhaus** - Checks malicious URLs
2. ✅ **ThreatFox** - Checks malware indicators
3. ✅ **Cisco Talos** - Checks domain reputation

#### With Free API Keys (adds 2 more sources):
4. 🔑 **AlienVault OTX** - 19M+ threat indicators
5. 🔑 **AbuseIPDB** - IP abuse database

**When you see:**
```
▼ AlienVault OTX - ✅ Threat Detected - Score: 90
  Source: AlienVault OTX
  Found: Yes
  Pulse Count: 3
  Tags: mobile_money_scam, fraud, zambia
```

**This means:** The threat was found in global threat intelligence, indicating it's part of a larger campaign.

---

## 🧪 Testing Workflow

### Step 1: Test Local Database (Works Now)
1. Go to http://72.61.162.49:9000/threat-intel/search
2. Login as investigator
3. Search any of the 10 test indicators
4. Observe local database results

**Expected:** All 10 test threats will be found in local database

---

### Step 2: Test External APIs (Partial - No Keys)
1. Same search as above
2. Check "Search External Sources" ✅
3. Click search

**Expected:**
- URLhaus: Will check (no results for test data)
- ThreatFox: Will check (no results for test data)
- Cisco Talos: Will check (no results for test data)
- AlienVault OTX: Shows "API key not configured"
- AbuseIPDB: Shows "API key not configured"

**Why no results?** The test data is Zambian-specific. Global APIs don't have this data yet.

---

### Step 3: Test with Real Global Threats (Optional)

To see external APIs actually work, search known malicious indicators:

```
malware.com       - Will be found by URLhaus/ThreatFox
phishing-site.com - May be found by URLhaus
185.220.101.1     - Tor exit node (needs AbuseIPDB key)
```

---

### Step 4: Test Public Reporting (No Login)
1. Go to http://72.61.162.49:9000/threat-intel/public/report
2. Fill out form:
   - Type: Phone Number
   - Category: Scam/Fraud
   - Indicator: +260999999999
   - Description: Test scam report
   - Financial Loss: 1000
3. Click "Submit Report"

**Expected:** Redirect to success page

4. Search for +260999999999 in threat intelligence

**Expected:** Your report appears in local database!

---

### Step 5: Test Automatic Integration (Phone OSINT)
1. Go to Investigations → Phone OSINT
2. Enter: +260971234567 (MTN scam from test data)
3. Run investigation

**Expected:**
- Normal Phone OSINT results (carrier, validation)
- PLUS: Threat Intelligence section automatically included
- Shows HIGH risk warning
- Links to full threat report

---

## 📈 Expected Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Local database search | < 100ms | Instant |
| Search with external APIs (no keys) | 2-3s | 3 sources checked |
| Search with all APIs (with keys) | 2-5s | 5 sources checked |
| Public report submission | < 500ms | Fast |
| Phone OSINT + threat intel | 30-35s | Normal + threat check |

---

## 🐛 Troubleshooting

### "No results found"
**Normal!** This means indicator is clean (not in threat database).

### "API key not configured"
**Expected** - Only shows for AlienVault OTX and AbuseIPDB until you add keys.

**To add keys (5 minutes):**
```bash
# Get free keys from:
# https://otx.alienvault.com/
# https://www.abuseipdb.com/

export ALIENVAULT_OTX_API_KEY="your_key"
export ABUSEIPDB_API_KEY="your_key"

# Restart app
pkill -f "python run.py"
source venv/bin/activate
python run.py
```

### "CSRF token missing"
1. Hard refresh page (Ctrl+Shift+R)
2. Clear browser cache
3. Enable cookies

---

## 📋 Testing Checklist

- [ ] Can access threat intelligence dashboard
- [ ] Can search local database (test all 10 indicators)
- [ ] Results show correct severity levels
- [ ] Results show correct data sources
- [ ] Can view detailed threat reports
- [ ] Public reporting form works (no login)
- [ ] Phone OSINT automatically includes threat intel
- [ ] External APIs are queried (even without keys)
- [ ] Risk levels color-coded correctly
- [ ] Financial losses displayed in ZMW

---

## 🎓 What Each Test Demonstrates

| Test # | Demonstrates |
|--------|-------------|
| 1 | Critical active threat, multiple victims, recent activity |
| 2 | Sophisticated phishing, HTTPS deception, international domain |
| 3 | Ransomware detection, business impact, malware tracking |
| 4 | Common Zambian scam pattern, social engineering |
| 5 | Account takeover, multi-victim fraud |
| 6 | Regional threats (Copperbelt), carrier impersonation |
| 7 | Cyber attack detection, government targeting |
| 8 | Unverified public reports, investigation workflow |
| 9 | Non-malicious nuisance (low priority) |
| 10 | False positive handling, verification process |

---

## 📊 Data Source Comparison

### Local Zambian Database
**Strengths:**
- ✅ Zambia-specific threats
- ✅ Police case numbers
- ✅ Financial losses in ZMW
- ✅ Geographic precision (regions, cities)
- ✅ Verification by officers
- ✅ Instant response

**Coverage:** Zambia only

---

### External APIs
**Strengths:**
- ✅ 19M+ global threats
- ✅ Real-time updates
- ✅ International scam patterns
- ✅ Malware/ransomware tracking
- ✅ Cross-border fraud

**Coverage:** Worldwide

---

## 🎯 Best Practices

1. **Always check both sources**
   - Local for Zambian threats
   - External for global threats

2. **Verify unverified threats**
   - Public reports need investigation
   - Admin can mark verified

3. **Update threat status**
   - Mark resolved when case closed
   - Mark false positives when confirmed

4. **Link to cases**
   - Add case numbers to threats
   - Track multiple victims

5. **Monitor critical threats**
   - Check dashboard daily
   - Review recent threats
   - Watch for patterns

---

## 📚 Additional Resources

1. **THREAT_INTEL_TECHNICAL_DEEP_DIVE.md**
   - Complete system architecture
   - API integration details
   - Performance metrics

2. **THREAT_INTELLIGENCE_USER_GUIDE.md**
   - User-friendly manual
   - Step-by-step instructions
   - Real-world examples

3. **THREAT_INTEL_QUICK_START.md**
   - 30-second quick start
   - Access URLs
   - Quick reference

---

## ✅ Summary

You now have:
- ✅ 10 realistic test threats in database
- ✅ All severity levels covered
- ✅ Mix of verified/unverified
- ✅ Multiple threat types
- ✅ Geographic distribution
- ✅ Financial loss data
- ✅ Complete documentation

**Ready to test the entire system!**

Access: http://72.61.162.49:9000/threat-intel/search

---

**Last Updated:** 2025-10-28
**Test Data Version:** 1.0.0
**Status:** ✅ Ready for Testing
