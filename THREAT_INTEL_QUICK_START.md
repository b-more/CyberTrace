# 🚀 Threat Intelligence - Quick Start Guide

## 📍 Access URLs

**Base URL:** http://72.61.162.49:9000

### For Investigators (Login Required)
- **Dashboard:** http://72.61.162.49:9000/threat-intel/dashboard
- **Search:** http://72.61.162.49:9000/threat-intel/search
- **Help Guide:** http://72.61.162.49:9000/threat-intel/help

### For Public (No Login Required)
- **Report a Scam:** http://72.61.162.49:9000/threat-intel/public/report
- **Help Guide:** http://72.61.162.49:9000/threat-intel/help

---

## ⚡ Quick Start (30 Seconds)

### For Investigators

**Option 1: Automatic (Easiest)**
1. Go to **Investigations** → **Phone OSINT**
2. Enter phone number
3. Click "Investigate Phone Number"
4. Scroll down to see threat intelligence results ✅

**Option 2: Manual Search**
1. Click **Threat Intelligence** → **Search Threats** in sidebar
2. Enter phone number: `+260xxxxxxxxx`
3. Check "Search External Sources" ✅
4. Click "Search Threat Intelligence"
5. View results in 2-5 seconds

### For Citizens

**Share this URL with the public:**
```
http://72.61.162.49:9000/threat-intel/public/report
```

Citizens can report:
- Scam phone numbers
- Phishing emails
- Fake websites
- Financial losses

**No login required** | **Anonymous reporting available**

---

## 🎯 What Can You Check?

| Type | Example | Auto-Detected |
|------|---------|---------------|
| **Phone Number** | +260xxxxxxxxx | ✅ Yes |
| **Email** | scammer@example.com | ✅ Yes |
| **Domain** | fake-bank.com | ✅ Yes |
| **IP Address** | 192.168.1.1 | ✅ Yes |
| **URL** | http://phishing.com/page | ✅ Yes |

---

## 📊 Understanding Results

### Threat Score
- **0-20:** ✅ Clean - No threat
- **21-40:** 🔵 Low risk - Monitor
- **41-60:** 🟡 Medium risk - Investigate
- **61-80:** 🟠 High risk - Priority
- **81-100:** 🔴 Critical - Immediate action

### Risk Levels
- 🟢 **Clean:** Not found in any threat database
- 🔵 **Low:** Minor indicators, low confidence
- 🟡 **Medium:** Multiple indicators, moderate confidence
- 🟠 **High:** Strong indicators, high confidence
- 🔴 **Critical:** Confirmed threat, immediate attention required

---

## 🔍 Where Does Data Come From?

### Local Database (Instant)
- Zambian police reports
- Citizen complaints
- Previous investigations
- Verified threats

### Global Sources (2-5 seconds)
1. **AlienVault OTX** - 19 million+ threat indicators
2. **URLhaus** - Malicious URLs and phishing sites
3. **ThreatFox** - Indicators of Compromise (IoC)
4. **AbuseIPDB** - IP abuse reports
5. **Cisco Talos** - Email and domain reputation

**Cost:** 100% FREE ✅

---

## 💡 Real-World Examples

### Example 1: Scam Phone Number
**Scenario:** You receive complaint about +260971234567

**Action:**
1. Search the number in Threat Intelligence
2. System checks 5 global sources + local database

**Result:**
```
⚠️ HIGH RISK (Score: 87/100)
Found in: Local Database + 2 global sources
- 8 previous reports
- K45,000 total losses
- Active scam campaign
- MTN mobile money scam pattern
```

**Benefit:** Immediately link to 8 other cases, fast-track investigation

---

### Example 2: Clean Number
**Scenario:** Checking witness contact number

**Action:**
1. Search +260977777777

**Result:**
```
✅ CLEAN (Score: 0/100)
Not found in any threat database
Safe to proceed with investigation
```

**Benefit:** Confidence that contact is legitimate

---

### Example 3: Phishing Email
**Scenario:** Victim received email from support@zanaco-secure.com

**Action:**
1. Search domain: zanaco-secure.com
2. Check external sources

**Result:**
```
🔴 CRITICAL (Score: 92/100)
Found in: URLhaus, ThreatFox
- Phishing campaign
- Registered 2 days ago
- Fake banking site
- Real Zanaco: zanaco.co.zm (different!)
```

**Benefit:** Immediately identify phishing, warn public, take down site

---

## 🎓 Training Resources

### Read First
1. **Interactive Help Guide** - http://72.61.162.49:9000/threat-intel/help
2. **User Guide** (PDF-ready) - `THREAT_INTELLIGENCE_USER_GUIDE.md`

### Step-by-Step
3. **Setup Guide** - `THREAT_INTELLIGENCE_SETUP.md`
4. **Implementation Details** - `THREAT_INTEL_IMPLEMENTATION_COMPLETE.md`
5. **Status Report** - `THREAT_INTELLIGENCE_STATUS.md`

---

## 🔐 Privacy & Security

✅ Anonymous reporting available
✅ No sensitive data sent to external APIs
✅ All actions audit logged
✅ Admin-only verification system
✅ Optional reporter contact info

---

## 📞 Support

### Need Help?
1. Click **Help & Guide** in sidebar
2. Read the interactive guide
3. Ask your supervisor
4. Contact IT support

### Found an Issue?
1. Note what you were doing
2. Screenshot any errors
3. Report to supervisor
4. Include case number if relevant

---

## 🚀 Optional: Enable External APIs

**Current Status:** ✅ System works without API keys (local database only)

**To enable global threat feeds (5 free sources):**

### Step 1: Get API Keys (5 minutes)
```
AlienVault OTX: https://otx.alienvault.com/
→ Sign up → Get API key (FREE)

AbuseIPDB: https://www.abuseipdb.com/
→ Sign up → Get API key (FREE - 1,000/day)
```

### Step 2: Set Environment Variables
```bash
export ALIENVAULT_OTX_API_KEY="your_otx_key_here"
export ABUSEIPDB_API_KEY="your_abuseipdb_key_here"
```

### Step 3: Restart Application
```bash
pkill -f "python run.py"
source venv/bin/activate
export FLASK_APP=run.py
python run.py
```

### Step 4: Test
Go to Search → Enter "malware.com" → Should see global results ✅

**Note:** Other 3 sources (URLhaus, ThreatFox, Cisco Talos) work without API keys

---

## ✅ Feature Checklist

### For Investigators
- ✅ Dashboard with statistics
- ✅ Search interface (7 indicator types)
- ✅ Automatic integration with Phone OSINT
- ✅ Detailed threat reports
- ✅ Risk scoring (0-100)
- ✅ Source-by-source results
- ✅ Case linking
- ✅ Financial loss tracking

### For Admins
- ✅ Verify threats
- ✅ Mark false positives
- ✅ View all reports
- ✅ Monitor statistics

### For Public
- ✅ Report scams (no login)
- ✅ Anonymous reporting
- ✅ Financial loss tracking
- ✅ Easy-to-use form

### For System
- ✅ 5 global threat feeds
- ✅ Local Zambian database
- ✅ Parallel processing (fast)
- ✅ Comprehensive audit logging
- ✅ Beautiful UI
- ✅ Mobile responsive
- ✅ 100% free to operate

---

## 🎉 You're Ready!

The Threat Intelligence System is fully operational. Start using it today to:

- 🔍 **Identify threats** before they cause harm
- 🔗 **Link cases** automatically
- 🌍 **Access global intelligence** for free
- 👥 **Engage the community** in crime prevention
- ⚡ **Speed up investigations** significantly
- 🛡️ **Protect Zambia** proactively

**Questions?** Read the interactive help guide: http://72.61.162.49:9000/threat-intel/help

---

**Last Updated:** 2025-10-28
**Version:** 1.0.0
**Status:** ✅ Production Ready
