# 🎓 CyberTrace Threat Intelligence - Complete Interactive Guide

## 📚 Table of Contents
1. [What is Threat Intelligence?](#what-is-it)
2. [How Does It Work?](#how-it-works)
3. [Step-by-Step Instructions](#step-by-step)
4. [Real-World Examples](#examples)
5. [Quick Reference](#quick-reference)
6. [Troubleshooting](#troubleshooting)

---

## 🤔 What is Threat Intelligence? {#what-is-it}

### Simple Explanation
Think of Threat Intelligence as a **national criminal database** specifically for digital threats. When you investigate a phone number, email, or website, the system instantly checks if it has been used in scams or fraud - anywhere in the world or right here in Zambia.

### What You Can Do
✅ Check if a phone number is used in scams
✅ Verify if an email address is malicious
✅ Detect phishing websites and domains
✅ Find IP addresses involved in cybercrime
✅ Track patterns across multiple cases

### Two Intelligence Sources

#### 1. **Local Zambian Database** 🇿🇲
Contains threats reported by:
- Zambian citizens via public reporting
- Police investigations
- Other law enforcement agencies

**Advantage:** Specific to Zambian fraud patterns (mobile money scams, MTN/Airtel fraud, etc.)

#### 2. **Global Threat Feeds** 🌍
Five international databases:

| Source | Coverage | What It Checks |
|--------|----------|----------------|
| **AlienVault OTX** | 19M+ threats | All types of threats |
| **URLhaus** | Malicious URLs | Phishing sites, malware URLs |
| **ThreatFox** | IoC Database | Malware campaigns, botnets |
| **AbuseIPDB** | IP Abuse | Spam, hacking attempts |
| **Cisco Talos** | Reputation | Email/domain reputation |

**Advantage:** Global coverage, real-time updates, catches international scams

---

## ⚙️ How Does It Work? {#how-it-works}

### System Flow

```
┌──────────────┐      ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│ Investigator │──────▶│    Search    │──────▶│   Process    │──────▶│   Results    │
│ Enters Query │      │  Databases   │      │  Calculate   │      │   Display    │
└──────────────┘      └──────────────┘      └──────────────┘      └──────────────┘
                             │                      │
                             │                      │
                        ┌────┴────┐            ┌────┴────┐
                        │ Local   │            │ Threat  │
                        │ Global  │            │ Score   │
                        └─────────┘            └─────────┘
```

### Detailed Process

#### **Step 1: You Enter an Indicator**
Example: You search for `+260xxxxxxxxx`
- System validates the format
- Identifies type (phone/email/domain/IP)
- Prepares for checking

#### **Step 2: Local Database Check** ⚡ (Instant)
Searches Zambian database for:
- Previous police reports
- Citizen complaints
- Known scam campaigns
- Related cases

**Speed:** Milliseconds

#### **Step 3: Global Database Check** 🌐 (2-5 seconds)
Simultaneously queries all 5 sources:

1. **AlienVault OTX** → Checks 19 million threat indicators
2. **URLhaus** → Checks malicious URL database
3. **ThreatFox** → Checks IoC (Indicators of Compromise)
4. **AbuseIPDB** → Checks IP abuse reports
5. **Cisco Talos** → Checks email/domain reputation

**Speed:** 2-5 seconds (parallel processing)

#### **Step 4: Calculate Threat Score** 🎯
System aggregates all results and calculates:

**Threat Score (0-100):**
- 0-20: Clean / No threat
- 21-40: Low risk
- 41-60: Medium risk - investigate
- 61-80: High risk - priority
- 81-100: Critical - immediate action

**Risk Level:**
- Clean
- Low
- Medium
- High
- Critical

**Confidence Factors:**
- Number of sources that found it
- Number of reports
- Recent activity
- Financial losses
- Verification status

#### **Step 5: Display Results** 📊
You see:
- Overall threat score and risk level
- Which sources found it
- Detailed findings from each source
- Related cases (if any)
- Financial losses reported
- Recommended actions

---

## 📖 Step-by-Step Instructions {#step-by-step}

### Method 1: Manual Search (Dashboard)

#### **STEP 1: Navigate to Threat Intelligence**
1. Login to CyberTrace
2. Look at the left sidebar
3. Under **"Threat Intelligence"** section, click:
   - **"Threat Dashboard"** → See overview
   - **"Search Threats"** → Go directly to search

#### **STEP 2: Access Search Interface**
1. On the dashboard, click **"Search Threats"** button (top right)
2. Or directly go to: `/threat-intel/search`

#### **STEP 3: Enter What You Want to Check**

**Phone Number:**
```
+260xxxxxxxxx
```
or
```
0972959023
```
or
```
260xxxxxxxxx
```

**Email Address:**
```
scammer@example.com
```

**Domain:**
```
fake-bank.com
```

**IP Address:**
```
192.168.1.1
```

**URL:**
```
http://phishing-site.com/login
```

#### **STEP 4: Choose Options**

**Indicator Type:**
- Select "Auto-detect" (recommended) - system figures it out
- Or manually select: Phone Number, Email, Domain, IP, URL

**Search External Sources:**
- ✅ **Check this box** to query global databases (recommended)
- Uncheck if you only want to search local Zambian database

#### **STEP 5: Click "Search Threat Intelligence"**
Wait 2-5 seconds for results

#### **STEP 6: Interpret Results**

##### **Local Results Section** (Zambian Database)
Shows if indicator found in local database:

**If Found:**
```
⚠️ Found 1 local threat(s)

Indicator: +260xxxxxxxxx
Type: scam
Severity: HIGH
Confidence: 85%
Reports: 12
Status: Verified
```

Click **"View Details"** to see full report

**If Not Found:**
```
✓ No threats found in Zambian database
```

##### **Global Results Section** (International Databases)

**Risk Level Card:**
```
┌─────────────────┐
│ Risk Level      │
│   HIGH          │
└─────────────────┘
```

**Threat Score Card:**
```
┌─────────────────┐
│ Threat Score    │
│   87/100        │
└─────────────────┘
```

**Sources Checked:**
```
┌─────────────────┐
│ Sources Checked │
│       5         │
└─────────────────┘
```

**Found In:**
```
┌─────────────────┐
│    Found In     │
│       3         │
└─────────────────┘
```

**Detailed Findings:**
Click to expand each source that found it:

```
▼ AlienVault OTX - Threat Detected - Score: 90
  Source: AlienVault OTX
  Found: Yes
  Pulse Count: 3
  Tags: mobile_money_scam, fraud, zambia

▼ ThreatFox - Threat Detected - Score: 85
  Source: ThreatFox
  Threat Type: Fraud
  Confidence: 100%
  Malware: N/A
```

---

### Method 2: Automatic (During Investigation) ✨

This is the **easiest method** - threat intelligence is automatically included!

#### **STEP 1: Run Normal Phone OSINT**
1. Go to: **Investigations** → **Phone OSINT**
2. Enter phone number: `+260xxxxxxxxx`
3. Select case
4. Click **"Investigate Phone Number"**

#### **STEP 2: Wait for Investigation to Complete**
(30-60 seconds)

#### **STEP 3: Scroll Down to See Threat Intelligence**
In the results page, scroll down to find:

```
═══════════════════════════════════════════════
🛡️ THREAT INTELLIGENCE
═══════════════════════════════════════════════

Risk Level: HIGH
Threat Score: 87/100
Status: ⚠️ MALICIOUS

Found in 3 sources:
✓ AlienVault OTX - Pulse: "Mobile Money Scam Campaign"
✓ ThreatFox - Confidence: 100%
✓ Zambian Database - 12 reports, K45,000 losses

⚠️ WARNING: This number is flagged in active scam campaigns!
═══════════════════════════════════════════════
```

**That's it!** No extra steps needed.

---

### Method 3: Public Reporting (For Citizens) 👥

Anyone can report threats - **no login required!**

#### **URL for Citizens:**
```
http://your-server:9000/threat-intel/public/report
```

#### **What Citizens Can Report:**
- Scam phone numbers
- Phishing emails
- Fake websites
- Suspicious URLs
- Financial losses

#### **How to Use Public Form:**

**STEP 1: Go to Public Reporting URL**

**STEP 2: Fill Out Form**

**Type of Threat:**
- Phone Number (Scam Call/SMS)
- Email Address (Phishing)
- Website/Domain (Fake Site)
- Suspicious URL/Link

**Scam Category:**
- Scam/Fraud
- Phishing
- Financial Fraud
- Identity Theft
- Spam
- Other

**Enter the Indicator:**
```
+260971234567
```

**Describe What Happened:**
```
This number called claiming to be from MTN
and asked for my mobile money PIN. They said
I won K5,000 and needed to verify my account.
```

**Financial Loss (optional):**
```
K5,000
```

**Your Information (optional):**
- Name: John Banda (or leave blank for anonymous)
- Contact: 0977777777 (in case police need more info)

**STEP 3: Click "Submit Report"**

**STEP 4: Success!**
```
✓ Report Submitted Successfully!
Thank you for helping protect Zambia from scammers
```

---

## 🎯 Real-World Examples {#examples}

### Example 1: Mobile Money Scam Detection

**Scenario:**
Officer receives complaint about +260971234567 claiming to be from MTN requesting mobile money PIN.

**Action:**
1. Officer runs Phone OSINT on +260971234567
2. System automatically checks threat intelligence

**Result:**
```
⚠️ CRITICAL THREAT DETECTED!

Threat Score: 92/100 (Critical)
Risk Level: CRITICAL
Found in: Local Zambian Database

Details:
- Previous Reports: 8 reports
- Financial Loss: K45,000 total
- Pattern: MTN mobile money scam
- First Seen: 15 days ago
- Last Seen: Today
- Affected Victims: 8 people
- Status: Active scam campaign

Related Cases:
- ZPS-2025-0089 (K5,000)
- ZPS-2025-0091 (K8,000)
- ZPS-2025-0095 (K3,500)
...
```

**Officer Action:**
- Immediately recognizes this is part of active scam campaign
- Links current case to 8 previous cases
- Fast-tracks arrest warrant
- Issues public warning on social media
- Coordinates with MTN to block number

**Outcome:**
- Scammer arrested within 24 hours
- 8 cases solved simultaneously
- K45,000 in losses prevented

---

### Example 2: Phishing Email Investigation

**Scenario:**
Victim received email from `support@zanaco-secure.com` asking for account details.

**Action:**
1. Officer searches domain `zanaco-secure.com` in threat intelligence
2. Checks "Search External Sources"

**Result:**
```
⚠️ SUSPICIOUS DOMAIN DETECTED!

Threat Score: 88/100 (High)
Risk Level: HIGH
Found in: URLhaus, ThreatFox

AlienVault OTX:
- Pulse: "Banking Phishing Campaign 2025"
- Category: Phishing
- Tags: zambia, zanaco, banking

URLhaus:
- Status: Online
- Threat: Phishing
- Date Added: 2 days ago
- Reporter: abuse.ch community

Domain Information:
- Registered: 2 days ago
- Registrar: Cheap domains
- Location: Panama
- Real Zanaco: zanaco.co.zm (DIFFERENT!)

WARNING: Fake banking site designed to steal credentials!
```

**Officer Action:**
- Confirms phishing attack
- Contacts hosting provider to take down site
- Issues public warning via social media
- Searches for other victims
- Identifies 12 victims who entered credentials
- Works with Zanaco to secure accounts

**Outcome:**
- Site taken down within 2 hours
- 12 victims' accounts secured
- Public warned about fake domain
- Investigation leads to arrest of scammer

---

### Example 3: Clean Number (No Threat)

**Scenario:**
Officer investigates +260977777777 mentioned in case notes as potential witness contact.

**Action:**
Officer searches the number in threat intelligence.

**Result:**
```
✓ CLEAN - NO THREAT DETECTED

Threat Score: 0/100
Risk Level: Clean
Local Reports: None
Global Sources: Not found in any threat database

This indicator appears clean with no history of
malicious activity.
```

**Officer Action:**
- Proceeds with normal investigation
- Contacts witness without concerns
- Number saved as clean reference

---

## 📋 Quick Reference Guide {#quick-reference}

### Threat Score Interpretation

| Score | Risk Level | Badge Color | Meaning | Action Required |
|-------|-----------|-------------|---------|-----------------|
| 0-20 | Clean | 🟢 Green | No threat detected | Normal investigation |
| 21-40 | Low | 🔵 Blue | Minor risk | Monitor situation |
| 41-60 | Medium | 🟡 Yellow | Moderate risk | Investigate carefully |
| 61-80 | High | 🟠 Orange | High risk | Priority investigation |
| 81-100 | Critical | 🔴 Red | Critical threat | Immediate action |

### Access Points

| Feature | URL | Login Required? |
|---------|-----|-----------------|
| Dashboard | `/threat-intel/dashboard` | Yes |
| Search | `/threat-intel/search` | Yes |
| Help Guide | `/threat-intel/help` | No |
| Public Report | `/threat-intel/public/report` | No |
| View Report | `/threat-intel/report/<id>` | Yes |

### What Can Be Checked?

| Type | Example | Format |
|------|---------|--------|
| Phone | +260xxxxxxxxx | International format preferred |
| Email | scammer@example.com | Standard email format |
| Domain | fake-bank.com | Without http:// |
| IP Address | 192.168.1.1 | IPv4 or IPv6 |
| URL | http://phishing.com/page | Full URL |

### Sidebar Navigation

```
Threat Intelligence
├── Threat Dashboard    → Overview & statistics
├── Search Threats      → Manual search interface
└── Help & Guide        → This guide (opens new tab)
```

---

## 🔧 Troubleshooting {#troubleshooting}

### Common Issues

#### Issue 1: "No results found"
**This is normal!** It means the indicator is NOT in any threat database - which is good news!

**Action:** Proceed with normal investigation.

#### Issue 2: "API key not configured"
**Meaning:** External threat feeds not set up yet.

**Solution:**
- Local Zambian database still works
- Ask admin to configure API keys (see setup guide)
- Only affects global threat feeds

#### Issue 3: Search takes long time
**Meaning:** Checking 5 global databases takes 2-5 seconds.

**Solution:**
- This is normal
- Uncheck "Search External Sources" for instant results (local only)

#### Issue 4: Can't access dashboard
**Check:**
- Are you logged in?
- Do you have investigator role or higher?
- Is threat intelligence enabled?

#### Issue 5: Public reporting form not working
**Check:**
- Form doesn't require login
- All required fields filled?
- Valid phone/email format?
- Try different browser

---

## 🎓 Training Checklist

Use this checklist to train new investigators:

### Basic Skills
- [ ] Can navigate to Threat Intelligence dashboard
- [ ] Can access search interface
- [ ] Can enter phone number correctly
- [ ] Can enter email address correctly
- [ ] Can interpret threat scores (0-100)
- [ ] Understands risk levels (Clean/Low/Medium/High/Critical)

### Intermediate Skills
- [ ] Can distinguish local vs global results
- [ ] Can expand detailed findings
- [ ] Knows when to use external sources
- [ ] Can link threats to cases
- [ ] Can share public reporting URL with citizens

### Advanced Skills
- [ ] Can verify threats (admin only)
- [ ] Can mark false positives (admin only)
- [ ] Can analyze patterns across multiple threats
- [ ] Can train others on the system

---

## 📞 Support

### Need Help?
1. **Read this guide** → Most answers are here
2. **Check the interactive help** → `/threat-intel/help`
3. **Ask your supervisor** → They can guide you
4. **Contact IT support** → For technical issues

### Reporting Issues
If you find a bug or have suggestions:
1. Note what you were doing
2. Screenshot any errors
3. Report to your supervisor
4. Include case number if relevant

---

## 🎉 Congratulations!

You now know how to use the Threat Intelligence system!

**Remember:**
- It automatically checks during Phone OSINT investigations
- Anyone can report threats via public form
- Threat scores help prioritize cases
- Global + Local = Comprehensive coverage

**Start protecting Zambia today!** 🇿🇲

---

**Last Updated:** 2025-10-28
**Version:** 1.0.0
**Status:** ✅ Production Ready
