# 📊 Threat Intelligence Dashboard - Quick Reference

**URL:** http://72.61.162.49:9000/threat-intel/dashboard

---

## 🎯 What You'll See

### 4 Statistics Cards
```
┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
│  Total   │ │ Verified │ │ Critical │ │   High   │
│ Threats  │ │ Threats  │ │ Severity │ │ Severity │
│    10    │ │    7     │ │    3     │ │    3     │
└──────────┘ └──────────┘ └──────────┘ └──────────┘
```

### Recent Threats Table
- Last 10 threats from past 30 days
- Shows: Indicator, Type, Severity, Confidence
- Click "View" to see full details

### Critical Threats Section
- Shows only CRITICAL active threats
- 3 threats requiring immediate action
- Includes: SIM swap, Ransomware, Banking phishing

---

## 🔴 Critical Threats (Action Required NOW!)

### 1. SIM Swap Fraud - +260978888888
```
Status: ⚡ ACTIVE (15 minutes ago)
Victims: 7 people
Loss: K185,000
Risk: 92/100
```
**What's happening:** Criminals are swapping SIM cards to steal mobile money
**Why critical:** Active RIGHT NOW, more victims expected tonight

### 2. Ransomware - secure-payment-zm.com
```
Status: ⚡ ACTIVE (30 minutes ago)
Victims: 15 reports, 4 businesses
Loss: K250,000
Risk: 98/100
```
**What's happening:** Email with malicious PDF encrypts all files
**Why critical:** Businesses can't operate, files held for ransom

### 3. Banking Phishing - zanaco-secure.com
```
Status: ⚡ ACTIVE (2 hours ago)
Victims: 12 people
Loss: K120,000
Risk: 95/100
```
**What's happening:** Fake Zanaco website stealing banking credentials
**Why critical:** High losses, sophisticated attack, looks legitimate

---

## 📈 All 10 Threats Summary

| Indicator | Type | Severity | Loss | Status |
|-----------|------|----------|------|--------|
| +260978888888 | SIM swap | 🔴 CRITICAL | K185K | Active |
| secure-payment-zm.com | Ransomware | 🔴 CRITICAL | K250K | Active |
| zanaco-secure.com | Phishing | 🔴 CRITICAL | K120K | Active |
| +260971234567 | MTN scam | 🟠 HIGH | K45K | Active |
| +260965432109 | WhatsApp | 🟠 HIGH | K67K | Active |
| free-airtel-data.com | Fake promo | 🟠 HIGH | K15K | Active |
| 41.222.45.10 | IP attack | 🟡 MEDIUM | K0 | Investigating |
| zambia-mining-jobs.com | Job scam | 🟡 MEDIUM | K8K | Investigating |
| +260977777777 | Telemarketing | 🔵 LOW | K0 | Resolved |
| +260955555555 | False positive | 🔵 LOW | K0 | Resolved |

**Total Financial Impact: K690,000**

---

## 🚨 SIM Swap Attack Explained (Critical #1)

### What is SIM Swap?
Criminals transfer your phone number to a SIM card they control.

### How It Works:
1. Scammer collects your personal info
2. Goes to MTN/Airtel shop
3. Pretends to be you
4. Gets new SIM with your number
5. Your phone stops working
6. Scammer receives all your SMS codes
7. Resets mobile money PIN
8. Steals all your money

### Current Attack Timeline:
```
Day 1 (Oct 26):
- 09:00 - Victim 1 loses K40,000
- 14:00 - Victim 2 loses K30,000

Day 2 (Oct 27):
- 10:30 - Victim 3 loses K22,000
- 15:00 - Victim 4 loses K28,000
- 19:00 - Victim 5 loses K20,000

Today (Oct 28):
- 17:45 - Victim 6 under attack
- 17:50 - Victim 7 under attack
- 18:00 - MORE EXPECTED TONIGHT!
```

### Why So Dangerous:
- ⚡ Happening RIGHT NOW
- 💰 K185,000 stolen in 48 hours
- 🎯 Pattern: Morning & evening attacks
- 👥 7 victims (and counting)
- 🕵️ Insider at telecom suspected
- 📍 All in Lusaka, MTN network

### What Police Are Doing:
```
✅ MTN notified and investigating
✅ Airtel alerted
✅ Banks monitoring suspect transfers
✅ Pattern identified
✅ Attempting to block +260978888888
✅ Looking for telecom employee
```

### What Citizens Should Do:
```
If your phone suddenly loses signal:
1. DON'T assume network issue
2. Call telecom IMMEDIATELY
3. Ask if SIM was swapped
4. Change all passwords NOW
5. Call bank to freeze accounts
6. Report to police
```

---

## 📊 Data Sources

### Local Zambian Database
**Contains:**
- Police investigations (7 threats)
- Public reports (3 threats)
- Verified by officers
- Case numbers included
- Financial losses tracked

**What you see:**
```
Source: case_investigation
Case: ZPS-2025-0099
Officer: Cyber Crimes Unit
Badge: ZP-CYBER-02
```

### External APIs (Not shown in test data)
- AlienVault OTX (global threats)
- URLhaus (malicious URLs)
- ThreatFox (malware IoCs)
- AbuseIPDB (IP abuse)
- Cisco Talos (reputation)

---

## 🎯 Quick Actions

### From Dashboard You Can:
1. **View Full Reports** - Click "View Details"
2. **Search Threats** - Click "Search Threats" button
3. **See Statistics** - At-a-glance numbers
4. **Identify Patterns** - Recent activity trends
5. **Prioritize Work** - Critical section shows urgent cases

### Next Steps:
- Review critical threats first
- Assign officers to active cases
- Update threat status as investigations progress
- Link threats to cases
- Mark resolved when closed

---

## 📱 How to Access

```
1. Go to: http://72.61.162.49:9000
2. Click "Threat Intelligence"
3. Click "Threat Dashboard"
   OR
   Direct: http://72.61.162.49:9000/threat-intel/dashboard
4. Login required (investigators only)
```

---

## 🔍 Related Features

- **Search:** `/threat-intel/search` - Search local & global
- **Public Report:** `/threat-intel/public/report` - Citizen reports (no login)
- **Help Guide:** `/threat-intel/help` - Full documentation

---

## 📈 Current Statistics

```
Total Threats:         10
Critical (urgent):     3
High (priority):       3
Medium (investigating): 2
Low (resolved):        2

Verified by Police:    7 threats (70%)
Unverified Reports:    3 threats (30%)

Total Financial Loss:  K690,000
Average per Threat:    K69,000

Most Dangerous:        Ransomware (K250K loss)
Most Active:           SIM Swap (15 min ago)
Longest Running:       False Positive (45 days)
```

---

## ⚠️ Important Notes

1. **Dashboard updates in real-time** - Refresh to see latest
2. **Login required** - Investigators and admins only
3. **Data is REAL** - These are actual test scenarios
4. **Take action** - Critical threats need immediate response
5. **Public can report** - Via `/threat-intel/public/report`

---

**For Full Details:** See `THREAT_INTEL_DASHBOARD_EXPLAINED.md`

**Last Updated:** 2025-10-28
