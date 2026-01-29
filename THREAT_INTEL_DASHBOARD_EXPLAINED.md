# 🎯 Threat Intelligence Dashboard - Complete Explanation

**URL:** http://72.61.162.49:9000/threat-intel/dashboard

**Access:** Login required (Investigators and Admins only)

---

## 📋 Table of Contents
1. [Dashboard Overview](#overview)
2. [Statistics Cards](#statistics)
3. [Recent Threats](#recent)
4. [Critical Threats](#critical)
5. [Search Integration](#search)
6. [Real Examples Explained](#examples)
7. [SIM Swap Fraud Deep Dive](#simswap)

---

## 🏠 Dashboard Overview {#overview}

### What You See When You Login

```
╔══════════════════════════════════════════════════════════════╗
║        🛡️ THREAT INTELLIGENCE DASHBOARD                      ║
║        Overview of active threats and investigations         ║
╚══════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────┐
│                    STATISTICS CARDS                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │  Total   │ │ Verified │ │ Critical │ │   High   │      │
│  │ Threats  │ │ Threats  │ │ Severity │ │ Severity │      │
│  │    10    │ │    7     │ │    3     │ │    3     │      │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘      │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│              📊 RECENT THREATS (Last 30 Days)                │
│  Table showing latest reported threats                       │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│              ⚠️ CRITICAL THREATS (Immediate Action)          │
│  High priority threats requiring urgent attention            │
└─────────────────────────────────────────────────────────────┘

                    [🔍 Search Threats]
```

---

## 📊 Statistics Cards {#statistics}

### Card 1: Total Threats
```
┌─────────────────────┐
│   TOTAL THREATS     │
│         10          │
│                     │
│  🇿🇲 In Database    │
└─────────────────────┘
```

**What it shows:** Total number of threat intelligence records in the Zambian database

**Current Value:** 10 threats

**Includes:**
- Phone numbers (scam calls, SIM swaps)
- Email addresses (phishing)
- Domains (fake websites)
- IP addresses (cyber attacks)
- URLs (malicious links)

**Data Source:** Local SQLite database table `threat_intel`

**SQL Query:**
```sql
SELECT COUNT(*) FROM threat_intel;
```

**Why it matters:** Gives you instant view of total known threats in Zambia

---

### Card 2: Verified Threats
```
┌─────────────────────┐
│  VERIFIED THREATS   │
│         7           │
│                     │
│  ✅ Confirmed       │
└─────────────────────┘
```

**What it shows:** Threats confirmed by police investigators

**Current Value:** 7 verified threats

**Verification means:**
- Investigated by officer
- Evidence collected
- Case number assigned
- Badge number recorded
- Confidence score increased

**Verified Examples:**
1. ✅ +260978888888 - SIM swap fraud (Cyber Crimes Unit)
2. ✅ +260971234567 - MTN scam (Officer Mwamba)
3. ✅ zanaco-secure.com - Banking phishing (Detective Banda)
4. ✅ secure-payment-zm.com - Ransomware (Cyber Crimes Unit)
5. ✅ +260965432109 - WhatsApp scam (Detective Zulu)
6. ✅ free-airtel-data.com - Fake promo (Officer Phiri)
7. ✅ (1 more verified threat)

**Unverified (3 threats):**
- 41.222.45.10 - Still investigating
- zambia-mining-jobs.com - Needs verification
- +260955555555 - False positive (intentional)

**SQL Query:**
```sql
SELECT COUNT(*) FROM threat_intel WHERE verified = TRUE;
```

**Why it matters:** Shows how many threats have police confirmation vs. unverified public reports

---

### Card 3: Critical Severity
```
┌─────────────────────┐
│ CRITICAL SEVERITY   │
│         3           │
│                     │
│  🔴 Urgent          │
└─────────────────────┘
```

**What it shows:** Threats marked as CRITICAL priority

**Current Value:** 3 critical threats

**Critical Threats:**

1. **+260978888888** - SIM Swap Fraud
   - Risk Score: 92/100
   - Financial Loss: K185,000
   - Victims: 7 people
   - Last seen: 15 minutes ago
   - **Why Critical:** Active right now, multiple victims, high losses

2. **zanaco-secure.com** - Banking Phishing
   - Risk Score: 95/100
   - Financial Loss: K120,000
   - Reports: 12
   - Last seen: 2 hours ago
   - **Why Critical:** Targets bank accounts, sophisticated attack

3. **secure-payment-zm.com** - Ransomware
   - Risk Score: 98/100
   - Financial Loss: K250,000
   - Businesses affected: 4
   - Last seen: 30 minutes ago
   - **Why Critical:** Encrypts files, demands ransom, business impact

**Severity Levels Explained:**

| Score | Level | Color | When Assigned |
|-------|-------|-------|---------------|
| 81-100 | CRITICAL | 🔴 Red | Immediate threat, active attacks, high losses |
| 61-80 | HIGH | 🟠 Orange | Serious threat, multiple reports, verified |
| 41-60 | MEDIUM | 🟡 Yellow | Investigating, moderate risk |
| 21-40 | LOW | 🔵 Blue | Minor threat, low impact |
| 0-20 | MINIMAL | 🟢 Green | Not malicious or resolved |

**SQL Query:**
```sql
SELECT COUNT(*) FROM threat_intel WHERE severity = 'critical';
```

**Why it matters:** These need immediate attention and action

---

### Card 4: High Severity
```
┌─────────────────────┐
│   HIGH SEVERITY     │
│         3           │
│                     │
│  🟠 Priority        │
└─────────────────────┘
```

**What it shows:** Threats marked as HIGH priority

**Current Value:** 3 high-severity threats

**High Severity Threats:**

1. **+260971234567** - MTN Mobile Money Scam
   - Risk Score: 85/100
   - Financial Loss: K45,000
   - Reports: 8
   - Active for: 15 days

2. **+260965432109** - WhatsApp Account Takeover
   - Risk Score: 90/100
   - Financial Loss: K67,000
   - Accounts compromised: 11
   - Active for: 8 days

3. **free-airtel-data.com** - Fake Airtel Promotion
   - Risk Score: 80/100
   - Financial Loss: K15,000
   - Reports: 6
   - Region: Copperbelt

**Why HIGH (not CRITICAL):**
- Still active but less urgent
- Lower financial losses
- Fewer victims
- Not seen in last few hours

**SQL Query:**
```sql
SELECT COUNT(*) FROM threat_intel WHERE severity = 'high';
```

**Why it matters:** Priority cases after critical threats are addressed

---

## 📋 Recent Threats (Last 30 Days) {#recent}

### What This Section Shows

```
╔════════════════════════════════════════════════════════════╗
║           📊 RECENT THREATS (LAST 30 DAYS)                 ║
╚════════════════════════════════════════════════════════════╝

┌────────────┬─────────┬──────────┬───────────┬─────────────┐
│ Indicator  │  Type   │ Severity │ Confidence│   Actions   │
├────────────┼─────────┼──────────┼───────────┼─────────────┤
│ +2609788.. │  fraud  │🔴CRITICAL│    92%    │ [View] [⚠] │
│ secure-p.. │ malware │🔴CRITICAL│    98%    │ [View] [⚠] │
│ zanaco-s.. │phishing │🔴CRITICAL│    95%    │ [View] [⚠] │
│ +2609654.. │identity │🟠 HIGH   │    90%    │ [View] [⚠] │
│ +2609712.. │  scam   │🟠 HIGH   │    85%    │ [View] [⚠] │
│ free-air.. │phishing │🟠 HIGH   │    80%    │ [View] [⚠] │
│ zambia-m.. │  scam   │🟡MEDIUM  │    55%    │ [View] [🔍]│
│ 41.222... │  fraud  │🟡MEDIUM  │    60%    │ [View] [🔍]│
│ +2609777.. │  spam   │🔵 LOW    │    20%    │ [View]     │
│ +2609555.. │  spam   │🔵 LOW    │    15%    │ [View]     │
└────────────┴─────────┴──────────┴───────────┴─────────────┘

Showing 10 threats from last 30 days
```

### Column Explanations

#### 1. Indicator Column
**Shows:** The actual threat indicator (truncated for display)

**Examples:**
- `+2609788...` → Full: +260978888888 (phone)
- `zanaco-s...` → Full: zanaco-secure.com (domain)
- `secure-p...` → Full: secure-payment-zm.com (domain)
- `41.222...` → Full: 41.222.45.10 (IP address)

**Data Field:** First 8-10 characters of primary indicator

#### 2. Type Column
**Shows:** Threat classification

**Possible Values:**
- `scam` - Fraudulent schemes
- `fraud` - Financial fraud
- `phishing` - Credential theft
- `malware` - Malicious software
- `spam` - Unwanted messages
- `identity_theft` - Impersonation
- `other` - Miscellaneous

**Current Distribution:**
- scam: 3 threats
- fraud: 2 threats
- phishing: 2 threats
- malware: 1 threat
- spam: 2 threats
- identity_theft: 1 threat

#### 3. Severity Column
**Shows:** Risk level with color coding

**Visual Indicators:**
- 🔴 CRITICAL (Red badge)
- 🟠 HIGH (Orange badge)
- 🟡 MEDIUM (Yellow badge)
- 🔵 LOW (Blue badge)
- 🟢 MINIMAL (Green badge)

#### 4. Confidence Column
**Shows:** How confident we are this is a real threat (0-100%)

**Confidence Calculation:**
```python
def calculate_confidence(threat):
    base_score = 50  # Start at 50%

    # Add points for verification
    if threat.verified:
        base_score += 30

    # Add points for multiple reports
    if threat.report_count >= 10:
        base_score += 20
    elif threat.report_count >= 5:
        base_score += 10
    elif threat.report_count >= 2:
        base_score += 5

    # Add points for financial loss
    if threat.financial_loss > 100000:
        base_score += 15
    elif threat.financial_loss > 50000:
        base_score += 10
    elif threat.financial_loss > 10000:
        base_score += 5

    # Cap at 100%
    return min(base_score, 100)
```

**Examples:**
- 98% = Verified + 15 reports + K250K loss → Highly confident
- 55% = Unverified + 4 reports + K8K loss → Moderate confidence
- 20% = Resolved + 2 reports + No loss → Low confidence

#### 5. Actions Column
**Shows:** Available actions for this threat

**Action Buttons:**

**[View]** - View full detailed report
- Click to see complete threat information
- Shows all indicator details
- Displays source information
- Shows investigation timeline
- Lists all reports

**[⚠]** - Alert icon for critical/high threats
- Red/orange warning indicator
- Means: Requires immediate attention
- Shows on critical and high severity only

**[🔍]** - Investigation icon for medium threats
- Yellow info indicator
- Means: Under investigation
- Shows on medium severity

### SQL Query Used
```sql
SELECT * FROM threat_intel
WHERE created_at >= (NOW() - INTERVAL 30 DAY)
ORDER BY created_at DESC
LIMIT 10;
```

### Why This Section Matters
- **Quick Overview:** See latest threats at a glance
- **Trend Detection:** Identify new attack patterns
- **Priority Action:** Know what to investigate first
- **Resource Allocation:** Assign officers to critical cases

---

## ⚠️ Critical Threats Section {#critical}

### What This Section Shows

```
╔════════════════════════════════════════════════════════════╗
║        ⚠️ CRITICAL THREATS (IMMEDIATE ACTION REQUIRED)     ║
╚════════════════════════════════════════════════════════════╝

┌──────────────────────────────────────────────────────────┐
│ 🔴 CRITICAL: SIM Swap Fraud                              │
├──────────────────────────────────────────────────────────┤
│ Indicator: +260978888888                                 │
│ Type: fraud                                              │
│ Confidence: 92%                                          │
│ Reports: 7 victims                                       │
│ Financial Loss: K185,000                                 │
│ Status: ✅ Verified by Cyber Crimes Unit                 │
│ Last Seen: 15 minutes ago                                │
│                                                          │
│ ⚡ ACTIVE THREAT - Multiple victims in last 48 hours    │
│                                                          │
│ [View Full Report] [Mark Resolved] [Add to Case]        │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│ 🔴 CRITICAL: Ransomware Email Campaign                   │
├──────────────────────────────────────────────────────────┤
│ Indicator: secure-payment-zm.com                         │
│ Type: malware                                            │
│ Confidence: 98%                                          │
│ Reports: 15 reports                                      │
│ Financial Loss: K250,000                                 │
│ Status: ✅ Verified by Cyber Crimes Unit                 │
│ Last Seen: 30 minutes ago                                │
│                                                          │
│ ⚡ URGENT - Ransomware encrypts files on open            │
│                                                          │
│ [View Full Report] [Mark Resolved] [Add to Case]        │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│ 🔴 CRITICAL: Zanaco Banking Phishing                     │
├──────────────────────────────────────────────────────────┤
│ Indicator: zanaco-secure.com                             │
│ Type: phishing                                           │
│ Confidence: 95%                                          │
│ Reports: 12 reports                                      │
│ Financial Loss: K120,000                                 │
│ Status: ✅ Verified by Detective Banda                   │
│ Last Seen: 2 hours ago                                   │
│                                                          │
│ ⚡ ACTIVE - Fake banking site stealing credentials       │
│                                                          │
│ [View Full Report] [Mark Resolved] [Add to Case]        │
└──────────────────────────────────────────────────────────┘

Total Critical Threats: 3
```

### Why Only Critical Threats Shown Here?

This section is **action-focused** - it shows only threats that need **immediate response**.

**Filtering Criteria:**
```python
# Only show threats that are:
1. severity = 'critical' AND
2. status = 'active' AND
3. verified = True
```

**Why these filters:**
- **Critical severity:** Highest risk level
- **Active status:** Currently ongoing (not resolved)
- **Verified:** Confirmed by investigators (not false alarms)

### Each Card Shows:

#### 1. Header
- 🔴 Icon + Severity badge
- Threat name/description

#### 2. Indicator Details
- **Indicator:** Actual phone/email/domain/IP
- **Type:** Threat classification
- **Confidence:** How sure we are (%)
- **Reports:** Number of victims/reports
- **Financial Loss:** Total money lost (in Kwacha)
- **Status:** Verification status with officer name
- **Last Seen:** When threat was last active

#### 3. Alert Message
- ⚡ ACTIVE/URGENT indicator
- Brief explanation of immediate danger

#### 4. Action Buttons
- **View Full Report:** See complete details
- **Mark Resolved:** Close the case
- **Add to Case:** Link to investigation

### SQL Query Used
```sql
SELECT * FROM threat_intel
WHERE severity = 'critical'
AND status = 'active'
AND verified = TRUE
ORDER BY last_seen DESC;
```

### Why This Section Matters
- **Urgent Action:** These can't wait
- **Resource Priority:** Assign best officers
- **Public Safety:** Prevent more victims
- **Financial Impact:** Stop ongoing losses

---

## 🔍 Search Integration {#search}

### Quick Search Button

At the bottom of dashboard, there's a prominent button:

```
┌────────────────────────────────┐
│   🔍 SEARCH THREAT INTELLIGENCE │
└────────────────────────────────┘
```

**What it does:**
- Redirects to: `/threat-intel/search`
- Opens search interface
- Allows searching local + external sources

**When to use:**
- Looking for specific phone number
- Checking if email is in database
- Investigating new complaint
- Verifying threat status

---

## 📊 Real Examples Explained {#examples}

Let me explain each threat in the dashboard:

### Example 1: Low Risk - Telemarketing
```
Indicator: +260977777777
Type: spam
Severity: LOW (20%)
Reports: 2
Loss: K0
Status: Resolved
```

**What happened:**
- 2 people complained about telemarketing calls
- Investigation revealed legitimate business
- Not malicious, just annoying
- Marked as resolved

**Why LOW severity:**
- No financial loss
- Not a scam
- Legitimate business activity
- Resolved status

**Data Source:** Public reports via /threat-intel/public/report

---

### Example 2: Medium Risk - Job Scam
```
Indicator: zambia-mining-jobs.com
Type: scam
Severity: MEDIUM (55%)
Reports: 4
Loss: K8,000
Status: Investigating
```

**What happened:**
- Website offers mining jobs
- Requires upfront "processing fee" of K500
- 4 people paid and got nothing
- Domain registered recently

**Why MEDIUM severity:**
- Moderate financial losses
- Not verified yet (investigating)
- Could be legitimate recruitment
- Needs more investigation

**Next steps:**
- Contact domain registrar
- Interview victims
- Verify with mining companies
- Determine if scam or legitimate

**Data Source:** Public reports (unverified)

---

### Example 3: High Risk - MTN Scam
```
Indicator: +260971234567
Type: scam
Severity: HIGH (85%)
Reports: 8
Loss: K45,000
Status: Active, Verified
```

**What happened:**
- Scammer calls claiming to be MTN staff
- Says account needs verification
- Asks for mobile money PIN
- 8 victims lost money

**How the scam works:**
1. Scammer calls victim
2. "Hello, this is MTN customer service"
3. "Your account will be suspended"
4. "We need to verify your mobile money PIN"
5. Victim gives PIN
6. Scammer drains mobile money account

**Why HIGH severity:**
- Multiple victims (8 people)
- Significant losses (K45,000 total)
- Verified by Officer Mwamba
- Active for 15 days
- Social engineering attack

**Case Details:**
- Case Number: ZPS-2025-0089
- Investigating Officer: Officer Mwamba
- Badge Number: ZP-5678
- Region: Lusaka

**Data Source:** Police investigation

---

### Example 4: High Risk - WhatsApp Takeover
```
Indicator: +260965432109
Type: identity_theft
Severity: HIGH (90%)
Reports: 11
Loss: K67,000
Status: Active, Verified
```

**What happened:**
- Scammer hacks WhatsApp accounts
- Messages victim's contacts
- Claims emergency situation
- Requests money urgently
- 11 accounts compromised

**How the attack works:**
1. Scammer gets victim's phone number
2. Requests WhatsApp verification code
3. Uses social engineering to get code
4. Takes over victim's WhatsApp
5. Messages all contacts: "Emergency! Send money!"
6. Contacts send money thinking it's their friend
7. Scammer disappears

**Why HIGH severity:**
- Multiple victims (11 accounts)
- High losses (K67,000)
- Identity theft component
- Targets trust relationships
- Hard to detect

**Case Details:**
- Case Number: ZPS-2025-0096
- Investigating Officer: Detective Zulu
- Badge Number: ZP-3456
- WhatsApp notified: Yes

**Data Source:** Police investigation

---

### Example 5: High Risk - Fake Airtel Promo
```
Indicator: free-airtel-data.com
Type: phishing
Severity: HIGH (80%)
Reports: 6
Loss: K15,000
Status: Active, Verified
```

**What happened:**
- Fake website claims "Free 50GB Airtel data"
- Asks for personal information
- Collects ID numbers, bank details
- No data actually given
- 6 victims in Copperbelt region

**How the scam works:**
1. Victim sees social media post
2. "Airtel giving FREE 50GB to all customers!"
3. Link to free-airtel-data.com
4. Form asks for:
   - Full name
   - ID number
   - Phone number
   - Bank account details
5. Submit form
6. "Data will be added in 24 hours"
7. Never receive data
8. Identity stolen

**Why HIGH severity:**
- Identity theft risk
- Regional targeting (Copperbelt)
- Verified by Officer Phiri
- Airtel confirmed it's fake
- Multiple data points stolen

**Case Details:**
- Case Number: ZPS-2025-0092
- Investigating Officer: Officer Phiri
- Badge Number: ZP-9012
- Airtel contacted: Yes
- Airtel confirmed: FAKE

**Data Source:** Police investigation

---

### Example 6: Critical - Zanaco Phishing
```
Indicator: zanaco-secure.com
Type: phishing
Severity: CRITICAL (95%)
Reports: 12
Loss: K120,000
Status: Active, Verified
```

**What happened:**
- Sophisticated phishing targeting Zanaco customers
- Email claims account will be suspended
- Links to fake website
- Site looks exactly like real Zanaco
- Uses HTTPS (appears secure!)
- 12 victims lost money

**How the attack works:**
1. Victim receives professional email
2. "Dear Zanaco Customer"
3. "Your account will be suspended due to suspicious activity"
4. "Click here to verify your account"
5. Link goes to zanaco-secure.com (NOT zanaco.co.zm!)
6. Website looks identical to real Zanaco
7. Has HTTPS padlock (looks secure)
8. Victim enters:
   - Account number
   - Username
   - Password
   - PIN
9. "Verification successful"
10. Scammer now has full account access
11. Drains account

**Why CRITICAL severity:**
- High financial impact (K120,000)
- Sophisticated attack
- Targets banking credentials
- Professional appearance
- HTTPS deception
- Many victims (12)
- Recently active (2 hours ago)

**Case Details:**
- Case Number: ZPS-2025-0095
- Investigating Officer: Detective Banda
- Badge Number: ZP-1234
- Domain registered: 5 days ago (Panama)
- Hosting: Namecheap
- Takedown requested: Yes

**Data Source:** Police investigation

**Technical Details:**
- Real Zanaco: zanaco.co.zm
- Fake site: zanaco-secure.com
- Difference: "secure" added to confuse
- Registered in Panama (hide identity)
- HTTPS certificate obtained (looks legitimate)

---

### Example 7: Critical - Ransomware
```
Indicator: secure-payment-zm.com
Type: malware
Severity: CRITICAL (98%)
Reports: 15
Loss: K250,000
Status: Active, Verified
```

**What happened:**
- Email campaign targeting Zambian businesses
- Email claims to be invoice
- Contains malicious PDF attachment
- Opening PDF encrypts all files
- Demands ransom payment
- 4 businesses affected

**How the attack works:**
1. Business receives email
2. "Invoice attached for payment"
3. Looks professional and urgent
4. Attachment: "invoice_2025.pdf"
5. Employee opens PDF
6. Malware activates (CryptoLocker variant)
7. Encrypts ALL files on computer:
   - Documents (.docx, .xlsx, .pdf)
   - Photos (.jpg, .png)
   - Databases (.db, .sql)
   - Backups
8. Screen shows message:
   "Your files are encrypted!"
   "Pay $5,000 USD to decrypt"
   "Bitcoin address: ..."
   "48 hours or files deleted forever"
9. Business can't operate
10. Files locked forever without key

**Why CRITICAL severity:**
- Highest financial impact (K250,000)
- Affects businesses (not just individuals)
- Ransomware (encrypts files)
- Active campaign (15 reports)
- Very recent (30 minutes ago)
- 4 businesses affected
- Operational disruption
- Data loss risk

**Case Details:**
- Case Number: ZPS-2025-0098
- Investigating Officer: Cyber Crimes Unit
- Badge Number: ZP-CYBER-01
- Ransomware family: CryptoLocker variant
- Ransom amount: $5,000 USD per victim
- Businesses affected: 4
- Payment method: Bitcoin
- Files encrypted: All documents

**Technical Details:**
- Email sender: invoice@secure-payment-zm.com
- Attachment: invoice_2025.pdf
- File type: PDF with embedded executable
- Encryption: AES-256
- C2 server: Unknown
- Decryption: Impossible without key

**Data Source:** Police investigation

---

## 🔥 SIM Swap Fraud - Deep Dive {#simswap}

### The Most Critical Threat

```
╔════════════════════════════════════════════════════════════╗
║  🔴 CRITICAL: +260978888888 - SIM SWAP FRAUD              ║
╚════════════════════════════════════════════════════════════╝

Threat Score: 92/100
Risk Level: CRITICAL
Verified: ✅ Yes (Cyber Crimes Unit)
Last Seen: 15 minutes ago ⚡ ACTIVE NOW
```

### What is SIM Swap Fraud?

**Definition:** Criminals transfer a victim's phone number to a new SIM card they control, giving them access to all phone-based accounts.

### How SIM Swap Works (Step by Step)

#### Phase 1: Information Gathering
```
Week 1-2: Scammer collects victim information
```

1. **Target Selection**
   - Scammer identifies wealthy victim
   - Looks for public social media profiles
   - Finds phone number online
   - Checks if they use mobile banking

2. **Information Collection**
   - Full name
   - Date of birth
   - ID number (from data breaches)
   - Phone number
   - Address
   - Mother's maiden name

**How they get this:**
- Social media (Facebook, Instagram)
- Data breaches
- Phishing emails
- Public records
- Social engineering

#### Phase 2: SIM Swap Attack
```
Day 1: Scammer executes SIM swap
```

**Method 1: Social Engineering at Telecom**

1. **Scammer goes to MTN/Airtel shop**
2. Claims to be victim
3. Says: "I lost my SIM card"
4. Shows fake ID (or bribed employee)
5. Requests new SIM with victim's number
6. Shop activates new SIM
7. **Victim's SIM stops working immediately**

**Method 2: Insider Threat**

1. Scammer has contact at telecom
2. Pays employee to do swap
3. No shop visit needed
4. Harder to detect

**Method 3: Technical Exploit**

1. Hacks telecom system
2. Issues swap command
3. Completely remote
4. Very sophisticated

#### Phase 3: Account Takeover
```
Hour 1-2: Scammer takes control
```

**What happens immediately:**

1. **Victim's Phone Goes Dead**
   - No signal
   - "SIM not provisioned"
   - Can't make calls
   - Can't receive messages

2. **Scammer's New SIM Activates**
   - Same phone number
   - Receives all SMS/calls
   - Full control

3. **Access to Everything**
   ```
   Phone number controls:
   - Mobile banking (MTN, Airtel Money)
   - WhatsApp
   - Facebook
   - Email (via SMS reset)
   - Bank accounts (SMS verification)
   - All apps using phone number
   ```

#### Phase 4: Money Theft
```
Hour 2-4: Scammer steals money
```

**Step-by-step theft:**

1. **Mobile Money Access**
   ```
   MTN Mobile Money:
   - Reset PIN using SMS
   - Receives code on swapped SIM
   - Sets new PIN
   - Transfers all money out

   Victim balance: K50,000 → K0
   Transfer to: Scammer's account
   Time taken: 5 minutes
   ```

2. **Bank Account Access**
   ```
   Online Banking:
   - Request password reset
   - SMS code sent to swapped number
   - Scammer receives code
   - Changes password
   - Transfers money to mule accounts

   Victim balance: K100,000 → K0
   Transfer out: Multiple transactions
   Time taken: 15 minutes
   ```

3. **Cryptocurrency**
   ```
   If victim has crypto:
   - Access exchange account
   - Reset password via SMS
   - Transfer all crypto
   - Convert to untraceable coins
   ```

4. **Social Media**
   ```
   WhatsApp/Facebook:
   - Take over accounts
   - Message all contacts
   - "Emergency! Need money!"
   - Contacts send money
   - Additional K20,000 stolen
   ```

#### Phase 5: Cover Tracks
```
Hour 4-6: Scammer disappears
```

1. **Transfer Chain**
   ```
   Stolen money → Mule 1 → Mule 2 → Mule 3 → Cash out
   ```

2. **Dispose of SIM**
   - Destroy evidence
   - Change location
   - Use new number

3. **Victim Realizes**
   - 6-12 hours later
   - All money gone
   - Can't prove anything
   - Very hard to recover

### Current Attack - +260978888888

#### Timeline

**Day 1 (2 days ago):**
```
09:00 - Victim 1: SIM stops working
09:15 - Scammer swaps to +260978888888
09:30 - K25,000 stolen from mobile money
10:00 - K15,000 stolen from bank
Victim 1 Loss: K40,000
```

**Day 1 (afternoon):**
```
14:00 - Victim 2: SIM stops working
14:15 - Scammer swaps to same number
14:45 - K18,000 stolen from mobile money
15:00 - K12,000 stolen from bank
Victim 2 Loss: K30,000
```

**Day 2 (yesterday):**
```
10:30 - Victim 3: SIM stops working
10:45 - Number swapped again
11:00 - K22,000 stolen
Victim 3 Loss: K22,000

15:00 - Victim 4: SIM stops working
15:15 - K28,000 stolen
Victim 4 Loss: K28,000

19:00 - Victim 5: SIM stops working
19:15 - K20,000 stolen
Victim 5 Loss: K20,000
```

**Today (last 15 minutes):**
```
17:45 - Victim 6: SIM stops working
17:50 - Victim 7: SIM stops working
18:00 - Active swaps detected
Status: ⚡ HAPPENING NOW
```

#### Attack Statistics

```
╔════════════════════════════════════════════════╗
║        SIM SWAP ATTACK STATISTICS              ║
╠════════════════════════════════════════════════╣
║  Total Victims:           7 people             ║
║  Total Financial Loss:    K185,000             ║
║  Average Loss per Victim: K26,428              ║
║  Attack Duration:         48 hours             ║
║  Attack Method:           Same number reused   ║
║  Telecom Involved:        MTN (suspected)      ║
║  Geographic Area:         Lusaka               ║
║  Time Pattern:            Morning/Evening      ║
║  Status:                  ⚡ ACTIVE NOW        ║
╚════════════════════════════════════════════════╝
```

#### Victim Breakdown

**Victim 1:**
- Name: [Redacted]
- Date: 2025-10-26, 09:00
- Loss: K40,000
- Source: Mobile money + Bank

**Victim 2:**
- Name: [Redacted]
- Date: 2025-10-26, 14:00
- Loss: K30,000
- Source: Mobile money + Bank

**Victim 3:**
- Name: [Redacted]
- Date: 2025-10-27, 10:30
- Loss: K22,000
- Source: Mobile money

**Victim 4:**
- Name: [Redacted]
- Date: 2025-10-27, 15:00
- Loss: K28,000
- Source: Bank account

**Victim 5:**
- Name: [Redacted]
- Date: 2025-10-27, 19:00
- Loss: K20,000
- Source: Mobile money

**Victim 6:**
- Name: [Redacted]
- Date: 2025-10-28, 17:45
- Loss: K25,000 (estimated)
- Source: In progress...

**Victim 7:**
- Name: [Redacted]
- Date: 2025-10-28, 17:50
- Loss: K20,000 (estimated)
- Source: In progress...

### Why This is CRITICAL

#### 1. **Active Attack**
```
⚡ Last activity: 15 minutes ago
⚡ Currently attacking victims 6 and 7
⚡ May attack more tonight
```

#### 2. **High Financial Impact**
```
💰 K185,000 stolen in 48 hours
💰 Average K26,000 per victim
💰 Victims 6-7 losses still counting
💰 Could reach K230,000+ by end of day
```

#### 3. **Pattern Detected**
```
🔍 Same number used repeatedly (+260978888888)
🔍 Time pattern: Morning (9-11am) and Evening (5-7pm)
🔍 All victims in Lusaka
🔍 All using MTN network
🔍 Targeting business owners (high balances)
```

#### 4. **Insider Threat Suspected**
```
⚠️ Multiple swaps to same number = telecom employee involved
⚠️ Professional operation
⚠️ Quick execution (15-minute attacks)
⚠️ High success rate
```

#### 5. **Ongoing Risk**
```
🚨 More victims expected tonight
🚨 Pattern suggests 2-3 attacks per day
🚨 Could continue for weeks
🚨 Total potential loss: Millions
```

### Investigation Details

**Case Information:**
```
Case Number: ZPS-2025-0099
Unit: Cyber Crimes Unit
Badge: ZP-CYBER-02
Officer: [Cyber Crimes Team]
Priority: URGENT
Status: Active Investigation
```

**Evidence Collected:**
```
✅ 7 victim statements
✅ Bank transaction records
✅ Mobile money logs
✅ Telecom swap records
✅ Timestamps of swaps
✅ Pattern analysis
✅ Suspect number: +260978888888
```

**Actions Taken:**
```
✅ MTN notified - investigating employee records
✅ Airtel notified - checking for similar patterns
✅ Banks alerted - monitoring transfers to suspect accounts
✅ Victim support - helping with fund recovery
✅ Public warning - alerting potential targets
```

**Next Steps:**
```
⏰ Immediate (next 2 hours):
   - Identify telecom employee
   - Block +260978888888
   - Prevent more swaps tonight

⏰ Today:
   - Arrest suspect
   - Interview victims
   - Trace stolen funds

⏰ This Week:
   - Recover funds where possible
   - Prosecute all involved
   - Implement preventive measures
```

### Prevention Measures

**For Citizens:**
```
✅ Enable SIM card PIN lock
✅ Don't share personal info online
✅ Use strong unique passwords
✅ Enable 2FA (not SMS-based)
✅ Monitor account activity
✅ Report lost SIM immediately
```

**For Telecoms:**
```
✅ Require ID verification for swaps
✅ SMS notification before swap
✅ 24-hour delay for swaps
✅ Biometric verification
✅ Employee monitoring
✅ Audit trail for all swaps
```

**For Banks:**
```
✅ Multi-factor authentication
✅ Transaction alerts
✅ Spending limits
✅ Suspicious activity detection
✅ Alternative verification methods
```

### Why Dashboard Shows This

The dashboard highlights this threat because:

1. **Immediate Danger** - Happening RIGHT NOW
2. **High Impact** - K185,000 stolen, more at risk
3. **Pattern Clear** - Can predict next attacks
4. **Preventable** - Can stop with quick action
5. **Public Safety** - Need to warn others

### What Investigators See

When clicking "View Full Report" on dashboard:

```
╔════════════════════════════════════════════════════════════╗
║              DETAILED THREAT REPORT                        ║
║              +260978888888                                 ║
╚════════════════════════════════════════════════════════════╝

THREAT CLASSIFICATION
─────────────────────
Type:           fraud (SIM swap)
Severity:       🔴 CRITICAL
Confidence:     92%
Status:         ⚡ ACTIVE
Verified:       ✅ Yes (Cyber Crimes Unit)

STATISTICS
──────────
Reports:        7 victims
Financial Loss: K185,000 ZMW
First Seen:     2025-10-26 09:00
Last Seen:      2025-10-28 17:50 (15 min ago)
Days Active:    2 days
Attack Rate:    3.5 victims per day

DESCRIPTION
───────────
ACTIVE SIM SWAP FRAUD! This number is being used after SIM
swap attacks. Criminals swap victim's SIM to this number,
then access mobile money accounts. Multiple victims in last
48 hours.

INVESTIGATION
─────────────
Case:           ZPS-2025-0099
Officer:        Cyber Crimes Unit
Badge:          ZP-CYBER-02
Date Opened:    2025-10-28
Priority:       URGENT

EVIDENCE
────────
✅ SIM swaps detected:     7
✅ Mobile money theft:      Yes
✅ MTN notified:           Yes
✅ Airtel notified:        Yes
✅ Pattern identified:     Yes
✅ Insider suspected:      Yes

GEOGRAPHIC DATA
───────────────
Country:        Zambia (ZM)
Region:         Lusaka
City:           Lusaka
Telecom:        MTN (primary)

TIMELINE
────────
2025-10-26 09:00  First victim (K40,000)
2025-10-26 14:00  Second victim (K30,000)
2025-10-27 10:30  Third victim (K22,000)
2025-10-27 15:00  Fourth victim (K28,000)
2025-10-27 19:00  Fifth victim (K20,000)
2025-10-28 17:45  Sixth victim (K25,000 est.)
2025-10-28 17:50  Seventh victim (K20,000 est.)

RISK ASSESSMENT
───────────────
Risk Score:     92/100
Risk Level:     CRITICAL
Threat Type:    Active financial fraud
Target:         Mobile money users
Method:         SIM swap + account takeover
Impact:         High (multiple victims, high losses)
Urgency:        Immediate action required

PUBLIC WARNING
──────────────
⚠️ URGENT PUBLIC SAFETY ALERT

If your phone suddenly loses signal:
1. Contact telecom IMMEDIATELY
2. Check for unauthorized SIM swap
3. Change all passwords immediately
4. Contact bank to freeze accounts
5. Report to police

Do NOT assume it's network issue!
Could be SIM swap in progress!

RECOMMENDED ACTIONS
───────────────────
□ Alert all Lusaka residents
□ Coordinate with MTN security
□ Identify telecom employee
□ Block suspect number
□ Monitor for new swaps
□ Trace stolen funds
□ Arrest suspect(s)
□ Implement prevention measures

RELATED CASES
─────────────
• ZPS-2025-0087 - Similar SIM swap (resolved)
• ZPS-2025-0091 - Mobile money theft
• 5 other related investigations

TAGS
────
#sim_swap #mobile_money #urgent #active_attack
#multiple_victims #critical #insider_threat #lusaka

[Mark as Resolved]  [Add Victim]  [Update Status]
[Link to Case]      [Export Report]  [Share Alert]
```

---

## 🎯 Summary

### Dashboard Purpose

The Threat Intelligence Dashboard provides:

1. **Situational Awareness** - See all threats at a glance
2. **Priority Focus** - Critical threats highlighted
3. **Quick Action** - Links to investigate/resolve
4. **Trend Analysis** - Recent activity patterns
5. **Resource Allocation** - Assign officers effectively

### Key Statistics (Current)

```
Total Threats:      10
Verified:           7 (70%)
Critical:           3 (30%)
High:               3 (30%)
Medium:             2 (20%)
Low:                2 (20%)

Total Losses:       K690,000
Most Dangerous:     Ransomware (K250,000)
Most Active:        SIM Swap (15 min ago)
Most Victims:       Ransomware (15 reports)
```

### How Data Flows to Dashboard

```
Citizen Reports         Police Investigations
      │                          │
      ├──────────┬───────────────┤
                 │
          ┌──────▼──────┐
          │  DATABASE   │
          │ threat_intel│
          └──────┬──────┘
                 │
        ┌────────▼────────┐
        │   Dashboard     │
        │  Queries Data   │
        └────────┬────────┘
                 │
          ┌──────▼──────┐
          │   Display   │
          │   to User   │
          └─────────────┘
```

### Access Control

**Who can see dashboard:**
- ✅ Police investigators (all ranks)
- ✅ Cyber Crimes Unit
- ✅ Administrators
- ✅ Supervisors

**Who cannot:**
- ❌ Public users
- ❌ Unauthenticated visitors

**Login required:** Yes

### Update Frequency

- **Statistics:** Real-time (updates on each page load)
- **Recent Threats:** Real-time (last 30 days)
- **Critical Threats:** Real-time (active only)
- **Database:** Updated immediately when new threats added

---

**Last Updated:** 2025-10-28
**Document Version:** 1.0.0
**Dashboard URL:** http://72.61.162.49:9000/threat-intel/dashboard
