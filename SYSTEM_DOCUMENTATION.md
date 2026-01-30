# CyberTrace OSINT Platform - System Documentation

**Organization:** Zambia Police Service - Investigations Team
**Access URL:** http://72.61.162.49:9000
**Stack:** Flask 3.0, PostgreSQL 14+, Redis, Python 3.10+, Bootstrap 5

---

## 1. Authentication & Login

### 1.1 Login
**URL:** `http://72.61.162.49:9000/auth/login`

1. User enters **Badge Number** and **Password**
2. System validates credentials against bcrypt hash
3. Account lockout enforced after **5 failed attempts** (locked for 15 minutes)
4. If **2FA is enabled**, user is redirected to `/auth/verify-2fa` to enter a 6-digit TOTP code
5. First-time users must accept **Terms & Conditions** at `/auth/accept-terms`
6. On success, user is redirected to the **Dashboard**

All login attempts (success/failure) are recorded in the audit log with IP address and user agent.

### 1.2 Password Requirements
- Minimum 12 characters
- Uppercase and lowercase letters
- Numbers and special characters

### 1.3 Two-Factor Authentication (2FA)
- TOTP-based (Google Authenticator, Authy, etc.)
- Setup/disable via `/auth/setup-2fa`
- QR code provided during setup

### 1.4 Other Auth Routes

| Route | Purpose |
|-------|---------|
| `/auth/change-password` | Change current password |
| `/auth/profile` | View user profile |
| `/auth/logout` | Log out and clear session |

---

## 2. Dashboard

**URL:** `http://72.61.162.49:9000/dashboard/`

The main landing page after login. Displays:

- **Statistics Cards:**
  - Total cases, open cases, cases under investigation, closed cases
  - Total investigations by user, investigations this month/week
  - Total evidence collected
- **Recent Cases** - Latest 5 cases (filtered by role)
- **Recent Investigations** - Latest 5 investigations by current user

Access is role-based: Admins and Senior Investigators see all cases; Investigators and Analysts see only their assigned cases.

---

## 3. Case Management

**URL:** `http://72.61.162.49:9000/cases/`

### 3.1 List Cases
Displays all cases the user has access to, with status indicators (open, investigating, pending, closed, archived) and priority levels.

### 3.2 Create Case
**URL:** `http://72.61.162.49:9000/cases/create`

| Field | Details |
|-------|---------|
| Title | Required |
| Description | Required |
| Case Type | Fraud, Cybercrime, Identity Theft, Financial Crime, Other |
| Priority | Low, Medium (default), High, Critical |

The system auto-generates a **case number** in the format `ZPS-YYYY-XXXX` and assigns the current user as lead investigator.

### 3.3 View Case Details
**URL:** `http://72.61.162.49:9000/cases/<case_id>`

Displays:
- Case metadata (number, title, type, priority, status)
- Lead investigator and assigned officers
- Warrant information (number, date, document)
- Case timeline with all activities
- Linked investigations and collected evidence
- Full audit trail for the case

### 3.4 Case Guide
**URL:** `http://72.61.162.49:9000/cases/case-management-guide/download` - Downloads a PDF guide for case management procedures.

---

## 4. Investigation Module (OSINT Tools)

**URL:** `http://72.61.162.49:9000/investigations/`

The investigation dashboard provides access to all OSINT tools. Every investigation must be linked to an existing case.

### 4.1 Email OSINT
**URL:** `http://72.61.162.49:9000/investigations/email`

**Input:** Email address + Case ID

**Investigation steps performed:**
1. Email format validation and MX record check
2. Domain analysis (registrar, expiration, nameservers)
3. Breach checking (Have I Been Pwned integration)
4. DNS records analysis (MX, TXT, SPF, DKIM, DMARC)
5. Social media account discovery
6. Email reputation assessment

**Output:** Validation status, breach count/details, domain info, DNS records, social media accounts, risk score.

**View results:** `/investigations/email/<investigation_id>`
**Download PDF:** `/investigations/email/<investigation_id>/pdf` (court-admissible format)

### 4.2 Email Header Analyzer
**URL:** `http://72.61.162.49:9000/investigations/email-header-analyzer`

**Input:** Raw email headers (pasted as text), optional Case ID

**Analysis performed:**
- Sender authentication verification (SPF, DKIM, DMARC)
- Spoofing detection
- Email routing analysis
- Authenticity scoring (0-100)
- Warning flag identification

### 4.3 Bulk Email Investigation
**URL:** `http://72.61.162.49:9000/investigations/email/bulk`

**Input:** Up to 50 email addresses (comma or newline separated) + Case ID

Runs the full email OSINT process on each address. Results are summarized on a bulk results page with links to individual investigation records.

### 4.4 Phone OSINT
**URL:** `http://72.61.162.49:9000/investigations/phone`

**Input:** Phone number (with or without country code, Zambia default) + Case ID

**Investigation steps performed:**
1. Phone number validation and formatting
2. Carrier and network type detection
3. Geographic location analysis
4. Line type classification (mobile, landline, VOIP)
5. Online presence detection
6. Risk assessment scoring

**Integrations:** Numverify API, PhoneInfoga (port 9050)

**View results:** `/investigations/phone/<investigation_id>`
**Download PDF:** `/investigations/phone/<investigation_id>/pdf`

### 4.5 Social Media OSINT
**URL:** `http://72.61.162.49:9000/investigations/social-media`

**Input:** Username + Case ID

Searches across multiple platforms:
- Facebook (profile, posts, groups, pages)
- Twitter/X
- Instagram
- LinkedIn
- TikTok
- YouTube
- GitHub
- Reddit
- And more

**View results:** `/investigations/social-media/<investigation_id>`

### 4.6 Investigation Guides

| Route | Format |
|-------|--------|
| `/investigations/email-osint-guide/download` | PDF |
| `/investigations/phone-osint-guide/download` | PDF |
| `/investigations/investigations-guide/download` | PDF |
| `/investigations/user-guide` | Web page |
| `/investigations/phone-osint-guide` | Web page |

---

## 5. Threat Intelligence Module

**URL:** `http://72.61.162.49:9000/threat-intel/dashboard`

### 5.1 Threat Dashboard
Displays:
- Total threats, active threats, verified threats, false positives
- Recent threats (last 30 days)
- Critical threats list
- Threat type breakdown (chart)
- Regional statistics (Zambia provinces/districts)

### 5.2 Search Threats
**URL:** `http://72.61.162.49:9000/threat-intel/search`

**Input:** Indicator value (phone, email, domain, or IP - auto-detected)

1. Searches the local threat database
2. Optionally queries external sources (AbuseIPDB, AlienVault OTX, Cisco Talos, Abuse.ch)
3. Displays matching threats with type, severity, and status

### 5.3 View Threat Report
**URL:** `http://72.61.162.49:9000/threat-intel/report/<threat_id>`

Displays full threat details: indicators, type, severity, description, verification status, financial loss estimate, reporter info, and source.

### 5.4 Threat Verification (Admin Only)
- **Verify:** `POST /threat-intel/verify/<threat_id>` - Marks a threat as verified
- **False Positive:** `POST /threat-intel/false-positive/<threat_id>` - Marks a threat as false positive with a reason

### 5.5 Public Threat Reporting
**URL:** `http://72.61.162.49:9000/threat-intel/public/report`

No authentication required. Citizens can submit threat reports with:
- Indicator type and value (phone, email, domain, URL)
- Threat type (Scam/Fraud, Malware, Phishing, Identity Theft, Other)
- Description, financial loss amount
- Reporter name and contact (optional, defaults to "Anonymous")

Reports are created with "investigating" status and 30% confidence score until verified by an admin.

### 5.6 Threat Intelligence API

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/threat-intel/api/check` | POST | Check an indicator against the threat database |
| `/threat-intel/api/stats` | GET | Retrieve threat statistics |

### 5.7 Help Guide
**URL:** `http://72.61.162.49:9000/threat-intel/help` - Interactive help and documentation.

---

## 6. Administration Module (Admin Only)

**URL:** `http://72.61.162.49:9000/admin/`

### 6.1 User Management
**URL:** `http://72.61.162.49:9000/admin/users`

Lists all users with search (name, badge number, email, username) and filters (role, status). Shows statistics: total, active, inactive, locked, admins, investigators.

### 6.2 Create User
**URL:** `http://72.61.162.49:9000/admin/users/create`

| Field | Details |
|-------|---------|
| Badge Number | Unique, required |
| Full Name | Required |
| Email | Unique, required |
| Username | Unique, required |
| Password | Must meet strength requirements |
| Role | Admin, Senior Investigator, Investigator, Analyst |
| Rank | Police rank |
| Department | Department name |

### 6.3 Edit User
**URL:** `http://72.61.162.49:9000/admin/users/<user_id>/edit`

Editable: full name, email, role, rank, department, phone number, password (optional reset).

### 6.4 User Account Actions

| Action | Route | Description |
|--------|-------|-------------|
| Toggle Status | `POST /admin/users/<id>/toggle-status` | Activate or deactivate a user (cannot self-deactivate) |
| Unlock Account | `POST /admin/users/<id>/unlock` | Reset failed login attempts and clear lock |
| Reset Password | `POST /admin/users/<id>/reset-password` | Reset password to badge number (user must change on next login) |

### 6.5 System Settings
**URL:** `http://72.61.162.49:9000/admin/settings`

Configurable options:
- App name and organization name
- Log level
- Feature flags (enable/disable individual OSINT modules)
- Email configuration
- API keys management
- Session timeout
- Password policy settings

### 6.6 Audit Logs
**URL:** `http://72.61.162.49:9000/admin/audit-logs`

Complete record of all system activity. Filterable by user, action, date range, and resource type.

Each log entry records: user (ID, username, badge number), action, resource, IP address, user agent, request method/path, HTTP status, and timestamp.

---

## 7. User Roles & Permissions

| Role | Cases | Investigations | Threat Intel | Admin |
|------|-------|----------------|-------------|-------|
| **Admin** | Create, view, edit all cases | Run all OSINT tools | Full access + verify/reject threats | Full access |
| **Senior Investigator** | Create, view all, assign officers | Run all OSINT tools | Full access | No access |
| **Investigator** | View/edit assigned cases only | Run OSINT tools on assigned cases | Read access | No access |
| **Analyst** | View assigned cases (read-only) | Run OSINT tools, view evidence | Read-only access | No access |

---

## 8. Security Features

| Feature | Details |
|---------|---------|
| Password Hashing | bcrypt (PBKDF2:SHA256) |
| Account Lockout | 5 failed attempts, 15-minute lock |
| 2FA | TOTP-based (optional) |
| CSRF Protection | Flask-WTF tokens on all forms |
| Rate Limiting | 200/day, 50/hour default |
| Session Security | Secure, HttpOnly, SameSite=Lax cookies, 30-min timeout |
| Security Headers | X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, HSTS, CSP |
| Evidence Integrity | SHA-256 hashing for tamper detection |
| Audit Logging | All actions logged with IP and user agent |
| Chain of Custody | Full evidence handling trail |

---

## 9. Typical Investigation Workflow

```
1. LOGIN
   Badge Number + Password --> 2FA (if enabled) --> Accept Terms (first time)
                                                          |
2. DASHBOARD                                              v
   View statistics, recent cases, recent investigations
                         |
3. CREATE CASE           v
   Title + Description + Type + Priority --> Case Number Generated (ZPS-YYYY-XXXX)
                         |
4. RUN INVESTIGATION     v
   Select OSINT Tool --> Enter Target --> Select Case --> System Runs Analysis
                         |
5. REVIEW RESULTS        v
   View findings --> Add notes --> Download PDF Report (court-admissible)
                         |
6. CHECK THREATS         v
   Search indicator --> Local DB + External Sources --> View matching threats
                         |
7. CLOSE CASE            v
   Update status to "Closed" --> Case archived with full audit trail
```

---

## 10. System Configuration

### Feature Flags
Each OSINT module can be independently enabled or disabled:
- `ENABLE_EMAIL_OSINT`
- `ENABLE_PHONE_OSINT`
- `ENABLE_SOCIAL_MEDIA_OSINT`
- `ENABLE_DOMAIN_IP_OSINT`
- `ENABLE_BREACH_CHECKER`
- `ENABLE_CRYPTO_TRACER`
- `ENABLE_METADATA_EXTRACTOR`
- `ENABLE_GEOLOCATION`

### Key Environment Variables
```
FLASK_ENV          - development / production / testing
SECRET_KEY         - Session encryption key
DATABASE_URL       - PostgreSQL connection string
REDIS_URL          - Redis connection string
ENABLE_2FA         - Enable two-factor authentication
ENABLE_AUDIT_LOGGING - Enable audit trail
```

### CLI Commands
```bash
flask init-db       # Create all database tables
flask create-admin  # Create default admin user
flask seed-data     # Load test/seed data
```

### Services

| Service | Address | Port |
|---------|---------|------|
| CyberTrace (Flask) | 72.61.162.49 | 9000 |
| PhoneInfoga | 72.61.162.49 | 9050 |
| PostgreSQL | localhost | 5432 |
| Redis | localhost | 6379 |

---

## 11. Complete Route Reference

### Authentication (`/auth`)
| Route | Method | Purpose |
|-------|--------|---------|
| `/auth/login` | GET/POST | Login |
| `/auth/logout` | GET | Logout |
| `/auth/verify-2fa` | GET/POST | 2FA verification |
| `/auth/setup-2fa` | GET/POST | Enable/disable 2FA |
| `/auth/change-password` | GET/POST | Change password |
| `/auth/accept-terms` | GET/POST | Accept terms & conditions |
| `/auth/profile` | GET | View profile |

### Dashboard (`/dashboard`)
| Route | Method | Purpose |
|-------|--------|---------|
| `/dashboard/` | GET | Main dashboard |

### Cases (`/cases`)
| Route | Method | Purpose |
|-------|--------|---------|
| `/cases/` | GET | List cases |
| `/cases/<case_id>` | GET | View case |
| `/cases/create` | GET/POST | Create case |
| `/cases/case-management-guide/download` | GET | Download guide PDF |

### Investigations (`/investigations`)
| Route | Method | Purpose |
|-------|--------|---------|
| `/investigations/` | GET | Investigation dashboard |
| `/investigations/email` | GET/POST | Email OSINT |
| `/investigations/email/<id>` | GET | View email results |
| `/investigations/email/<id>/pdf` | GET | Download email report |
| `/investigations/email-header-analyzer` | GET/POST | Header analyzer |
| `/investigations/email-header/<id>` | GET | View header results |
| `/investigations/email/bulk` | GET/POST | Bulk email OSINT |
| `/investigations/bulk-results/<case_id>` | GET | Bulk results summary |
| `/investigations/phone` | GET/POST | Phone OSINT |
| `/investigations/phone/<id>` | GET | View phone results |
| `/investigations/phone/<id>/pdf` | GET | Download phone report |
| `/investigations/social-media` | GET/POST | Social media OSINT |
| `/investigations/social-media/<id>` | GET | View social media results |

### Threat Intelligence (`/threat-intel`)
| Route | Method | Purpose |
|-------|--------|---------|
| `/threat-intel/dashboard` | GET | TI dashboard |
| `/threat-intel/search` | GET/POST | Search threats |
| `/threat-intel/report/<threat_id>` | GET | View threat report |
| `/threat-intel/verify/<threat_id>` | POST | Verify threat (admin) |
| `/threat-intel/false-positive/<threat_id>` | POST | Mark false positive (admin) |
| `/threat-intel/public/report` | GET/POST | Public threat report |
| `/threat-intel/public/success` | GET | Report success page |
| `/threat-intel/help` | GET | Help guide |
| `/threat-intel/api/check` | POST | Check indicator API |
| `/threat-intel/api/stats` | GET | Get stats API |

### Administration (`/admin`)
| Route | Method | Purpose |
|-------|--------|---------|
| `/admin/users` | GET | List users |
| `/admin/users/create` | GET/POST | Create user |
| `/admin/users/<id>/edit` | GET/POST | Edit user |
| `/admin/users/<id>/toggle-status` | POST | Activate/deactivate |
| `/admin/users/<id>/unlock` | POST | Unlock account |
| `/admin/users/<id>/reset-password` | POST | Reset password |
| `/admin/settings` | GET/POST | System settings |
| `/admin/audit-logs` | GET | View audit logs |
