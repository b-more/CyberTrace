# Threat Intelligence - Valid Enum Values Reference

## Source Field (source)

Valid values for the `source` field in ThreatIntel model:

1. **`case_investigation`** - Threat identified through police investigation
   - Use when: Police case is investigating this threat
   - Example: MTN mobile money scam under active investigation

2. **`public_report`** - Reported by citizens via public form
   - Use when: Citizen submitted report through /threat-intel/public/report
   - Example: Complaint about suspicious phone number

3. **`partner_agency`** - Information from partner organizations
   - Use when: Data from banks, telecom providers, other agencies
   - Example: Airtel reports suspicious SIM swap activity

4. **`external_feed`** - From external threat intelligence APIs
   - Use when: Imported from AlienVault OTX, URLhaus, etc.
   - Example: Global phishing campaign detected by URLhaus

5. **`automated_detection`** - Automatically detected by system
   - Use when: System algorithms detect patterns
   - Example: Multiple failed login attempts from same IP

## Threat Type Field (threat_type)

Valid values:
- `scam`
- `fraud`
- `phishing`
- `malware`
- `spam`
- `identity_theft`
- `other`

## Severity Field (severity)

Valid values:
- `low`
- `medium`
- `high`
- `critical`

## Status Field (status)

Valid values:
- `active` - Threat is currently active
- `investigating` - Under investigation
- `resolved` - Case closed/threat neutralized
- `false_positive` - Confirmed not a threat

## Examples

### Police Investigation
```python
ThreatIntel(
    phone_number='+260971234567',
    threat_type='scam',
    severity='high',
    status='active',
    source='case_investigation',  # ✅ Correct
    source_details={
        'case_number': 'ZPS-2025-0089',
        'officer': 'Detective Mwamba'
    }
)
```

### Public Report
```python
ThreatIntel(
    email_address='scam@example.com',
    threat_type='phishing',
    severity='medium',
    status='investigating',
    source='public_report',  # ✅ Correct
    source_details={
        'reporter_name': 'Anonymous',
        'report_date': '2025-10-28'
    }
)
```

### External Feed
```python
ThreatIntel(
    domain='malware.com',
    threat_type='malware',
    severity='critical',
    status='active',
    source='external_feed',  # ✅ Correct
    source_details={
        'feed_source': 'URLhaus',
        'imported_at': '2025-10-28T12:00:00'
    }
)
```

## Common Mistakes

❌ **WRONG:**
```python
source='investigation'  # Will cause LookupError
source='case'           # Will cause LookupError
source='police'         # Will cause LookupError
```

✅ **CORRECT:**
```python
source='case_investigation'
```

---

**Last Updated:** 2025-10-28
**Model:** app/models/threat_intel.py
**Line:** ~55-60
