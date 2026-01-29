#!/usr/bin/env python3
"""
Add Sample Threat Intelligence Test Data
Zambia Police Service CyberTrace Platform
This script adds realistic test data to demonstrate all threat intelligence features.
"""
from app import create_app, db
from app.models.threat_intel import ThreatIntel
from datetime import datetime, timedelta
import json
def add_test_data():
    app = create_app()
    with app.app_context():
        print("🔄 Adding test threat intelligence data...\n")
        # Clear existing test data (optional)
        # ThreatIntel.query.delete()
        # db.session.commit()
        test_threats = []
        # ═══════════════════════════════════════════════════════════════
        # TEST 1: HIGH SEVERITY - MTN Mobile Money Scam
        # ═══════════════════════════════════════════════════════════════
        threat1 = ThreatIntel(
            phone_number='+260971234567',
            threat_type='scam',
            severity='high',
            confidence_score=85,
            status='active',
            verified=True,
            description='MTN mobile money scam. Caller claims to be MTN customer service and requests mobile money PIN. Uses social engineering to gain trust by knowing victim\'s name and account balance.',
            source='case_investigation',
            source_details={
                'case_number': 'ZPS-2025-0089',
                'investigating_officer': 'Officer Mwamba',
                'badge_number': 'ZP-5678',
                'investigation_date': (datetime.utcnow() - timedelta(days=10)).isoformat(),
                'verified_at': (datetime.utcnow() - timedelta(days=10)).isoformat()
            },
            tags=['mtn', 'mobile_money', 'pin_theft', 'social_engineering', 'active_campaign'],
            report_count=8,
            financial_loss=45000.00,
            country_code='ZM',
            region='Lusaka',
            city='Lusaka',
            first_seen=datetime.utcnow() - timedelta(days=15),
            last_seen=datetime.utcnow()
        )
        test_threats.append(threat1)
        print("✅ Test 1: MTN Mobile Money Scam (+260971234567)")
        # ═══════════════════════════════════════════════════════════════
        # TEST 2: CRITICAL SEVERITY - Fake Zanaco Banking Phishing
        # ═══════════════════════════════════════════════════════════════
        threat2 = ThreatIntel(
            email_address='support@zanaco-secure.com',
            domain='zanaco-secure.com',
            url='https://zanaco-secure.com/login',
            threat_type='phishing',
            severity='critical',
            confidence_score=95,
            status='active',
            verified=True,
            description='Sophisticated phishing campaign targeting Zanaco bank customers. Email claims account will be suspended unless user verifies credentials. Site uses HTTPS to appear legitimate. Domain registered 5 days ago in Panama.',
            source='case_investigation',
            source_details={
                'case_number': 'ZPS-2025-0095',
                'investigating_officer': 'Detective Banda',
                'badge_number': 'ZP-1234',
                'investigation_date': (datetime.utcnow() - timedelta(days=3)).isoformat(),
                'takedown_requested': True,
                'hosting_provider': 'Namecheap'
            },
            tags=['zanaco', 'banking', 'phishing', 'credential_theft', 'https', 'urgent_priority'],
            report_count=12,
            financial_loss=120000.00,
            country_code='ZM',
            region='Lusaka',
            city='Lusaka',
            first_seen=datetime.utcnow() - timedelta(days=5),
            last_seen=datetime.utcnow() - timedelta(hours=2)
        )
        test_threats.append(threat2)
        print("✅ Test 2: Zanaco Phishing (zanaco-secure.com)")
        # ═══════════════════════════════════════════════════════════════
        # TEST 3: LOW SEVERITY - Telemarketing (Not Malicious)
        # ═══════════════════════════════════════════════════════════════
        threat3 = ThreatIntel(
            phone_number='+260977777777',
            threat_type='spam',
            severity='low',
            confidence_score=20,
            status='resolved',
            verified=False,
            description='Telemarketing calls from legitimate business. Multiple complaints but no financial loss. Not considered malicious, just annoying.',
            source='public_report',
            source_details={
                'report_method': 'public_form',
                'anonymous_reports': 2
            },
            tags=['telemarketing', 'spam', 'not_malicious', 'resolved'],
            report_count=2,
            financial_loss=0.00,
            country_code='ZM',
            region='Ndola',
            city='Ndola',
            first_seen=datetime.utcnow() - timedelta(days=30),
            last_seen=datetime.utcnow() - timedelta(days=25)
        )
        test_threats.append(threat3)
        print("✅ Test 3: Telemarketing Spam (+260977777777)")
        # ═══════════════════════════════════════════════════════════════
        # TEST 4: HIGH SEVERITY - Fake Airtel Promotion
        # ═══════════════════════════════════════════════════════════════
        threat4 = ThreatIntel(
            domain='free-airtel-data.com',
            url='http://free-airtel-data.com/claim',
            threat_type='phishing',
            severity='high',
            confidence_score=80,
            status='active',
            verified=True,
            description='Fake Airtel promotion claiming "Free 50GB data for all customers". Collects personal information including ID number, phone number, and bank details. No actual data given.',
            source='case_investigation',
            source_details={
                'case_number': 'ZPS-2025-0092',
                'investigating_officer': 'Officer Phiri',
                'badge_number': 'ZP-9012',
                'investigation_date': (datetime.utcnow() - timedelta(days=5)).isoformat(),
                'airtel_contacted': True,
                'airtel_confirmed_fake': True
            },
            tags=['airtel', 'fake_promotion', 'data_theft', 'identity_fraud', 'copperbelt'],
            report_count=6,
            financial_loss=15000.00,
            country_code='ZM',
            region='Copperbelt',
            city='Kitwe',
            first_seen=datetime.utcnow() - timedelta(days=10),
            last_seen=datetime.utcnow() - timedelta(days=1)
        )
        test_threats.append(threat4)
        print("✅ Test 4: Fake Airtel Promotion (free-airtel-data.com)")
        # ═══════════════════════════════════════════════════════════════
        # TEST 5: MEDIUM SEVERITY - Suspicious IP (Multiple Login Attempts)
        # ═══════════════════════════════════════════════════════════════
        threat5 = ThreatIntel(
            ip_address='41.222.45.10',
            threat_type='fraud',
            severity='medium',
            confidence_score=60,
            status='investigating',
            verified=False,
            description='Multiple failed login attempts detected from this IP address targeting government websites. Possible credential stuffing attack. IP registered in Zambia but suspicious activity pattern.',
            source='case_investigation',
            source_details={
                'detection_method': 'automated_monitoring',
                'failed_attempts': 147,
                'targeted_sites': ['gov.zm', 'parliament.gov.zm', 'moe.gov.zm'],
                'investigation_status': 'ongoing'
            },
            tags=['brute_force', 'credential_stuffing', 'government_target', 'cyber_attack'],
            report_count=3,
            financial_loss=0.00,
            country_code='ZM',
            first_seen=datetime.utcnow() - timedelta(days=7),
            last_seen=datetime.utcnow() - timedelta(hours=12)
        )
        test_threats.append(threat5)
        print("✅ Test 5: Suspicious IP (41.222.45.10)")
        # ═══════════════════════════════════════════════════════════════
        # TEST 6: CRITICAL SEVERITY - Ransomware Email Campaign
        # ═══════════════════════════════════════════════════════════════
        threat6 = ThreatIntel(
            email_address='invoice@secure-payment-zm.com',
            domain='secure-payment-zm.com',
            threat_type='malware',
            severity='critical',
            confidence_score=98,
            status='active',
            verified=True,
            description='URGENT: Active ransomware email campaign. Email contains malicious PDF attachment that encrypts files when opened. Targets businesses in Zambia. Several companies already affected.',
            source='case_investigation',
            source_details={
                'case_number': 'ZPS-2025-0098',
                'investigating_officer': 'Cyber Crimes Unit',
                'badge_number': 'ZP-CYBER-01',
                'investigation_date': (datetime.utcnow() - timedelta(days=1)).isoformat(),
                'ransomware_family': 'CryptoLocker variant',
                'ransom_amount_usd': 5000,
                'businesses_affected': 4
            },
            tags=['ransomware', 'malware', 'cryptolocker', 'business_target', 'urgent', 'active_threat'],
            report_count=15,
            financial_loss=250000.00,
            country_code='ZM',
            region='Lusaka',
            city='Lusaka',
            first_seen=datetime.utcnow() - timedelta(days=3),
            last_seen=datetime.utcnow() - timedelta(minutes=30)
        )
        test_threats.append(threat6)
        print("✅ Test 6: Ransomware Campaign (secure-payment-zm.com)")
        # ═══════════════════════════════════════════════════════════════
        # TEST 7: HIGH SEVERITY - WhatsApp Impersonation Scam
        # ═══════════════════════════════════════════════════════════════
        threat7 = ThreatIntel(
            phone_number='+260965432109',
            threat_type='identity_theft',
            severity='high',
            confidence_score=90,
            status='active',
            verified=True,
            description='WhatsApp impersonation scam. Scammer hacks WhatsApp accounts then messages contacts claiming emergency and requesting money. Uses victim\'s profile picture and status.',
            source='case_investigation',
            source_details={
                'case_number': 'ZPS-2025-0096',
                'investigating_officer': 'Detective Zulu',
                'badge_number': 'ZP-3456',
                'investigation_date': (datetime.utcnow() - timedelta(days=2)).isoformat(),
                'whatsapp_reported': True,
                'accounts_compromised': 11
            },
            tags=['whatsapp', 'account_takeover', 'emergency_scam', 'impersonation', 'social_engineering'],
            report_count=11,
            financial_loss=67000.00,
            country_code='ZM',
            region='Lusaka',
            city='Lusaka',
            first_seen=datetime.utcnow() - timedelta(days=8),
            last_seen=datetime.utcnow() - timedelta(hours=5)
        )
        test_threats.append(threat7)
        print("✅ Test 7: WhatsApp Impersonation (+260965432109)")
        # ═══════════════════════════════════════════════════════════════
        # TEST 8: MEDIUM SEVERITY - Job Scam (False Positive Candidate)
        # ═══════════════════════════════════════════════════════════════
        threat8 = ThreatIntel(
            email_address='hr@zambia-mining-jobs.com',
            domain='zambia-mining-jobs.com',
            threat_type='scam',
            severity='medium',
            confidence_score=55,
            status='investigating',
            verified=False,
            description='Suspicious job offers for mining positions. Requires upfront payment for "processing fees". Domain registered recently. Needs verification - could be legitimate recruitment.',
            source='public_report',
            source_details={
                'report_method': 'public_form',
                'reporter_count': 4,
                'upfront_fee_requested': 500.00,
                'verification_pending': True
            },
            tags=['job_scam', 'mining', 'upfront_fee', 'needs_verification'],
            report_count=4,
            financial_loss=8000.00,
            country_code='ZM',
            region='Copperbelt',
            city='Ndola',
            first_seen=datetime.utcnow() - timedelta(days=12),
            last_seen=datetime.utcnow() - timedelta(days=3)
        )
        test_threats.append(threat8)
        print("✅ Test 8: Job Scam (zambia-mining-jobs.com)")
        # ═══════════════════════════════════════════════════════════════
        # TEST 9: LOW SEVERITY - Resolved Spam (Educational Example)
        # ═══════════════════════════════════════════════════════════════
        threat9 = ThreatIntel(
            phone_number='+260955555555',
            threat_type='spam',
            severity='low',
            confidence_score=15,
            status='false_positive',
            verified=False,
            description='Marked as false positive. Initially reported as spam but investigation revealed legitimate business SMS notifications from MTN.',
            source='public_report',
            source_details={
                'report_method': 'public_form',
                'false_positive_reason': 'Legitimate business notifications',
                'mtn_confirmed': True
            },
            tags=['false_positive', 'mtn', 'business_sms', 'resolved'],
            report_count=1,
            financial_loss=0.00,
            country_code='ZM',
            region='Lusaka',
            first_seen=datetime.utcnow() - timedelta(days=45),
            last_seen=datetime.utcnow() - timedelta(days=40)
        )
        test_threats.append(threat9)
        print("✅ Test 9: False Positive Example (+260955555555)")
        # ═══════════════════════════════════════════════════════════════
        # TEST 10: CRITICAL SEVERITY - Active SIM Swap Fraud
        # ═══════════════════════════════════════════════════════════════
        threat10 = ThreatIntel(
            phone_number='+260978888888',
            threat_type='fraud',
            severity='critical',
            confidence_score=92,
            status='active',
            verified=True,
            description='ACTIVE SIM SWAP FRAUD! This number is being used after SIM swap attacks. Criminals swap victim\'s SIM to this number, then access mobile money accounts. Multiple victims in last 48 hours.',
            source='case_investigation',
            source_details={
                'case_number': 'ZPS-2025-0099',
                'investigating_officer': 'Cyber Crimes Unit',
                'badge_number': 'ZP-CYBER-02',
                'investigation_date': datetime.utcnow().isoformat(),
                'sim_swaps_detected': 7,
                'mobile_money_theft': True,
                'mtn_airtel_notified': True,
                'urgent_priority': True
            },
            tags=['sim_swap', 'mobile_money', 'urgent', 'active_attack', 'multiple_victims', 'critical'],
            report_count=7,
            financial_loss=185000.00,
            country_code='ZM',
            region='Lusaka',
            city='Lusaka',
            first_seen=datetime.utcnow() - timedelta(days=2),
            last_seen=datetime.utcnow() - timedelta(minutes=15)
        )
        test_threats.append(threat10)
        print("✅ Test 10: SIM Swap Fraud (+260978888888)")
        # Add all threats to database
        try:
            for threat in test_threats:
                db.session.add(threat)
            db.session.commit()
            print("\n" + "="*60)
            print("✅ SUCCESS! All 10 test threats added to database!")
            print("="*60)
            print("\n📊 Test Data Summary:\n")
            print("  • 10 diverse threat scenarios")
            print("  • 7 different threat types")
            print("  • All severity levels (low, medium, high, critical)")
            print("  • Multiple regions in Zambia")
            print("  • Total financial losses: K690,000")
            print("  • Mix of verified and unverified threats")
            print("  • Includes 1 false positive example")
            print("\n🔍 Test These Indicators:\n")
            print("  High Priority:")
            print("    +260978888888  - SIM swap fraud (CRITICAL)")
            print("    zanaco-secure.com - Banking phishing (CRITICAL)")
            print("    secure-payment-zm.com - Ransomware (CRITICAL)")
            print("\n  Active Scams:")
            print("    +260971234567  - MTN money scam (HIGH)")
            print("    +260965432109  - WhatsApp scam (HIGH)")
            print("    free-airtel-data.com - Fake promotion (HIGH)")
            print("\n  Investigation:")
            print("    41.222.45.10 - Suspicious IP (MEDIUM)")
            print("    zambia-mining-jobs.com - Job scam (MEDIUM)")
            print("\n  Low Risk:")
            print("    +260977777777 - Telemarketing (LOW)")
            print("    +260955555555 - False positive (LOW)")
            print("\n" + "="*60)
            print("🚀 Ready to test! Go to:")
            print("   http://72.61.162.49:9000/threat-intel/search")
            print("="*60)
        except Exception as e:
            db.session.rollback()
            print(f"\n❌ ERROR: Failed to add test data: {str(e)}")
            return False
        return True
if __name__ == "__main__":
    success = add_test_data()
    exit(0 if success else 1)
