"""
Email OSINT Module
CyberTrace - Zambia Police Service

Comprehensive email investigation toolkit for fraud and cybercrime cases
"""

import re
import dns.resolver
import whois
import requests
import time
import socket
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import hashlib
import json


class EmailOSINT:
    """Email Open Source Intelligence Investigation Tool"""

    def __init__(self):
        self.results = {
            'email': None,
            'is_valid': False,
            'validation': {},
            'breaches': [],
            'domain_info': {},
            'dns_records': {},
            'social_media': [],
            'reputation': {},
            'metadata': {
                'investigated_at': None,
                'investigation_duration': 0,
                'api_calls_made': 0
            }
        }
        self.start_time = None
        self.api_calls = 0

    def investigate(self, email: str, case_id: str = None) -> Dict:
        """
        Main orchestrator function for email investigation

        Args:
            email (str): Email address to investigate
            case_id (str): Optional case ID to link investigation

        Returns:
            Dict: Comprehensive investigation results
        """
        self.start_time = time.time()
        self.results['email'] = email.lower().strip()
        self.results['metadata']['investigated_at'] = datetime.utcnow().isoformat()

        # Step 1: Email Validation
        is_valid, validation_details = self.validate_email(email)
        self.results['is_valid'] = is_valid
        self.results['validation'] = validation_details

        if not is_valid:
            self.results['metadata']['investigation_duration'] = time.time() - self.start_time
            self.results['metadata']['api_calls_made'] = self.api_calls
            return self.results

        # Step 2: Extract domain
        domain = email.split('@')[1]

        # Step 3: Breach Checking
        breaches = self.check_breaches(email)
        self.results['breaches'] = breaches

        # Step 4: Domain Analysis
        domain_info = self.analyze_domain(domain)
        self.results['domain_info'] = domain_info

        # Step 5: DNS Records
        dns_records = self.get_dns_records(domain)
        self.results['dns_records'] = dns_records

        # Step 6: Social Media Account Discovery
        social_accounts = self.discover_social_media(email)
        self.results['social_media'] = social_accounts

        # Step 7: Email Reputation
        reputation = self.check_reputation(email, domain)
        self.results['reputation'] = reputation

        # Calculate investigation duration
        self.results['metadata']['investigation_duration'] = time.time() - self.start_time
        self.results['metadata']['api_calls_made'] = self.api_calls

        return self.results

    def validate_email(self, email: str) -> Tuple[bool, Dict]:
        """
        Validate email address format and deliverability

        Args:
            email (str): Email address to validate

        Returns:
            Tuple[bool, Dict]: (is_valid, validation_details)
        """
        validation = {
            'syntax_valid': False,
            'domain_exists': False,
            'mx_records_exist': False,
            'disposable': False,
            'free_provider': False,
            'errors': []
        }

        # Regex pattern for email validation
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

        # Check syntax
        if not re.match(email_regex, email):
            validation['errors'].append('Invalid email syntax')
            return False, validation

        validation['syntax_valid'] = True

        try:
            domain = email.split('@')[1]

            # Check if domain exists
            try:
                socket.gethostbyname(domain)
                validation['domain_exists'] = True
            except socket.gaierror:
                validation['errors'].append('Domain does not exist')
                validation['domain_exists'] = False

            # Check MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                if mx_records:
                    validation['mx_records_exist'] = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                validation['errors'].append('No MX records found')
                validation['mx_records_exist'] = False

            # Check for disposable email providers
            disposable_domains = [
                'tempmail.com', 'guerrillamail.com', '10minutemail.com',
                'mailinator.com', 'throwaway.email', 'temp-mail.org'
            ]
            validation['disposable'] = domain in disposable_domains

            # Check for free email providers
            free_providers = [
                'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
                'aol.com', 'icloud.com', 'protonmail.com', 'mail.com'
            ]
            validation['free_provider'] = domain in free_providers

        except Exception as e:
            validation['errors'].append(f'Validation error: {str(e)}')
            return False, validation

        # Email is valid if syntax is correct and domain exists
        is_valid = validation['syntax_valid'] and validation['domain_exists']

        return is_valid, validation

    def check_breaches(self, email: str) -> List[Dict]:
        """
        Check if email appears in known data breaches (HaveIBeenPwned)

        Args:
            email (str): Email address to check

        Returns:
            List[Dict]: List of breaches found
        """
        breaches = []

        try:
            # HaveIBeenPwned API v3
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {
                'User-Agent': 'CyberTrace-ZambiaPolice',
                'api-version': '3'
            }

            # Note: Rate limit is 1 request per 1500ms without API key
            time.sleep(1.5)
            self.api_calls += 1

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                breach_data = response.json()
                for breach in breach_data:
                    breaches.append({
                        'name': breach.get('Name', 'Unknown'),
                        'title': breach.get('Title', 'Unknown'),
                        'domain': breach.get('Domain', 'Unknown'),
                        'breach_date': breach.get('BreachDate', 'Unknown'),
                        'added_date': breach.get('AddedDate', 'Unknown'),
                        'pwn_count': breach.get('PwnCount', 0),
                        'description': breach.get('Description', ''),
                        'data_classes': breach.get('DataClasses', []),
                        'is_verified': breach.get('IsVerified', False),
                        'is_sensitive': breach.get('IsSensitive', False),
                        'is_retired': breach.get('IsRetired', False),
                        'is_spam_list': breach.get('IsSpamList', False)
                    })
            elif response.status_code == 404:
                # No breaches found - this is good
                pass
            elif response.status_code == 429:
                breaches.append({
                    'error': 'Rate limit exceeded - please try again later',
                    'name': 'API_RATE_LIMIT'
                })
            else:
                breaches.append({
                    'error': f'API error: {response.status_code}',
                    'name': 'API_ERROR'
                })

        except requests.exceptions.RequestException as e:
            breaches.append({
                'error': f'Request failed: {str(e)}',
                'name': 'REQUEST_ERROR'
            })
        except Exception as e:
            breaches.append({
                'error': f'Breach check failed: {str(e)}',
                'name': 'GENERAL_ERROR'
            })

        return breaches

    def analyze_domain(self, domain: str) -> Dict:
        """
        Analyze email domain using WHOIS

        Args:
            domain (str): Domain to analyze

        Returns:
            Dict: Domain information
        """
        domain_info = {
            'domain': domain,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'name_servers': [],
            'registrant': None,
            'country': None,
            'status': [],
            'error': None
        }

        try:
            w = whois.whois(domain)

            # Extract creation date
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    domain_info['creation_date'] = w.creation_date[0].isoformat() if w.creation_date[0] else None
                else:
                    domain_info['creation_date'] = w.creation_date.isoformat() if w.creation_date else None

            # Extract expiration date
            if w.expiration_date:
                if isinstance(w.expiration_date, list):
                    domain_info['expiration_date'] = w.expiration_date[0].isoformat() if w.expiration_date[0] else None
                else:
                    domain_info['expiration_date'] = w.expiration_date.isoformat() if w.expiration_date else None

            domain_info['registrar'] = w.registrar
            domain_info['name_servers'] = w.name_servers if w.name_servers else []
            domain_info['country'] = w.country

            # Domain status
            if w.status:
                if isinstance(w.status, list):
                    domain_info['status'] = w.status
                else:
                    domain_info['status'] = [w.status]

        except Exception as e:
            domain_info['error'] = f'WHOIS lookup failed: {str(e)}'

        return domain_info

    def get_dns_records(self, domain: str) -> Dict:
        """
        Get DNS records for domain (MX, SPF, DMARC, TXT)

        Args:
            domain (str): Domain to query

        Returns:
            Dict: DNS records
        """
        dns_records = {
            'mx': [],
            'spf': None,
            'dmarc': None,
            'txt': [],
            'a': [],
            'errors': []
        }

        # MX Records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            for mx in mx_records:
                dns_records['mx'].append({
                    'priority': mx.preference,
                    'server': str(mx.exchange)
                })
        except Exception as e:
            dns_records['errors'].append(f'MX lookup failed: {str(e)}')

        # TXT Records (includes SPF)
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            for txt in txt_records:
                txt_value = str(txt).strip('"')
                dns_records['txt'].append(txt_value)

                # Check for SPF
                if txt_value.startswith('v=spf1'):
                    dns_records['spf'] = txt_value
        except Exception as e:
            dns_records['errors'].append(f'TXT lookup failed: {str(e)}')

        # DMARC Record
        try:
            dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for dmarc in dmarc_records:
                dmarc_value = str(dmarc).strip('"')
                if dmarc_value.startswith('v=DMARC1'):
                    dns_records['dmarc'] = dmarc_value
        except Exception as e:
            dns_records['errors'].append(f'DMARC lookup failed: {str(e)}')

        # A Records
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            for a in a_records:
                dns_records['a'].append(str(a))
        except Exception as e:
            dns_records['errors'].append(f'A record lookup failed: {str(e)}')

        return dns_records

    def discover_social_media(self, email: str) -> List[Dict]:
        """
        Discover social media accounts associated with email

        Args:
            email (str): Email address to search

        Returns:
            List[Dict]: Social media accounts found
        """
        social_accounts = []
        username = email.split('@')[0]
        email_hash = hashlib.md5(email.encode().lower()).hexdigest()

        # Expanded social media platform checks
        platforms = [
            # Profile-based platforms
            {'name': 'GitHub', 'check_url': f'https://api.github.com/users/{username}', 'method': 'api'},
            {'name': 'GitLab', 'check_url': f'https://gitlab.com/{username}', 'method': 'http'},
            {'name': 'Gravatar', 'check_url': f'https://www.gravatar.com/avatar/{email_hash}?d=404', 'method': 'http'},

            # Professional platforms
            {'name': 'LinkedIn', 'check_url': f'https://www.linkedin.com/in/{username}', 'method': 'http'},

            # Developer platforms
            {'name': 'Stack Overflow', 'check_url': f'https://stackoverflow.com/users/{username}', 'method': 'http'},
            {'name': 'HackerRank', 'check_url': f'https://www.hackerrank.com/{username}', 'method': 'http'},

            # Creative platforms
            {'name': 'Behance', 'check_url': f'https://www.behance.net/{username}', 'method': 'http'},
            {'name': 'Dribbble', 'check_url': f'https://dribbble.com/{username}', 'method': 'http'},

            # Social platforms
            {'name': 'Twitter/X', 'check_url': f'https://twitter.com/{username}', 'method': 'http'},
            {'name': 'Instagram', 'check_url': f'https://www.instagram.com/{username}', 'method': 'http'},
            {'name': 'Facebook', 'check_url': f'https://www.facebook.com/{username}', 'method': 'http'},

            # Other platforms
            {'name': 'Medium', 'check_url': f'https://medium.com/@{email}', 'method': 'http'},
            {'name': 'Reddit', 'check_url': f'https://www.reddit.com/user/{username}', 'method': 'http'},
        ]

        for platform in platforms:
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }

                response = requests.get(
                    platform['check_url'],
                    headers=headers,
                    timeout=5,
                    allow_redirects=True
                )
                self.api_calls += 1

                # Determine if account exists based on response
                found = False
                confidence = 'low'

                if response.status_code == 200:
                    found = True
                    confidence = 'medium'

                    # Higher confidence for API responses
                    if platform['method'] == 'api':
                        try:
                            data = response.json()
                            if data:  # Valid JSON response indicates account exists
                                confidence = 'high'
                        except:
                            pass

                    # Check for profile indicators in HTML
                    elif platform['method'] == 'http':
                        content_lower = response.text.lower()
                        # Look for common profile indicators
                        if any(indicator in content_lower for indicator in ['profile', 'user', 'member', '@' + username.lower()]):
                            confidence = 'medium'
                        else:
                            # Page exists but might not be a profile
                            found = False
                            confidence = 'low'

                elif response.status_code == 404:
                    found = False
                    confidence = 'high'  # High confidence that account doesn't exist

                if found or platform['name'] in ['GitHub', 'Gravatar', 'GitLab']:
                    # Always report GitHub, Gravatar, GitLab for more accurate results
                    social_accounts.append({
                        'platform': platform['name'],
                        'found': found,
                        'url': platform['check_url'],
                        'confidence': confidence
                    })

                # Rate limiting - small delay between requests
                time.sleep(0.2)

            except requests.exceptions.Timeout:
                # Platform didn't respond in time
                social_accounts.append({
                    'platform': platform['name'],
                    'found': False,
                    'url': platform['check_url'],
                    'confidence': 'unknown',
                    'note': 'Timeout'
                })
            except Exception as e:
                # Silently fail for other social media checks
                pass

        return social_accounts

    def check_reputation(self, email: str, domain: str) -> Dict:
        """
        Check email/domain reputation

        Args:
            email (str): Email address
            domain (str): Email domain

        Returns:
            Dict: Reputation information
        """
        reputation = {
            'risk_score': 0,  # 0-100, higher is riskier
            'flags': [],
            'recommendations': []
        }

        # Check disposable email
        disposable_domains = [
            'tempmail.com', 'guerrillamail.com', '10minutemail.com',
            'mailinator.com', 'throwaway.email', 'temp-mail.org'
        ]
        if domain in disposable_domains:
            reputation['risk_score'] += 50
            reputation['flags'].append('Disposable email provider')
            reputation['recommendations'].append('High risk - temporary email service')

        # Check for suspicious patterns
        local_part = email.split('@')[0]

        # Random-looking username (many numbers)
        if sum(c.isdigit() for c in local_part) > len(local_part) * 0.5:
            reputation['risk_score'] += 20
            reputation['flags'].append('Username contains many numbers')

        # Very long local part
        if len(local_part) > 30:
            reputation['risk_score'] += 10
            reputation['flags'].append('Unusually long username')

        # Check breach count
        if len(self.results.get('breaches', [])) > 0:
            breach_count = len(self.results['breaches'])
            if breach_count > 5:
                reputation['risk_score'] += 30
                reputation['flags'].append(f'Found in {breach_count} data breaches')
                reputation['recommendations'].append('High breach exposure - credentials likely compromised')
            elif breach_count > 2:
                reputation['risk_score'] += 15
                reputation['flags'].append(f'Found in {breach_count} data breaches')

        # Determine overall assessment
        if reputation['risk_score'] >= 70:
            reputation['assessment'] = 'HIGH RISK'
        elif reputation['risk_score'] >= 40:
            reputation['assessment'] = 'MEDIUM RISK'
        else:
            reputation['assessment'] = 'LOW RISK'

        return reputation

    def generate_summary(self) -> str:
        """
        Generate a human-readable summary of findings

        Returns:
            str: Investigation summary
        """
        summary = []

        email = self.results.get('email', 'Unknown')
        summary.append(f"Email Investigation: {email}")
        summary.append("=" * 50)

        # Validation
        if self.results['is_valid']:
            summary.append("OK Email is valid and deliverable")
        else:
            summary.append("X Email is invalid or not deliverable")

        # Breaches
        breach_count = len([b for b in self.results.get('breaches', []) if 'error' not in b])
        if breach_count > 0:
            summary.append(f"! Found in {breach_count} data breach(es)")
        else:
            summary.append("OK No known data breaches found")

        # Domain
        domain_info = self.results.get('domain_info', {})
        if domain_info.get('creation_date'):
            summary.append(f"Domain registered: {domain_info['creation_date'][:10]}")

        # Risk assessment
        reputation = self.results.get('reputation', {})
        if reputation:
            summary.append(f"Risk Assessment: {reputation.get('assessment', 'UNKNOWN')}")

        return "\n".join(summary)


def investigate_email(email: str, case_id: str = None) -> Dict:
    """
    Convenience function to investigate an email address

    Args:
        email (str): Email address to investigate
        case_id (str): Optional case ID

    Returns:
        Dict: Investigation results
    """
    osint = EmailOSINT()
    results = osint.investigate(email, case_id)
    return results
