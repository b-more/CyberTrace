"""
Unified Threat Intelligence Service
Queries all threat intelligence sources and aggregates results
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import current_app
from datetime import datetime

from .alienvault_otx import check_alienvault_otx
from .abuse_ch import check_urlhaus, check_threatfox
from .abuseipdb import check_abuseipdb
from .cisco_talos import check_cisco_talos

logger = logging.getLogger(__name__)


class ThreatIntelligenceService:
    """Unified service to check indicators across all threat intelligence sources"""

    def __init__(self):
        """Initialize the service"""
        self.sources = {
            'alienvault_otx': {
                'name': 'AlienVault OTX',
                'supports': ['ip_address', 'domain', 'url', 'email_address'],
                'check_func': check_alienvault_otx
            },
            'urlhaus': {
                'name': 'URLhaus',
                'supports': ['url', 'domain'],
                'check_func': check_urlhaus
            },
            'threatfox': {
                'name': 'ThreatFox',
                'supports': ['ip_address', 'domain', 'url', 'phone_number', 'email_address'],
                'check_func': lambda indicator, indicator_type: check_threatfox(indicator)
            },
            'abuseipdb': {
                'name': 'AbuseIPDB',
                'supports': ['ip_address'],
                'check_func': lambda indicator, indicator_type: check_abuseipdb(indicator)
            },
            'cisco_talos': {
                'name': 'Cisco Talos',
                'supports': ['ip_address', 'domain', 'email_address'],
                'check_func': check_cisco_talos
            }
        }

    def check_indicator(self, indicator, indicator_type, sources=None, timeout=30):
        """
        Check indicator across multiple threat intelligence sources

        Args:
            indicator (str): Indicator value (IP, domain, email, phone, etc.)
            indicator_type (str): Type of indicator
            sources (list): Specific sources to check (default: all applicable)
            timeout (int): Maximum time to wait for all checks (seconds)

        Returns:
            dict: Aggregated threat intelligence results
        """
        if sources is None:
            # Determine which sources support this indicator type
            sources = [
                source_id for source_id, source_info in self.sources.items()
                if indicator_type in source_info['supports']
            ]

        results = {
            'indicator': indicator,
            'indicator_type': indicator_type,
            'checked_at': datetime.utcnow().isoformat(),
            'sources_checked': [],
            'sources_found': [],
            'total_sources': len(sources),
            'findings': [],
            'threat_score': 0,
            'max_threat_score': 0,
            'avg_threat_score': 0,
            'risk_level': 'unknown',
            'is_malicious': False
        }

        # Query sources in parallel for speed
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_source = {}

            for source_id in sources:
                source_info = self.sources.get(source_id)
                if not source_info:
                    continue

                future = executor.submit(
                    self._check_source,
                    source_id,
                    source_info,
                    indicator,
                    indicator_type
                )
                future_to_source[future] = source_id

            # Collect results as they complete
            for future in as_completed(future_to_source, timeout=timeout):
                source_id = future_to_source[future]
                try:
                    result = future.result()
                    results['sources_checked'].append(source_id)

                    if result and result.get('success') and result.get('found'):
                        results['sources_found'].append(source_id)
                        results['findings'].append(result)

                except Exception as e:
                    logger.error(f"Error checking {source_id}: {str(e)}")
                    results['findings'].append({
                        'success': False,
                        'source': source_id,
                        'error': str(e)
                    })

        # Calculate aggregated threat scores
        threat_scores = [
            finding.get('threat_score', 0)
            for finding in results['findings']
            if finding.get('success') and finding.get('threat_score') is not None
        ]

        if threat_scores:
            results['max_threat_score'] = max(threat_scores)
            results['avg_threat_score'] = sum(threat_scores) / len(threat_scores)
            results['threat_score'] = results['max_threat_score']  # Use max for safety

            # Determine risk level
            if results['threat_score'] >= 80:
                results['risk_level'] = 'critical'
                results['is_malicious'] = True
            elif results['threat_score'] >= 60:
                results['risk_level'] = 'high'
                results['is_malicious'] = True
            elif results['threat_score'] >= 40:
                results['risk_level'] = 'medium'
            elif results['threat_score'] >= 20:
                results['risk_level'] = 'low'
            else:
                results['risk_level'] = 'clean'
        elif len(results['sources_found']) > 0:
            # Found in sources but no threat score
            results['risk_level'] = 'medium'
            results['threat_score'] = 50
        else:
            results['risk_level'] = 'clean'
            results['threat_score'] = 0

        return results

    def _check_source(self, source_id, source_info, indicator, indicator_type):
        """
        Check a single source (internal method)

        Args:
            source_id (str): Source identifier
            source_info (dict): Source configuration
            indicator (str): Indicator value
            indicator_type (str): Indicator type

        Returns:
            dict: Result from the source
        """
        try:
            check_func = source_info['check_func']
            result = check_func(indicator, indicator_type)

            # Add source identifier if not present
            if result and 'source' not in result:
                result['source'] = source_info['name']

            return result

        except Exception as e:
            logger.error(f"Error in {source_id} check: {str(e)}")
            return {
                'success': False,
                'source': source_info['name'],
                'error': str(e)
            }

    def check_phone(self, phone_number):
        """
        Check phone number across threat intelligence sources

        Args:
            phone_number (str): Phone number to check

        Returns:
            dict: Threat intelligence results
        """
        return self.check_indicator(phone_number, 'phone_number')

    def check_email(self, email_address):
        """
        Check email address across threat intelligence sources

        Args:
            email_address (str): Email address to check

        Returns:
            dict: Threat intelligence results
        """
        return self.check_indicator(email_address, 'email_address')

    def check_domain(self, domain):
        """
        Check domain across threat intelligence sources

        Args:
            domain (str): Domain to check

        Returns:
            dict: Threat intelligence results
        """
        return self.check_indicator(domain, 'domain')

    def check_ip(self, ip_address):
        """
        Check IP address across threat intelligence sources

        Args:
            ip_address (str): IP address to check

        Returns:
            dict: Threat intelligence results
        """
        return self.check_indicator(ip_address, 'ip_address')

    def check_url(self, url):
        """
        Check URL across threat intelligence sources

        Args:
            url (str): URL to check

        Returns:
            dict: Threat intelligence results
        """
        return self.check_indicator(url, 'url')

    def get_available_sources(self):
        """
        Get list of available threat intelligence sources

        Returns:
            dict: Source information
        """
        return {
            source_id: {
                'name': info['name'],
                'supports': info['supports']
            }
            for source_id, info in self.sources.items()
        }
