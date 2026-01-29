"""
AbuseIPDB Integration
IP address abuse and reputation database
Free tier: 1,000 requests per day
"""

import requests
import logging
from flask import current_app

logger = logging.getLogger(__name__)


class AbuseIPDB:
    """AbuseIPDB API integration"""

    BASE_URL = 'https://api.abuseipdb.com/api/v2'

    def __init__(self, api_key=None):
        """
        Initialize AbuseIPDB client

        Args:
            api_key (str): AbuseIPDB API key (get free at abuseipdb.com)
        """
        self.api_key = api_key or current_app.config.get('ABUSEIPDB_API_KEY', '')
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({
                'Key': self.api_key,
                'Accept': 'application/json'
            })

    def check_ip(self, ip_address, max_age_days=90):
        """
        Check IP address for abuse reports

        Args:
            ip_address (str): IP address to check
            max_age_days (int): Maximum age of reports to include

        Returns:
            dict: Threat intelligence data
        """
        if not self.api_key:
            return {
                'success': False,
                'error': 'AbuseIPDB API key not configured',
                'source': 'AbuseIPDB'
            }

        try:
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': max_age_days,
                'verbose': ''  # Get detailed report info
            }

            response = self.session.get(
                f"{self.BASE_URL}/check",
                params=params,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            if data.get('errors'):
                return {
                    'success': False,
                    'error': data['errors'][0]['detail'],
                    'source': 'AbuseIPDB'
                }

            ip_data = data.get('data', {})
            abuse_score = ip_data.get('abuseConfidenceScore', 0)
            total_reports = ip_data.get('totalReports', 0)

            # Determine threat level
            if abuse_score >= 75:
                threat_level = 'critical'
            elif abuse_score >= 50:
                threat_level = 'high'
            elif abuse_score >= 25:
                threat_level = 'medium'
            else:
                threat_level = 'low'

            return {
                'success': True,
                'source': 'AbuseIPDB',
                'indicator': ip_address,
                'indicator_type': 'ip_address',
                'found': total_reports > 0,
                'abuse_confidence_score': abuse_score,
                'total_reports': total_reports,
                'num_distinct_users': ip_data.get('numDistinctUsers', 0),
                'last_reported': ip_data.get('lastReportedAt'),
                'is_whitelisted': ip_data.get('isWhitelisted', False),
                'country_code': ip_data.get('countryCode'),
                'usage_type': ip_data.get('usageType'),
                'isp': ip_data.get('isp'),
                'domain': ip_data.get('domain'),
                'threat_level': threat_level,
                'threat_score': abuse_score,
                'reports': ip_data.get('reports', [])[:5],  # Top 5 reports
                'raw_data': data
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"AbuseIPDB API error: {str(e)}")
            return {'success': False, 'error': str(e), 'source': 'AbuseIPDB'}

    def report_ip(self, ip_address, categories, comment=''):
        """
        Report an IP address for abuse (requires API key with report permissions)

        Args:
            ip_address (str): IP address to report
            categories (list): Abuse category IDs (see AbuseIPDB docs)
            comment (str): Optional comment about the abuse

        Returns:
            dict: Report submission result
        """
        if not self.api_key:
            return {
                'success': False,
                'error': 'AbuseIPDB API key not configured'
            }

        try:
            data = {
                'ip': ip_address,
                'categories': ','.join(map(str, categories)),
                'comment': comment
            }

            response = self.session.post(
                f"{self.BASE_URL}/report",
                data=data,
                timeout=10
            )
            response.raise_for_status()
            result = response.json()

            return {
                'success': True,
                'message': 'IP successfully reported to AbuseIPDB',
                'data': result
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"AbuseIPDB report error: {str(e)}")
            return {'success': False, 'error': str(e)}


def check_abuseipdb(ip_address):
    """
    Check IP address against AbuseIPDB

    Args:
        ip_address (str): IP address to check

    Returns:
        dict: Threat intelligence data
    """
    client = AbuseIPDB()
    return client.check_ip(ip_address)
