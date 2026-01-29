"""
AlienVault OTX (Open Threat Exchange) Integration
Free threat intelligence from AlienVault
"""

import requests
import logging
from flask import current_app

logger = logging.getLogger(__name__)


class AlienVaultOTX:
    """AlienVault OTX API integration"""

    BASE_URL = 'https://otx.alienvault.com/api/v1'

    def __init__(self, api_key=None):
        """
        Initialize AlienVault OTX client

        Args:
            api_key (str): OTX API key (get free at otx.alienvault.com)
        """
        self.api_key = api_key or current_app.config.get('ALIENVAULT_OTX_API_KEY', '')
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({'X-OTX-API-KEY': self.api_key})

    def _make_request(self, endpoint, timeout=10):
        """
        Make API request to OTX

        Args:
            endpoint (str): API endpoint
            timeout (int): Request timeout in seconds

        Returns:
            dict: API response or error
        """
        try:
            url = f"{self.BASE_URL}/{endpoint}"
            response = self.session.get(url, timeout=timeout)
            response.raise_for_status()
            return {'success': True, 'data': response.json()}
        except requests.exceptions.RequestException as e:
            logger.error(f"AlienVault OTX API error: {str(e)}")
            return {'success': False, 'error': str(e)}

    def check_ip(self, ip_address):
        """
        Check IP address reputation

        Args:
            ip_address (str): IP address to check

        Returns:
            dict: Threat intelligence data
        """
        endpoint = f"indicators/IPv4/{ip_address}/general"
        result = self._make_request(endpoint)

        if not result['success']:
            return result

        data = result['data']

        return {
            'success': True,
            'source': 'AlienVault OTX',
            'indicator': ip_address,
            'indicator_type': 'ip_address',
            'found': data.get('pulse_info', {}).get('count', 0) > 0,
            'pulse_count': data.get('pulse_info', {}).get('count', 0),
            'pulses': data.get('pulse_info', {}).get('pulses', [])[:5],  # Top 5 pulses
            'reputation': data.get('reputation', 0),
            'country': data.get('country_name'),
            'asn': data.get('asn'),
            'tags': [pulse.get('name') for pulse in data.get('pulse_info', {}).get('pulses', [])[:5]],
            'threat_score': min(data.get('pulse_info', {}).get('count', 0) * 10, 100),
            'raw_data': data
        }

    def check_domain(self, domain):
        """
        Check domain reputation

        Args:
            domain (str): Domain to check

        Returns:
            dict: Threat intelligence data
        """
        endpoint = f"indicators/domain/{domain}/general"
        result = self._make_request(endpoint)

        if not result['success']:
            return result

        data = result['data']

        return {
            'success': True,
            'source': 'AlienVault OTX',
            'indicator': domain,
            'indicator_type': 'domain',
            'found': data.get('pulse_info', {}).get('count', 0) > 0,
            'pulse_count': data.get('pulse_info', {}).get('count', 0),
            'pulses': data.get('pulse_info', {}).get('pulses', [])[:5],
            'alexa_rank': data.get('alexa'),
            'tags': [pulse.get('name') for pulse in data.get('pulse_info', {}).get('pulses', [])[:5]],
            'threat_score': min(data.get('pulse_info', {}).get('count', 0) * 10, 100),
            'raw_data': data
        }

    def check_url(self, url):
        """
        Check URL reputation

        Args:
            url (str): URL to check

        Returns:
            dict: Threat intelligence data
        """
        endpoint = f"indicators/url/{url}/general"
        result = self._make_request(endpoint)

        if not result['success']:
            return result

        data = result['data']

        return {
            'success': True,
            'source': 'AlienVault OTX',
            'indicator': url,
            'indicator_type': 'url',
            'found': data.get('pulse_info', {}).get('count', 0) > 0,
            'pulse_count': data.get('pulse_info', {}).get('count', 0),
            'pulses': data.get('pulse_info', {}).get('pulses', [])[:5],
            'tags': [pulse.get('name') for pulse in data.get('pulse_info', {}).get('pulses', [])[:5]],
            'threat_score': min(data.get('pulse_info', {}).get('count', 0) * 10, 100),
            'raw_data': data
        }

    def check_email(self, email):
        """
        Check email address in threat intelligence

        Args:
            email (str): Email address to check

        Returns:
            dict: Threat intelligence data
        """
        # OTX doesn't have direct email lookup, search in pulses
        try:
            endpoint = f"search/pulses?q={email}"
            result = self._make_request(endpoint)

            if not result['success']:
                return result

            data = result['data']
            results = data.get('results', [])

            return {
                'success': True,
                'source': 'AlienVault OTX',
                'indicator': email,
                'indicator_type': 'email',
                'found': len(results) > 0,
                'pulse_count': len(results),
                'pulses': results[:5],
                'tags': [pulse.get('name') for pulse in results[:5]],
                'threat_score': min(len(results) * 15, 100),
                'raw_data': data
            }
        except Exception as e:
            logger.error(f"OTX email check error: {str(e)}")
            return {'success': False, 'error': str(e)}


def check_alienvault_otx(indicator, indicator_type):
    """
    Check indicator against AlienVault OTX

    Args:
        indicator (str): Indicator value (IP, domain, email, etc.)
        indicator_type (str): Type of indicator

    Returns:
        dict: Threat intelligence data
    """
    otx = AlienVaultOTX()

    if not otx.api_key:
        return {
            'success': False,
            'error': 'AlienVault OTX API key not configured',
            'source': 'AlienVault OTX'
        }

    if indicator_type == 'ip_address':
        return otx.check_ip(indicator)
    elif indicator_type == 'domain':
        return otx.check_domain(indicator)
    elif indicator_type == 'url':
        return otx.check_url(indicator)
    elif indicator_type == 'email_address':
        return otx.check_email(indicator)
    else:
        return {
            'success': False,
            'error': f'Unsupported indicator type: {indicator_type}',
            'source': 'AlienVault OTX'
        }
