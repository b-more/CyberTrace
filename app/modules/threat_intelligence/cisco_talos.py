"""
Cisco Talos Intelligence Integration
Free email and domain reputation service
"""

import requests
import logging
from bs4 import BeautifulSoup
import re

logger = logging.getLogger(__name__)


class CiscoTalos:
    """Cisco Talos reputation checker"""

    REPUTATION_URL = 'https://talosintelligence.com/reputation_center/lookup'

    @staticmethod
    def check_email_domain(email_or_domain):
        """
        Check email or domain reputation on Cisco Talos

        Args:
            email_or_domain (str): Email address or domain to check

        Returns:
            dict: Reputation data
        """
        try:
            # Extract domain from email if needed
            if '@' in email_or_domain:
                domain = email_or_domain.split('@')[1]
                indicator_type = 'email_address'
            else:
                domain = email_or_domain
                indicator_type = 'domain'

            # Talos doesn't have a public API, we'll use web scraping
            # Note: This is a simplified version. For production, consider rate limiting
            params = {'search': domain}
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }

            response = requests.get(
                CiscoTalos.REPUTATION_URL,
                params=params,
                headers=headers,
                timeout=15
            )
            response.raise_for_status()

            # Parse the response
            soup = BeautifulSoup(response.text, 'html.parser')

            # Look for reputation indicators
            # This is a simplified parser - adjust based on actual page structure
            reputation_text = soup.get_text().lower()

            # Determine reputation
            if 'good' in reputation_text or 'neutral' in reputation_text:
                reputation = 'good'
                threat_score = 10
            elif 'poor' in reputation_text or 'bad' in reputation_text:
                reputation = 'poor'
                threat_score = 80
            elif 'untrusted' in reputation_text:
                reputation = 'untrusted'
                threat_score = 90
            else:
                reputation = 'unknown'
                threat_score = 50

            # Extract email volume category if available
            email_volume = 'unknown'
            if 'high volume' in reputation_text:
                email_volume = 'high'
            elif 'medium volume' in reputation_text:
                email_volume = 'medium'
            elif 'low volume' in reputation_text:
                email_volume = 'low'

            return {
                'success': True,
                'source': 'Cisco Talos',
                'indicator': email_or_domain,
                'indicator_type': indicator_type,
                'domain': domain,
                'reputation': reputation,
                'email_volume': email_volume,
                'threat_score': threat_score,
                'lookup_url': f"{CiscoTalos.REPUTATION_URL}?search={domain}",
                'found': reputation != 'unknown'
            }

        except Exception as e:
            logger.error(f"Cisco Talos check error: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'source': 'Cisco Talos'
            }

    @staticmethod
    def check_ip(ip_address):
        """
        Check IP address reputation on Cisco Talos

        Args:
            ip_address (str): IP address to check

        Returns:
            dict: Reputation data
        """
        try:
            params = {'search': ip_address}
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }

            response = requests.get(
                CiscoTalos.REPUTATION_URL,
                params=params,
                headers=headers,
                timeout=15
            )
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')
            reputation_text = soup.get_text().lower()

            # Determine reputation
            if 'good' in reputation_text or 'neutral' in reputation_text:
                reputation = 'good'
                threat_score = 10
            elif 'poor' in reputation_text or 'bad' in reputation_text:
                reputation = 'poor'
                threat_score = 80
            elif 'untrusted' in reputation_text:
                reputation = 'untrusted'
                threat_score = 90
            else:
                reputation = 'unknown'
                threat_score = 50

            return {
                'success': True,
                'source': 'Cisco Talos',
                'indicator': ip_address,
                'indicator_type': 'ip_address',
                'reputation': reputation,
                'threat_score': threat_score,
                'lookup_url': f"{CiscoTalos.REPUTATION_URL}?search={ip_address}",
                'found': reputation != 'unknown'
            }

        except Exception as e:
            logger.error(f"Cisco Talos IP check error: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'source': 'Cisco Talos'
            }


def check_cisco_talos(indicator, indicator_type):
    """
    Check indicator against Cisco Talos

    Args:
        indicator (str): Indicator value
        indicator_type (str): Type of indicator

    Returns:
        dict: Threat intelligence data
    """
    if indicator_type in ['email_address', 'domain']:
        return CiscoTalos.check_email_domain(indicator)
    elif indicator_type == 'ip_address':
        return CiscoTalos.check_ip(indicator)
    else:
        return {
            'success': False,
            'error': f'Cisco Talos does not support {indicator_type}',
            'source': 'Cisco Talos'
        }
