"""
Abuse.ch Integration (URLhaus, ThreatFox)
Free malware and threat intelligence
"""

import requests
import logging

logger = logging.getLogger(__name__)


class URLhaus:
    """URLhaus API integration - malicious URL database"""

    BASE_URL = 'https://urlhaus-api.abuse.ch/v1'

    @staticmethod
    def check_url(url):
        """
        Check if URL is malicious

        Args:
            url (str): URL to check

        Returns:
            dict: Threat intelligence data
        """
        try:
            response = requests.post(
                f"{URLhaus.BASE_URL}/url/",
                data={'url': url},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            if data.get('query_status') == 'no_results':
                return {
                    'success': True,
                    'source': 'URLhaus',
                    'indicator': url,
                    'indicator_type': 'url',
                    'found': False,
                    'threat_score': 0
                }

            return {
                'success': True,
                'source': 'URLhaus',
                'indicator': url,
                'indicator_type': 'url',
                'found': True,
                'status': data.get('url_status'),
                'threat': data.get('threat'),
                'tags': data.get('tags', []),
                'date_added': data.get('date_added'),
                'reporter': data.get('reporter'),
                'threat_score': 95 if data.get('url_status') == 'online' else 70,
                'raw_data': data
            }

        except Exception as e:
            logger.error(f"URLhaus API error: {str(e)}")
            return {'success': False, 'error': str(e), 'source': 'URLhaus'}

    @staticmethod
    def check_domain(domain):
        """
        Check if domain hosts malicious URLs

        Args:
            domain (str): Domain to check

        Returns:
            dict: Threat intelligence data
        """
        try:
            response = requests.post(
                f"{URLhaus.BASE_URL}/host/",
                data={'host': domain},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            if data.get('query_status') == 'no_results':
                return {
                    'success': True,
                    'source': 'URLhaus',
                    'indicator': domain,
                    'indicator_type': 'domain',
                    'found': False,
                    'threat_score': 0
                }

            urls = data.get('urls', [])
            active_urls = [url for url in urls if url.get('url_status') == 'online']

            return {
                'success': True,
                'source': 'URLhaus',
                'indicator': domain,
                'indicator_type': 'domain',
                'found': True,
                'url_count': data.get('url_count', 0),
                'active_urls': len(active_urls),
                'blacklists': data.get('blacklists', {}),
                'urls': urls[:5],  # First 5 malicious URLs
                'threat_score': min(len(active_urls) * 20 + 40, 100),
                'raw_data': data
            }

        except Exception as e:
            logger.error(f"URLhaus domain check error: {str(e)}")
            return {'success': False, 'error': str(e), 'source': 'URLhaus'}


class ThreatFox:
    """ThreatFox API integration - IOC database"""

    BASE_URL = 'https://threatfox-api.abuse.ch/api/v1/'

    @staticmethod
    def search_ioc(ioc_value):
        """
        Search for Indicator of Compromise

        Args:
            ioc_value (str): IOC to search for

        Returns:
            dict: Threat intelligence data
        """
        try:
            response = requests.post(
                ThreatFox.BASE_URL,
                json={'query': 'search_ioc', 'search_term': ioc_value},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            if data.get('query_status') == 'no_result':
                return {
                    'success': True,
                    'source': 'ThreatFox',
                    'indicator': ioc_value,
                    'found': False,
                    'threat_score': 0
                }

            iocs = data.get('data', [])
            if not iocs:
                return {
                    'success': True,
                    'source': 'ThreatFox',
                    'indicator': ioc_value,
                    'found': False,
                    'threat_score': 0
                }

            first_ioc = iocs[0]

            return {
                'success': True,
                'source': 'ThreatFox',
                'indicator': ioc_value,
                'indicator_type': first_ioc.get('ioc_type'),
                'found': True,
                'threat_type': first_ioc.get('threat_type'),
                'malware': first_ioc.get('malware'),
                'confidence_level': first_ioc.get('confidence_level'),
                'tags': first_ioc.get('tags', []),
                'date_added': first_ioc.get('first_seen'),
                'reporter': first_ioc.get('reporter'),
                'ioc_count': len(iocs),
                'threat_score': 90 if first_ioc.get('confidence_level') == 100 else 75,
                'raw_data': data
            }

        except Exception as e:
            logger.error(f"ThreatFox API error: {str(e)}")
            return {'success': False, 'error': str(e), 'source': 'ThreatFox'}


def check_urlhaus(indicator, indicator_type):
    """
    Check indicator against URLhaus

    Args:
        indicator (str): Indicator value
        indicator_type (str): Type of indicator (url, domain)

    Returns:
        dict: Threat intelligence data
    """
    if indicator_type == 'url':
        return URLhaus.check_url(indicator)
    elif indicator_type == 'domain':
        return URLhaus.check_domain(indicator)
    else:
        return {
            'success': False,
            'error': f'URLhaus does not support {indicator_type}',
            'source': 'URLhaus'
        }


def check_threatfox(indicator):
    """
    Check indicator against ThreatFox

    Args:
        indicator (str): Indicator value (any type)

    Returns:
        dict: Threat intelligence data
    """
    return ThreatFox.search_ioc(indicator)
