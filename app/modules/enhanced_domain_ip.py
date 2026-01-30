"""
Enhanced Domain & IP OSINT Module
CyberTrace - Zambia Police Service

Comprehensive domain and IP address investigation toolkit with WHOIS,
DNS enumeration, SSL certificate transparency, subdomain discovery,
typosquatting detection, and Wayback Machine integration.
"""

import re
import time
import socket
import logging
import string
from typing import Dict, List, Optional, Tuple
from datetime import datetime

import dns.resolver
import whois
import requests

logger = logging.getLogger('osint')


class DomainIPOSINT:
    """Enhanced Domain and IP Address OSINT Investigation Tool"""

    def __init__(self):
        self.results = {
            'target': None,
            'target_type': None,
            'whois': {},
            'dns_records': {},
            'ssl_certificates': [],
            'subdomains': [],
            'typosquatting': [],
            'wayback': [],
            'reverse_dns': None,
            'geolocation': {},
            'vpn_proxy': {},
            'reputation': {},
            'metadata': {
                'investigated_at': None,
                'investigation_duration': 0,
                'api_calls_made': 0
            }
        }
        self.start_time = None
        self.api_calls = 0

    def investigate_domain(self, domain: str, case_id: str = None) -> Dict:
        """
        Main orchestrator for domain investigation.

        Args:
            domain: Domain name to investigate
            case_id: Optional case ID to link investigation

        Returns:
            Dict with comprehensive domain investigation results
        """
        self.start_time = time.time()
        domain = domain.lower().strip()
        self.results['target'] = domain
        self.results['target_type'] = 'domain'
        self.results['metadata']['investigated_at'] = datetime.utcnow().isoformat()

        # Step 1: WHOIS Lookup
        try:
            self.results['whois'] = self._whois_lookup(domain)
        except Exception as e:
            logger.error(f"WHOIS lookup failed for {domain}: {e}")
            self.results['whois'] = {'error': str(e)}

        # Step 2: DNS Enumeration
        try:
            self.results['dns_records'] = self._dns_enumeration(domain)
        except Exception as e:
            logger.error(f"DNS enumeration failed for {domain}: {e}")
            self.results['dns_records'] = {'error': str(e)}

        # Step 3: SSL Certificate Transparency
        try:
            self.results['ssl_certificates'] = self._ssl_cert_lookup(domain)
        except Exception as e:
            logger.error(f"SSL cert lookup failed for {domain}: {e}")
            self.results['ssl_certificates'] = []

        # Step 4: Subdomain Discovery from crt.sh
        try:
            self.results['subdomains'] = self._discover_subdomains(domain)
        except Exception as e:
            logger.error(f"Subdomain discovery failed for {domain}: {e}")
            self.results['subdomains'] = []

        # Step 5: Typosquatting Detection
        try:
            self.results['typosquatting'] = self._detect_typosquatting(domain)
        except Exception as e:
            logger.error(f"Typosquatting detection failed for {domain}: {e}")
            self.results['typosquatting'] = []

        # Step 6: Wayback Machine
        try:
            self.results['wayback'] = self._wayback_lookup(domain)
        except Exception as e:
            logger.error(f"Wayback Machine lookup failed for {domain}: {e}")
            self.results['wayback'] = []

        # Finalize metadata
        self.results['metadata']['investigation_duration'] = time.time() - self.start_time
        self.results['metadata']['api_calls_made'] = self.api_calls

        return self.results

    def investigate_ip(self, ip_address: str, case_id: str = None) -> Dict:
        """
        Main orchestrator for IP address investigation.

        Args:
            ip_address: IP address to investigate
            case_id: Optional case ID to link investigation

        Returns:
            Dict with comprehensive IP investigation results
        """
        self.start_time = time.time()
        ip_address = ip_address.strip()
        self.results['target'] = ip_address
        self.results['target_type'] = 'ip'
        self.results['metadata']['investigated_at'] = datetime.utcnow().isoformat()

        # Step 1: Reverse DNS
        try:
            self.results['reverse_dns'] = self._reverse_dns(ip_address)
        except Exception as e:
            logger.error(f"Reverse DNS failed for {ip_address}: {e}")
            self.results['reverse_dns'] = {'error': str(e)}

        # Step 2: Geolocation
        try:
            self.results['geolocation'] = self._geolocate_ip(ip_address)
        except Exception as e:
            logger.error(f"Geolocation failed for {ip_address}: {e}")
            self.results['geolocation'] = {'error': str(e)}

        # Step 3: VPN/Proxy Detection Heuristics
        try:
            self.results['vpn_proxy'] = self._detect_vpn_proxy(ip_address)
        except Exception as e:
            logger.error(f"VPN/Proxy detection failed for {ip_address}: {e}")
            self.results['vpn_proxy'] = {'error': str(e)}

        # Step 4: Reputation Check
        try:
            self.results['reputation'] = self._check_ip_reputation(ip_address)
        except Exception as e:
            logger.error(f"Reputation check failed for {ip_address}: {e}")
            self.results['reputation'] = {'error': str(e)}

        # Finalize metadata
        self.results['metadata']['investigation_duration'] = time.time() - self.start_time
        self.results['metadata']['api_calls_made'] = self.api_calls

        return self.results

    def _whois_lookup(self, domain: str) -> Dict:
        """Perform WHOIS lookup on a domain."""
        info = {
            'domain': domain,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'name_servers': [],
            'registrant': None,
            'registrant_country': None,
            'status': [],
            'dnssec': None,
            'error': None
        }

        try:
            w = whois.whois(domain)

            if w.creation_date:
                cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                info['creation_date'] = cd.isoformat() if cd else None

            if w.expiration_date:
                ed = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                info['expiration_date'] = ed.isoformat() if ed else None

            if w.updated_date:
                ud = w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date
                info['updated_date'] = ud.isoformat() if ud else None

            info['registrar'] = w.registrar
            info['name_servers'] = w.name_servers if w.name_servers else []
            info['registrant_country'] = w.country
            info['dnssec'] = getattr(w, 'dnssec', None)

            if w.status:
                info['status'] = w.status if isinstance(w.status, list) else [w.status]

        except Exception as e:
            info['error'] = f'WHOIS lookup failed: {str(e)}'
            logger.warning(f"WHOIS error for {domain}: {e}")

        return info

    def _dns_enumeration(self, domain: str) -> Dict:
        """Enumerate DNS records for a domain (A, AAAA, MX, NS, TXT, CNAME, SOA)."""
        records = {
            'a': [],
            'aaaa': [],
            'mx': [],
            'ns': [],
            'txt': [],
            'cname': [],
            'soa': None,
            'errors': []
        }

        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                key = rtype.lower()

                if rtype == 'A':
                    records['a'] = [str(r) for r in answers]
                elif rtype == 'AAAA':
                    records['aaaa'] = [str(r) for r in answers]
                elif rtype == 'MX':
                    records['mx'] = [
                        {'priority': r.preference, 'server': str(r.exchange)}
                        for r in answers
                    ]
                elif rtype == 'NS':
                    records['ns'] = [str(r) for r in answers]
                elif rtype == 'TXT':
                    records['txt'] = [str(r).strip('"') for r in answers]
                elif rtype == 'CNAME':
                    records['cname'] = [str(r) for r in answers]
                elif rtype == 'SOA':
                    soa = answers[0]
                    records['soa'] = {
                        'mname': str(soa.mname),
                        'rname': str(soa.rname),
                        'serial': soa.serial,
                        'refresh': soa.refresh,
                        'retry': soa.retry,
                        'expire': soa.expire,
                        'minimum': soa.minimum
                    }
            except dns.resolver.NoAnswer:
                pass  # Record type not available, not an error
            except dns.resolver.NXDOMAIN:
                records['errors'].append(f'Domain {domain} does not exist')
                break
            except dns.resolver.NoNameservers:
                records['errors'].append(f'No nameservers available for {rtype}')
            except Exception as e:
                records['errors'].append(f'{rtype} lookup failed: {str(e)}')

        return records

    def _ssl_cert_lookup(self, domain: str) -> List[Dict]:
        """Query crt.sh for SSL certificate transparency logs."""
        certs = []

        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            headers = {'User-Agent': 'CyberTrace-ZambiaPolice'}
            response = requests.get(url, headers=headers, timeout=15)
            self.api_calls += 1

            if response.status_code == 200:
                data = response.json()
                seen = set()
                for entry in data[:100]:  # Limit to 100 entries
                    cert_id = entry.get('id')
                    if cert_id in seen:
                        continue
                    seen.add(cert_id)
                    certs.append({
                        'id': cert_id,
                        'issuer_name': entry.get('issuer_name', ''),
                        'common_name': entry.get('common_name', ''),
                        'name_value': entry.get('name_value', ''),
                        'not_before': entry.get('not_before', ''),
                        'not_after': entry.get('not_after', ''),
                        'serial_number': entry.get('serial_number', '')
                    })
        except requests.exceptions.RequestException as e:
            logger.warning(f"crt.sh request failed for {domain}: {e}")
        except ValueError as e:
            logger.warning(f"crt.sh JSON parse error for {domain}: {e}")

        return certs

    def _discover_subdomains(self, domain: str) -> List[Dict]:
        """Discover subdomains from crt.sh certificate transparency data."""
        subdomains = []
        seen = set()

        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            headers = {'User-Agent': 'CyberTrace-ZambiaPolice'}
            response = requests.get(url, headers=headers, timeout=15)
            self.api_calls += 1

            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    # crt.sh can return newline-separated names
                    names = name_value.split('\n')
                    for name in names:
                        name = name.strip().lower()
                        if name and name.endswith(f'.{domain}') and name not in seen:
                            seen.add(name)
                            # Try to resolve the subdomain
                            resolved_ip = None
                            try:
                                resolved_ip = socket.gethostbyname(name)
                            except socket.gaierror:
                                pass

                            subdomains.append({
                                'subdomain': name,
                                'resolved_ip': resolved_ip,
                                'active': resolved_ip is not None
                            })
        except requests.exceptions.RequestException as e:
            logger.warning(f"Subdomain discovery request failed for {domain}: {e}")
        except ValueError as e:
            logger.warning(f"Subdomain discovery JSON parse error for {domain}: {e}")

        return subdomains

    def _detect_typosquatting(self, domain: str) -> List[Dict]:
        """Generate common typosquatting variants and check if they resolve."""
        typos = []
        parts = domain.rsplit('.', 1)
        if len(parts) != 2:
            return typos

        name, tld = parts[0], parts[1]
        variants = set()

        # Character omission
        for i in range(len(name)):
            variant = name[:i] + name[i + 1:]
            if variant:
                variants.add(f"{variant}.{tld}")

        # Adjacent character swap
        for i in range(len(name) - 1):
            swapped = list(name)
            swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
            variants.add(f"{''.join(swapped)}.{tld}")

        # Character duplication
        for i in range(len(name)):
            doubled = name[:i] + name[i] + name[i:]
            variants.add(f"{doubled}.{tld}")

        # Common character substitution
        substitutions = {
            'o': '0', '0': 'o', 'l': '1', '1': 'l', 'i': '1',
            'e': '3', 'a': '4', 's': '5', 'g': '9', 'b': '6',
            'rn': 'm', 'vv': 'w', 'cl': 'd'
        }
        for orig, repl in substitutions.items():
            if orig in name:
                variants.add(f"{name.replace(orig, repl, 1)}.{tld}")

        # Common TLD swaps
        alt_tlds = ['com', 'net', 'org', 'co', 'io', 'info', 'biz']
        for alt_tld in alt_tlds:
            if alt_tld != tld:
                variants.add(f"{name}.{alt_tld}")

        # Remove the original domain from variants
        variants.discard(domain)

        # Check resolution for a limited set
        checked = 0
        for variant in list(variants)[:30]:
            try:
                ip = socket.gethostbyname(variant)
                typos.append({
                    'variant': variant,
                    'resolves': True,
                    'resolved_ip': ip,
                    'risk': 'high'
                })
            except socket.gaierror:
                typos.append({
                    'variant': variant,
                    'resolves': False,
                    'resolved_ip': None,
                    'risk': 'low'
                })
            checked += 1
            if checked >= 30:
                break

        return typos

    def _wayback_lookup(self, domain: str) -> List[Dict]:
        """Query the Wayback Machine CDX API for historical snapshots."""
        snapshots = []

        try:
            url = f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=50"
            headers = {'User-Agent': 'CyberTrace-ZambiaPolice'}
            response = requests.get(url, headers=headers, timeout=15)
            self.api_calls += 1

            if response.status_code == 200:
                data = response.json()
                if data and len(data) > 1:
                    # First row is the header
                    headers_row = data[0]
                    for row in data[1:]:
                        entry = dict(zip(headers_row, row))
                        snapshots.append({
                            'timestamp': entry.get('timestamp', ''),
                            'original_url': entry.get('original', ''),
                            'mime_type': entry.get('mimetype', ''),
                            'status_code': entry.get('statuscode', ''),
                            'digest': entry.get('digest', ''),
                            'length': entry.get('length', ''),
                            'archive_url': f"https://web.archive.org/web/{entry.get('timestamp', '')}/{entry.get('original', '')}"
                        })
        except requests.exceptions.RequestException as e:
            logger.warning(f"Wayback Machine request failed for {domain}: {e}")
        except ValueError as e:
            logger.warning(f"Wayback Machine JSON parse error for {domain}: {e}")

        return snapshots

    def _reverse_dns(self, ip_address: str) -> Dict:
        """Perform reverse DNS lookup on an IP address."""
        result = {
            'ip': ip_address,
            'hostname': None,
            'error': None
        }

        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            result['hostname'] = hostname
        except socket.herror as e:
            result['error'] = f'No reverse DNS entry: {str(e)}'
        except Exception as e:
            result['error'] = f'Reverse DNS failed: {str(e)}'

        return result

    def _geolocate_ip(self, ip_address: str) -> Dict:
        """Geolocate an IP address using socket and geopy."""
        geo = {
            'ip': ip_address,
            'hostname': None,
            'latitude': None,
            'longitude': None,
            'country': None,
            'city': None,
            'region': None,
            'isp': None,
            'error': None
        }

        try:
            # Try hostname resolution
            try:
                geo['hostname'] = socket.gethostbyaddr(ip_address)[0]
            except socket.herror:
                pass

            # Use ip-api.com for geolocation (free, no key required)
            url = f"http://ip-api.com/json/{ip_address}"
            response = requests.get(url, timeout=10)
            self.api_calls += 1

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    geo['latitude'] = data.get('lat')
                    geo['longitude'] = data.get('lon')
                    geo['country'] = data.get('country')
                    geo['city'] = data.get('city')
                    geo['region'] = data.get('regionName')
                    geo['isp'] = data.get('isp')

                    # Reverse geocode for location name if geopy available
                    try:
                        from geopy.geocoders import Nominatim
                        if geo['latitude'] and geo['longitude']:
                            geolocator = Nominatim(user_agent='CyberTrace-ZambiaPolice')
                            location = geolocator.reverse(
                                f"{geo['latitude']}, {geo['longitude']}",
                                timeout=5
                            )
                            if location:
                                geo['location_name'] = location.address
                    except ImportError:
                        logger.debug("geopy not available for reverse geocoding")
                    except Exception as e:
                        logger.debug(f"Reverse geocoding failed: {e}")
        except requests.exceptions.RequestException as e:
            geo['error'] = f'Geolocation request failed: {str(e)}'
        except Exception as e:
            geo['error'] = f'Geolocation failed: {str(e)}'

        return geo

    def _detect_vpn_proxy(self, ip_address: str) -> Dict:
        """Detect VPN/proxy heuristics for an IP address."""
        vpn_info = {
            'is_vpn': False,
            'is_proxy': False,
            'is_tor': False,
            'is_datacenter': False,
            'confidence': 'low',
            'indicators': [],
            'error': None
        }

        try:
            # Heuristic: Check reverse DNS for VPN/proxy keywords
            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
                hostname_lower = hostname.lower()

                vpn_keywords = ['vpn', 'proxy', 'tor', 'exit', 'relay', 'node',
                                'tunnel', 'anonymo', 'private', 'hide', 'mask']

                datacenter_keywords = ['aws', 'amazon', 'azure', 'google', 'cloud',
                                       'digitalocean', 'linode', 'vultr', 'ovh',
                                       'hetzner', 'datacenter', 'hosting']

                for kw in vpn_keywords:
                    if kw in hostname_lower:
                        vpn_info['is_vpn'] = True
                        vpn_info['indicators'].append(f'Hostname contains VPN keyword: {kw}')

                if 'tor' in hostname_lower or 'exit' in hostname_lower:
                    vpn_info['is_tor'] = True
                    vpn_info['indicators'].append('Hostname suggests Tor exit node')

                for kw in datacenter_keywords:
                    if kw in hostname_lower:
                        vpn_info['is_datacenter'] = True
                        vpn_info['indicators'].append(f'Hostname suggests datacenter: {kw}')

            except socket.herror:
                vpn_info['indicators'].append('No reverse DNS (common for VPNs)')

            # Set confidence based on number of indicators
            if len(vpn_info['indicators']) >= 2:
                vpn_info['confidence'] = 'high'
            elif len(vpn_info['indicators']) == 1:
                vpn_info['confidence'] = 'medium'

        except Exception as e:
            vpn_info['error'] = f'VPN/Proxy detection failed: {str(e)}'

        return vpn_info

    def _check_ip_reputation(self, ip_address: str) -> Dict:
        """Check IP reputation (placeholder with basic heuristics)."""
        reputation = {
            'risk_score': 0,
            'flags': [],
            'assessment': 'UNKNOWN',
            'error': None
        }

        try:
            # Basic checks
            if ip_address.startswith('10.') or ip_address.startswith('192.168.') or ip_address.startswith('172.'):
                reputation['flags'].append('Private/internal IP address')
                reputation['risk_score'] = 0
                reputation['assessment'] = 'PRIVATE'
                return reputation

            # Check VPN/proxy results
            vpn = self.results.get('vpn_proxy', {})
            if vpn.get('is_tor'):
                reputation['risk_score'] += 40
                reputation['flags'].append('Tor exit node detected')
            if vpn.get('is_vpn'):
                reputation['risk_score'] += 25
                reputation['flags'].append('VPN detected')
            if vpn.get('is_datacenter'):
                reputation['risk_score'] += 15
                reputation['flags'].append('Datacenter IP')

            # Determine assessment
            if reputation['risk_score'] >= 60:
                reputation['assessment'] = 'HIGH RISK'
            elif reputation['risk_score'] >= 30:
                reputation['assessment'] = 'MEDIUM RISK'
            else:
                reputation['assessment'] = 'LOW RISK'

        except Exception as e:
            reputation['error'] = f'Reputation check failed: {str(e)}'

        return reputation


def investigate_domain(domain: str, case_id: str = None) -> Dict:
    """
    Convenience function to investigate a domain.

    Args:
        domain: Domain name to investigate
        case_id: Optional case ID

    Returns:
        Dict with investigation results
    """
    osint = DomainIPOSINT()
    return osint.investigate_domain(domain, case_id)


def investigate_ip(ip_address: str, case_id: str = None) -> Dict:
    """
    Convenience function to investigate an IP address.

    Args:
        ip_address: IP address to investigate
        case_id: Optional case ID

    Returns:
        Dict with investigation results
    """
    osint = DomainIPOSINT()
    return osint.investigate_ip(ip_address, case_id)
