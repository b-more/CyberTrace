"""
Correlation Engine Module
CyberTrace - Zambia Police Service

Cross-case indicator correlation engine that extracts investigative
indicators from cases, finds matches across investigations, builds
network graphs, and calculates confidence scores.
"""

import re
import json
import time
import logging
from typing import Dict, List, Optional
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger('osint')


class CorrelationEngine:
    """Cross-Case Indicator Correlation Engine"""

    def __init__(self):
        self.results = {
            'indicators_extracted': 0,
            'matches_found': 0,
            'matches': [],
            'network_graph': {'nodes': [], 'edges': []},
            'correlation_summary': {},
            'metadata': {
                'analyzed_at': None,
                'analysis_duration': 0,
                'api_calls_made': 0
            }
        }
        self.start_time = None
        self.api_calls = 0

    def extract_indicators_from_investigation(self, investigation) -> List[Dict]:
        """
        Extract investigative indicators from an investigation record's
        processed_results JSON.

        Args:
            investigation: Investigation object or dict with processed_results

        Returns:
            List of extracted indicator dicts
        """
        indicators = []

        try:
            # Get processed results - handle both object and dict
            if hasattr(investigation, 'processed_results'):
                raw = investigation.processed_results
            elif isinstance(investigation, dict):
                raw = investigation.get('processed_results', '{}')
            else:
                return indicators

            if isinstance(raw, str):
                try:
                    data = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    return indicators
            elif isinstance(raw, dict):
                data = raw
            else:
                return indicators

            # Get case_id and investigation_id
            case_id = None
            investigation_id = None
            if hasattr(investigation, 'case_id'):
                case_id = investigation.case_id
            elif isinstance(investigation, dict):
                case_id = investigation.get('case_id')

            if hasattr(investigation, 'id'):
                investigation_id = investigation.id
            elif isinstance(investigation, dict):
                investigation_id = investigation.get('id')

            # Regex patterns for indicator types
            patterns = {
                'phone': re.compile(r'(?:\+?260|0)\d{9}|\+?\d{10,15}'),
                'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
                'ip_address': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
                'domain': re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'),
                'btc_address': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
                'eth_address': re.compile(r'\b0x[0-9a-fA-F]{40}\b'),
                'username': re.compile(r'@[a-zA-Z0-9_]{3,30}'),
            }

            # Convert data to string for extraction
            data_str = json.dumps(data) if isinstance(data, dict) else str(data)

            # Also check specific known fields
            indicator_fields = self._extract_from_fields(data, case_id, investigation_id)
            indicators.extend(indicator_fields)

            # Regex extraction from full text
            seen = set()
            for ind_type, pattern in patterns.items():
                for match in pattern.finditer(data_str):
                    value = match.group()
                    key = f"{ind_type}:{value}"
                    if key not in seen:
                        seen.add(key)
                        indicators.append({
                            'indicator_type': ind_type,
                            'indicator_value': value,
                            'case_id': case_id,
                            'investigation_id': investigation_id,
                            'source': 'regex_extraction',
                            'extracted_at': datetime.utcnow().isoformat()
                        })

            self.results['indicators_extracted'] = len(indicators)

        except Exception as e:
            logger.error(f"Indicator extraction failed: {e}")

        return indicators

    def _extract_from_fields(self, data: Dict, case_id, investigation_id) -> List[Dict]:
        """Extract indicators from known structured fields."""
        indicators = []
        seen = set()

        def add_indicator(ind_type, value, source='field_extraction'):
            if value and isinstance(value, str) and value.strip():
                key = f"{ind_type}:{value.strip()}"
                if key not in seen:
                    seen.add(key)
                    indicators.append({
                        'indicator_type': ind_type,
                        'indicator_value': value.strip(),
                        'case_id': case_id,
                        'investigation_id': investigation_id,
                        'source': source,
                        'extracted_at': datetime.utcnow().isoformat()
                    })

        # Email investigation results
        if 'email' in data:
            add_indicator('email', data.get('email'))

        # Phone results
        if 'phone_number' in data:
            add_indicator('phone', data.get('phone_number'))

        # Domain/IP results
        if 'target' in data:
            target_type = data.get('target_type', '')
            if target_type == 'domain':
                add_indicator('domain', data.get('target'))
            elif target_type == 'ip':
                add_indicator('ip_address', data.get('target'))

        # Crypto results
        if 'address' in data and data.get('chain'):
            chain = data.get('chain', '')
            if chain == 'btc':
                add_indicator('btc_address', data.get('address'))
            elif chain == 'eth':
                add_indicator('eth_address', data.get('address'))
            else:
                add_indicator('crypto_address', data.get('address'))

        # Social media accounts
        for account in data.get('social_media', []):
            if account.get('found') and account.get('url'):
                add_indicator('username', account.get('url'), 'social_media')

        # DNS records - IPs
        dns = data.get('dns_records', {})
        for ip in dns.get('a', []):
            add_indicator('ip_address', ip, 'dns_records')

        # Subdomains
        for sub in data.get('subdomains', []):
            if sub.get('subdomain'):
                add_indicator('domain', sub['subdomain'], 'subdomain_discovery')

        return indicators

    def find_matches(self, case_id: str = None) -> List[Dict]:
        """
        Find matching indicators across different cases using the database.

        Args:
            case_id: Optional case ID to focus the search

        Returns:
            List of match dicts with shared indicators
        """
        self.start_time = time.time()
        self.results['metadata']['analyzed_at'] = datetime.utcnow().isoformat()
        matches = []

        try:
            from app import db
            from app.models import CorrelationIndicator

            if case_id:
                # Find indicators for this case, then look for same values in other cases
                case_indicators = CorrelationIndicator.query.filter_by(
                    case_id=case_id
                ).all()

                for indicator in case_indicators:
                    # Find same indicator value in other cases
                    other_matches = CorrelationIndicator.query.filter(
                        CorrelationIndicator.indicator_value == indicator.indicator_value,
                        CorrelationIndicator.case_id != case_id
                    ).all()

                    for other in other_matches:
                        matches.append({
                            'indicator_type': indicator.indicator_type,
                            'indicator_value': indicator.indicator_value,
                            'case_1': case_id,
                            'case_2': other.case_id,
                            'investigation_1': indicator.investigation_id,
                            'investigation_2': other.investigation_id,
                            'confidence': self.calculate_confidence(
                                indicator.indicator_type,
                                CorrelationIndicator.query.filter_by(
                                    indicator_value=indicator.indicator_value
                                ).count()
                            ),
                            'found_at': datetime.utcnow().isoformat()
                        })
            else:
                # Global correlation: find all indicators appearing in multiple cases
                from sqlalchemy import func

                # Group by indicator value and find those with multiple cases
                duplicates = db.session.query(
                    CorrelationIndicator.indicator_value,
                    CorrelationIndicator.indicator_type,
                    func.count(func.distinct(CorrelationIndicator.case_id)).label('case_count')
                ).group_by(
                    CorrelationIndicator.indicator_value,
                    CorrelationIndicator.indicator_type
                ).having(
                    func.count(func.distinct(CorrelationIndicator.case_id)) > 1
                ).all()

                for dup in duplicates:
                    # Get all cases with this indicator
                    related = CorrelationIndicator.query.filter_by(
                        indicator_value=dup.indicator_value
                    ).all()

                    case_ids = list(set(r.case_id for r in related if r.case_id))

                    matches.append({
                        'indicator_type': dup.indicator_type,
                        'indicator_value': dup.indicator_value,
                        'cases': case_ids,
                        'case_count': dup.case_count,
                        'confidence': self.calculate_confidence(
                            dup.indicator_type, dup.case_count
                        ),
                        'found_at': datetime.utcnow().isoformat()
                    })

        except ImportError:
            logger.error("Database modules not available for correlation")
            matches = []
        except Exception as e:
            logger.error(f"Correlation matching failed: {e}")
            matches = []

        self.results['matches'] = matches
        self.results['matches_found'] = len(matches)

        # Build network graph
        try:
            self.results['network_graph'] = self.build_network_graph(matches)
        except Exception as e:
            logger.error(f"Network graph build failed: {e}")

        self.results['metadata']['analysis_duration'] = time.time() - self.start_time
        self.results['metadata']['api_calls_made'] = self.api_calls

        return matches

    def build_network_graph(self, matches: List[Dict]) -> Dict:
        """
        Build a D3.js-compatible network graph from correlation matches.

        Args:
            matches: List of match dicts

        Returns:
            Dict with nodes (cases) and edges (shared indicators)
        """
        nodes = {}
        edges = []
        edge_set = set()

        for match in matches:
            # Handle per-case-pair matches
            if 'case_1' in match and 'case_2' in match:
                case_1 = str(match['case_1'])
                case_2 = str(match['case_2'])

                if case_1 not in nodes:
                    nodes[case_1] = {
                        'id': case_1,
                        'label': f'Case {case_1}',
                        'type': 'case',
                        'group': 0,
                        'connections': 0
                    }

                if case_2 not in nodes:
                    nodes[case_2] = {
                        'id': case_2,
                        'label': f'Case {case_2}',
                        'type': 'case',
                        'group': 1,
                        'connections': 0
                    }

                edge_key = tuple(sorted([case_1, case_2]))
                if edge_key not in edge_set:
                    edge_set.add(edge_key)
                    edges.append({
                        'source': case_1,
                        'target': case_2,
                        'indicator_type': match.get('indicator_type', ''),
                        'indicator_value': match.get('indicator_value', ''),
                        'confidence': match.get('confidence', 0)
                    })

                nodes[case_1]['connections'] += 1
                nodes[case_2]['connections'] += 1

            # Handle multi-case matches
            elif 'cases' in match:
                case_ids = [str(c) for c in match['cases']]
                for cid in case_ids:
                    if cid not in nodes:
                        nodes[cid] = {
                            'id': cid,
                            'label': f'Case {cid}',
                            'type': 'case',
                            'group': 0,
                            'connections': 0
                        }

                # Create edges between all pairs
                for i in range(len(case_ids)):
                    for j in range(i + 1, len(case_ids)):
                        edge_key = tuple(sorted([case_ids[i], case_ids[j]]))
                        if edge_key not in edge_set:
                            edge_set.add(edge_key)
                            edges.append({
                                'source': case_ids[i],
                                'target': case_ids[j],
                                'indicator_type': match.get('indicator_type', ''),
                                'indicator_value': match.get('indicator_value', ''),
                                'confidence': match.get('confidence', 0)
                            })
                            nodes[case_ids[i]]['connections'] += 1
                            nodes[case_ids[j]]['connections'] += 1

        return {
            'nodes': list(nodes.values()),
            'edges': edges
        }

    def calculate_confidence(self, indicator_type: str, match_count: int) -> float:
        """
        Calculate correlation confidence based on indicator type and match count.

        Higher confidence for more unique indicator types (e.g., crypto addresses).
        Lower confidence for common indicators (e.g., domains).

        Args:
            indicator_type: Type of the indicator
            match_count: Number of cases sharing this indicator

        Returns:
            Float confidence score 0.0-1.0
        """
        # Base confidence by indicator type uniqueness
        type_weights = {
            'btc_address': 0.95,
            'eth_address': 0.95,
            'crypto_address': 0.90,
            'email': 0.85,
            'phone': 0.80,
            'username': 0.70,
            'ip_address': 0.60,
            'domain': 0.40,
        }

        base = type_weights.get(indicator_type, 0.50)

        # Adjust based on match count (more matches = slightly higher confidence)
        if match_count >= 5:
            multiplier = 1.0
        elif match_count >= 3:
            multiplier = 0.95
        elif match_count >= 2:
            multiplier = 0.90
        else:
            multiplier = 0.80

        confidence = min(base * multiplier, 1.0)
        return round(confidence, 2)


def run_correlation(case_id: str = None) -> Dict:
    """
    Convenience function to run correlation analysis.

    Args:
        case_id: Optional case ID to focus the correlation

    Returns:
        Dict with correlation results
    """
    engine = CorrelationEngine()
    engine.find_matches(case_id)
    return engine.results
