"""
Enhanced Threat Intelligence Module
CyberTrace - Zambia Police Service

Threat intelligence management with bulk import/export support,
STIX 2.1 integration, and automatic indicator extraction from cases.
"""

import os
import csv
import json
import time
import uuid
import logging
from typing import Dict, List, Optional
from datetime import datetime
from io import StringIO

logger = logging.getLogger('osint')


class EnhancedThreatIntel:
    """Enhanced Threat Intelligence Management Tool"""

    def __init__(self):
        self.results = {
            'imported': 0,
            'exported': 0,
            'indicators': [],
            'stix_bundle': None,
            'errors': [],
            'metadata': {
                'processed_at': None,
                'processing_duration': 0,
                'api_calls_made': 0
            }
        }
        self.start_time = None
        self.api_calls = 0

    def bulk_import_csv(self, file_path: str) -> List[Dict]:
        """
        Import threat indicators from a CSV file.

        Expected CSV columns: indicator_type, indicator_value, threat_type, severity
        Optional columns: source, description, tags, first_seen, last_seen

        Args:
            file_path: Path to the CSV file

        Returns:
            List of imported indicator dicts
        """
        self.start_time = time.time()
        self.results['metadata']['processed_at'] = datetime.utcnow().isoformat()
        indicators = []
        errors = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)

                # Normalize column names
                if reader.fieldnames:
                    reader.fieldnames = [
                        col.strip().lower().replace(' ', '_')
                        for col in reader.fieldnames
                    ]

                row_num = 1
                for row in reader:
                    row_num += 1
                    try:
                        indicator_type = row.get('indicator_type', '').strip()
                        indicator_value = row.get('indicator_value', '').strip()
                        threat_type = row.get('threat_type', '').strip()
                        severity = row.get('severity', 'medium').strip().lower()

                        # Validate required fields
                        if not indicator_type or not indicator_value:
                            errors.append(
                                f"Row {row_num}: Missing indicator_type or indicator_value"
                            )
                            continue

                        # Validate severity
                        valid_severities = ['low', 'medium', 'high', 'critical']
                        if severity not in valid_severities:
                            severity = 'medium'

                        indicator = {
                            'indicator_type': indicator_type,
                            'indicator_value': indicator_value,
                            'threat_type': threat_type,
                            'severity': severity,
                            'source': row.get('source', 'csv_import').strip(),
                            'description': row.get('description', '').strip(),
                            'tags': row.get('tags', '').strip(),
                            'first_seen': row.get('first_seen', '').strip(),
                            'last_seen': row.get('last_seen', '').strip(),
                            'imported_at': datetime.utcnow().isoformat(),
                            'is_active': True
                        }

                        indicators.append(indicator)

                        # Try to persist to database
                        try:
                            from app import db
                            from app.models import ThreatIndicator

                            db_indicator = ThreatIndicator(
                                indicator_type=indicator_type,
                                indicator_value=indicator_value,
                                threat_type=threat_type,
                                severity=severity,
                                source=indicator['source'],
                                description=indicator['description'],
                                is_active=True
                            )
                            db.session.add(db_indicator)
                        except ImportError:
                            pass
                        except Exception as e:
                            errors.append(f"Row {row_num}: DB insert failed - {str(e)}")

                    except Exception as e:
                        errors.append(f"Row {row_num}: Parse error - {str(e)}")

                # Commit all database inserts
                try:
                    from app import db
                    db.session.commit()
                except ImportError:
                    pass
                except Exception as e:
                    logger.error(f"Bulk import commit failed: {e}")
                    errors.append(f"Database commit failed: {str(e)}")
                    try:
                        from app import db
                        db.session.rollback()
                    except Exception:
                        pass

            logger.info(f"Imported {len(indicators)} indicators from {file_path}")

        except FileNotFoundError:
            errors.append(f"File not found: {file_path}")
            logger.error(f"CSV file not found: {file_path}")
        except Exception as e:
            errors.append(f"Import failed: {str(e)}")
            logger.error(f"Bulk CSV import failed: {e}")

        self.results['imported'] = len(indicators)
        self.results['indicators'] = indicators
        self.results['errors'] = errors
        self.results['metadata']['processing_duration'] = time.time() - self.start_time

        return indicators

    def bulk_export_csv(self, filters: Optional[Dict] = None) -> List[Dict]:
        """
        Export filtered threat indicators in CSV-ready format.

        Args:
            filters: Optional dict with filter criteria:
                - indicator_type (str)
                - threat_type (str)
                - severity (str)
                - is_active (bool)
                - source (str)

        Returns:
            List of indicator dicts suitable for CSV export
        """
        self.start_time = time.time()
        self.results['metadata']['processed_at'] = datetime.utcnow().isoformat()
        export_data = []

        try:
            from app import db
            from app.models import ThreatIndicator

            query = ThreatIndicator.query

            if filters:
                if filters.get('indicator_type'):
                    query = query.filter_by(indicator_type=filters['indicator_type'])
                if filters.get('threat_type'):
                    query = query.filter_by(threat_type=filters['threat_type'])
                if filters.get('severity'):
                    query = query.filter_by(severity=filters['severity'])
                if filters.get('is_active') is not None:
                    query = query.filter_by(is_active=filters['is_active'])
                if filters.get('source'):
                    query = query.filter_by(source=filters['source'])

            indicators = query.all()

            for ind in indicators:
                export_data.append({
                    'indicator_type': ind.indicator_type,
                    'indicator_value': ind.indicator_value,
                    'threat_type': ind.threat_type,
                    'severity': ind.severity,
                    'source': ind.source,
                    'description': ind.description,
                    'is_active': ind.is_active,
                    'created_at': ind.created_at.isoformat() if ind.created_at else None
                })

            logger.info(f"Exported {len(export_data)} indicators")

        except ImportError:
            logger.debug("Database not available for export")
        except Exception as e:
            logger.error(f"Bulk export failed: {e}")
            self.results['errors'].append(f"Export failed: {str(e)}")

        self.results['exported'] = len(export_data)
        self.results['indicators'] = export_data
        self.results['metadata']['processing_duration'] = time.time() - self.start_time

        return export_data

    def export_stix_bundle(self, indicators: List[Dict]) -> Dict:
        """
        Generate a STIX 2.1 JSON bundle from indicators.

        Args:
            indicators: List of indicator dicts to export

        Returns:
            Dict representing a STIX 2.1 bundle
        """
        stix_objects = []

        # STIX indicator type mapping
        stix_pattern_map = {
            'ip_address': lambda v: f"[ipv4-addr:value = '{v}']",
            'domain': lambda v: f"[domain-name:value = '{v}']",
            'email': lambda v: f"[email-addr:value = '{v}']",
            'url': lambda v: f"[url:value = '{v}']",
            'md5': lambda v: f"[file:hashes.MD5 = '{v}']",
            'sha1': lambda v: f"[file:hashes.'SHA-1' = '{v}']",
            'sha256': lambda v: f"[file:hashes.'SHA-256' = '{v}']",
            'btc_address': lambda v: f"[x-crypto-addr:value = '{v}']",
            'eth_address': lambda v: f"[x-crypto-addr:value = '{v}']",
            'phone': lambda v: f"[x-phone-number:value = '{v}']",
        }

        # STIX severity to TLP mapping
        severity_tlp = {
            'low': 'TLP:GREEN',
            'medium': 'TLP:AMBER',
            'high': 'TLP:RED',
            'critical': 'TLP:RED'
        }

        for ind in indicators:
            ind_type = ind.get('indicator_type', '')
            ind_value = ind.get('indicator_value', '')
            threat_type = ind.get('threat_type', 'unknown')
            severity = ind.get('severity', 'medium')

            # Generate STIX pattern
            pattern_fn = stix_pattern_map.get(ind_type)
            if pattern_fn:
                pattern = pattern_fn(ind_value)
            else:
                pattern = f"[x-custom:value = '{ind_value}']"

            stix_indicator = {
                'type': 'indicator',
                'spec_version': '2.1',
                'id': f'indicator--{uuid.uuid4()}',
                'created': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                'modified': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                'name': f'{ind_type}: {ind_value}',
                'description': ind.get('description', f'{threat_type} indicator'),
                'indicator_types': [self._map_threat_to_stix_type(threat_type)],
                'pattern': pattern,
                'pattern_type': 'stix',
                'valid_from': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                'labels': [severity, severity_tlp.get(severity, 'TLP:AMBER')],
                'confidence': self._severity_to_confidence(severity),
                'external_references': [
                    {
                        'source_name': 'CyberTrace-ZambiaPolice',
                        'description': f'Source: {ind.get("source", "manual")}'
                    }
                ]
            }

            stix_objects.append(stix_indicator)

        bundle = {
            'type': 'bundle',
            'id': f'bundle--{uuid.uuid4()}',
            'objects': stix_objects
        }

        self.results['stix_bundle'] = bundle
        logger.info(f"Generated STIX 2.1 bundle with {len(stix_objects)} indicators")

        return bundle

    def _map_threat_to_stix_type(self, threat_type: str) -> str:
        """Map internal threat types to STIX indicator types."""
        mapping = {
            'malware': 'malicious-activity',
            'phishing': 'malicious-activity',
            'fraud': 'malicious-activity',
            'ransomware': 'malicious-activity',
            'botnet': 'malicious-activity',
            'c2': 'malicious-activity',
            'suspicious': 'anomalous-activity',
            'unknown': 'anomalous-activity',
            'benign': 'benign',
        }
        return mapping.get(threat_type.lower(), 'anomalous-activity')

    def _severity_to_confidence(self, severity: str) -> int:
        """Map severity to STIX confidence score (0-100)."""
        mapping = {
            'critical': 95,
            'high': 80,
            'medium': 60,
            'low': 40
        }
        return mapping.get(severity, 50)

    def import_stix_bundle(self, file_path: str) -> List[Dict]:
        """
        Parse and import a STIX 2.1 JSON bundle file.

        Args:
            file_path: Path to the STIX JSON file

        Returns:
            List of parsed indicator dicts
        """
        self.start_time = time.time()
        self.results['metadata']['processed_at'] = datetime.utcnow().isoformat()
        indicators = []
        errors = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                bundle = json.load(f)

            if bundle.get('type') != 'bundle':
                errors.append('File does not contain a valid STIX bundle')
                self.results['errors'] = errors
                return indicators

            for obj in bundle.get('objects', []):
                if obj.get('type') != 'indicator':
                    continue

                try:
                    # Parse the STIX pattern to extract value
                    pattern = obj.get('pattern', '')
                    ind_type, ind_value = self._parse_stix_pattern(pattern)

                    # Map STIX indicator types back to internal types
                    stix_types = obj.get('indicator_types', [])
                    threat_type = 'unknown'
                    if stix_types:
                        if 'malicious-activity' in stix_types:
                            threat_type = 'malware'
                        elif 'anomalous-activity' in stix_types:
                            threat_type = 'suspicious'

                    # Extract severity from labels
                    labels = obj.get('labels', [])
                    severity = 'medium'
                    for label in labels:
                        if label in ('low', 'medium', 'high', 'critical'):
                            severity = label
                            break

                    indicator = {
                        'indicator_type': ind_type,
                        'indicator_value': ind_value,
                        'threat_type': threat_type,
                        'severity': severity,
                        'source': 'stix_import',
                        'description': obj.get('description', ''),
                        'stix_id': obj.get('id', ''),
                        'confidence': obj.get('confidence', 50),
                        'valid_from': obj.get('valid_from', ''),
                        'imported_at': datetime.utcnow().isoformat()
                    }

                    indicators.append(indicator)

                    # Try to persist
                    try:
                        from app import db
                        from app.models import ThreatIndicator

                        db_indicator = ThreatIndicator(
                            indicator_type=ind_type,
                            indicator_value=ind_value,
                            threat_type=threat_type,
                            severity=severity,
                            source='stix_import',
                            description=indicator['description'],
                            is_active=True
                        )
                        db.session.add(db_indicator)
                    except ImportError:
                        pass
                    except Exception as e:
                        errors.append(f"DB insert failed for {ind_value}: {str(e)}")

                except Exception as e:
                    errors.append(f"Failed to parse STIX object: {str(e)}")

            # Commit
            try:
                from app import db
                db.session.commit()
            except ImportError:
                pass
            except Exception as e:
                errors.append(f"Database commit failed: {str(e)}")
                try:
                    from app import db
                    db.session.rollback()
                except Exception:
                    pass

            logger.info(f"Imported {len(indicators)} indicators from STIX bundle")

        except FileNotFoundError:
            errors.append(f"File not found: {file_path}")
            logger.error(f"STIX file not found: {file_path}")
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON: {str(e)}")
            logger.error(f"STIX JSON parse error: {e}")
        except Exception as e:
            errors.append(f"Import failed: {str(e)}")
            logger.error(f"STIX import failed: {e}")

        self.results['imported'] = len(indicators)
        self.results['indicators'] = indicators
        self.results['errors'] = errors
        self.results['metadata']['processing_duration'] = time.time() - self.start_time

        return indicators

    def _parse_stix_pattern(self, pattern: str) -> tuple:
        """Parse a STIX pattern to extract indicator type and value."""
        import re

        # Pattern format: [type:property = 'value']
        match = re.search(r"\[([^\]]+)\]", pattern)
        if not match:
            return 'unknown', pattern

        inner = match.group(1)

        # Extract value
        value_match = re.search(r"=\s*'([^']+)'", inner)
        value = value_match.group(1) if value_match else ''

        # Determine type from STIX object type
        if 'ipv4-addr' in inner or 'ipv6-addr' in inner:
            return 'ip_address', value
        elif 'domain-name' in inner:
            return 'domain', value
        elif 'email-addr' in inner:
            return 'email', value
        elif 'url:value' in inner:
            return 'url', value
        elif 'MD5' in inner:
            return 'md5', value
        elif 'SHA-1' in inner:
            return 'sha1', value
        elif 'SHA-256' in inner:
            return 'sha256', value
        elif 'x-crypto-addr' in inner:
            return 'crypto_address', value
        elif 'x-phone-number' in inner:
            return 'phone', value
        else:
            return 'unknown', value

    def auto_extract_from_case(self, case_id: str) -> List[Dict]:
        """
        Automatically extract threat indicators from all investigations in a case.

        Args:
            case_id: Case ID to extract indicators from

        Returns:
            List of extracted and stored indicator dicts
        """
        self.start_time = time.time()
        self.results['metadata']['processed_at'] = datetime.utcnow().isoformat()
        all_indicators = []
        errors = []

        try:
            from app import db
            from app.models import Investigation, ThreatIndicator
            from app.modules.correlation_engine import CorrelationEngine

            # Get all investigations for this case
            investigations = Investigation.query.filter_by(case_id=case_id).all()

            engine = CorrelationEngine()

            for investigation in investigations:
                try:
                    indicators = engine.extract_indicators_from_investigation(investigation)

                    for ind in indicators:
                        # Check if already exists
                        existing = ThreatIndicator.query.filter_by(
                            indicator_value=ind['indicator_value'],
                            indicator_type=ind['indicator_type']
                        ).first()

                        if not existing:
                            db_indicator = ThreatIndicator(
                                indicator_type=ind['indicator_type'],
                                indicator_value=ind['indicator_value'],
                                threat_type='auto_extracted',
                                severity='medium',
                                source=f'case_{case_id}',
                                description=f'Auto-extracted from case {case_id}',
                                is_active=True
                            )
                            db.session.add(db_indicator)
                            all_indicators.append(ind)

                except Exception as e:
                    errors.append(
                        f"Extraction failed for investigation {investigation.id}: {str(e)}"
                    )
                    logger.error(f"Auto-extraction error: {e}")

            db.session.commit()
            logger.info(
                f"Auto-extracted {len(all_indicators)} indicators from case {case_id}"
            )

        except ImportError:
            errors.append("Database modules not available")
            logger.debug("Database not available for auto-extraction")
        except Exception as e:
            errors.append(f"Auto-extraction failed: {str(e)}")
            logger.error(f"Auto-extraction failed for case {case_id}: {e}")
            try:
                from app import db
                db.session.rollback()
            except Exception:
                pass

        self.results['imported'] = len(all_indicators)
        self.results['indicators'] = all_indicators
        self.results['errors'] = errors
        self.results['metadata']['processing_duration'] = time.time() - self.start_time

        return all_indicators


def bulk_import(file_path: str, format: str = 'csv') -> Dict:
    """
    Convenience function to bulk import threat indicators.

    Args:
        file_path: Path to the import file
        format: File format ('csv' or 'stix')

    Returns:
        Dict with import results
    """
    intel = EnhancedThreatIntel()

    if format == 'csv':
        intel.bulk_import_csv(file_path)
    elif format == 'stix':
        intel.import_stix_bundle(file_path)
    else:
        intel.results['errors'].append(f'Unsupported format: {format}')

    return intel.results
