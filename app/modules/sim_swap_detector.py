"""
SIM Swap Detector Module
CyberTrace - Zambia Police Service

SIM swap fraud detection and investigation toolkit including timeline
building, carrier data import, compromise correlation, and risk scoring.
"""

import os
import re
import time
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger('osint')


class SimSwapDetector:
    """SIM Swap Fraud Detection and Investigation Tool"""

    def __init__(self):
        self.results = {
            'phone_number': None,
            'sim_events': [],
            'timeline': [],
            'risk_score': 0,
            'risk_factors': [],
            'correlations': [],
            'carrier_data': [],
            'metadata': {
                'investigated_at': None,
                'investigation_duration': 0,
                'api_calls_made': 0
            }
        }
        self.start_time = None
        self.api_calls = 0

    def investigate(self, phone_number: str, case_id: str = None) -> Dict:
        """
        Main orchestrator for SIM swap investigation.

        Args:
            phone_number: Phone number to investigate
            case_id: Optional case ID to link investigation

        Returns:
            Dict with SIM swap investigation results
        """
        self.start_time = time.time()
        phone_number = re.sub(r'[^\d+]', '', phone_number.strip())
        self.results['phone_number'] = phone_number
        self.results['metadata']['investigated_at'] = datetime.utcnow().isoformat()

        # Step 1: Check for SIM swap indicators
        try:
            indicators = self._check_sim_indicators(phone_number)
            self.results['sim_events'] = indicators
        except Exception as e:
            logger.error(f"SIM indicator check failed for {phone_number}: {e}")
            self.results['sim_events'] = []

        # Step 2: Build timeline from available events
        try:
            self.results['timeline'] = self.build_timeline(self.results['sim_events'])
        except Exception as e:
            logger.error(f"Timeline build failed for {phone_number}: {e}")
            self.results['timeline'] = []

        # Step 3: Calculate risk score
        try:
            risk_data = self.calculate_risk_score(self.results['sim_events'])
            self.results['risk_score'] = risk_data['score']
            self.results['risk_factors'] = risk_data['factors']
        except Exception as e:
            logger.error(f"Risk score calculation failed for {phone_number}: {e}")

        # Finalize metadata
        self.results['metadata']['investigation_duration'] = time.time() - self.start_time
        self.results['metadata']['api_calls_made'] = self.api_calls

        return self.results

    def _check_sim_indicators(self, phone_number: str) -> List[Dict]:
        """
        Check for SIM swap indicators on a phone number.

        Args:
            phone_number: Phone number to check

        Returns:
            List of SIM event indicator dicts
        """
        indicators = []

        # Placeholder: In production, this would query carrier APIs or databases
        # For now, return structured format for manual data entry

        indicator_template = {
            'event_type': None,          # sim_swap, port_out, sim_activation, etc.
            'timestamp': None,
            'carrier': None,
            'previous_sim': None,
            'new_sim': None,
            'location': None,
            'method': None,              # in_store, phone, online
            'authorized': None,          # True/False/Unknown
            'agent_id': None,
            'notes': None
        }

        logger.info(
            f"SIM swap indicator check for {phone_number} - "
            f"manual data entry or carrier API integration required"
        )

        return indicators

    def import_carrier_data(self, file_path: str, carrier: str,
                            case_id: str = None) -> List[Dict]:
        """
        Import and parse carrier records from CSV.

        Args:
            file_path: Path to carrier data CSV
            carrier: Carrier name (e.g., 'airtel', 'mtn', 'zamtel')
            case_id: Optional case ID

        Returns:
            List of parsed carrier event dicts
        """
        events = []

        try:
            import pandas as pd

            df = pd.read_csv(file_path)
            df.columns = [col.strip().lower().replace(' ', '_') for col in df.columns]

            for _, row in df.iterrows():
                event = {
                    'event_type': str(row.get('event_type', row.get('type', ''))).strip(),
                    'timestamp': str(row.get('timestamp', row.get('date', row.get('datetime', '')))).strip(),
                    'carrier': carrier,
                    'phone_number': str(row.get('phone_number', row.get('msisdn', row.get('number', '')))).strip(),
                    'previous_sim': str(row.get('previous_sim', row.get('old_iccid', row.get('old_sim', '')))).strip(),
                    'new_sim': str(row.get('new_sim', row.get('new_iccid', row.get('iccid', '')))).strip(),
                    'imei': str(row.get('imei', '')).strip(),
                    'location': str(row.get('location', row.get('store', row.get('branch', '')))).strip(),
                    'method': str(row.get('method', row.get('channel', ''))).strip(),
                    'agent_id': str(row.get('agent_id', row.get('agent', row.get('staff_id', '')))).strip(),
                    'authorized': row.get('authorized', None),
                    'notes': str(row.get('notes', row.get('remarks', ''))).strip(),
                    'case_id': case_id
                }
                events.append(event)

            self.results['carrier_data'] = events
            self.results['sim_events'].extend(events)
            logger.info(f"Imported {len(events)} carrier records from {file_path}")

        except ImportError:
            logger.error("pandas is required for carrier data import")
        except FileNotFoundError:
            logger.error(f"Carrier data file not found: {file_path}")
        except Exception as e:
            logger.error(f"Carrier data import failed: {e}")

        return events

    def build_timeline(self, events: List[Dict]) -> List[Dict]:
        """
        Build a chronological timeline from SIM events.

        Args:
            events: List of SIM event dicts

        Returns:
            Sorted list of timeline entry dicts
        """
        timeline = []

        for event in events:
            timestamp = event.get('timestamp')
            if not timestamp:
                continue

            # Parse timestamp to ensure consistent formatting
            parsed_time = None
            for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%d/%m/%Y %H:%M',
                         '%Y-%m-%d', '%d-%m-%Y', '%m/%d/%Y']:
                try:
                    parsed_time = datetime.strptime(str(timestamp), fmt)
                    break
                except (ValueError, TypeError):
                    continue

            if not parsed_time:
                parsed_time_str = str(timestamp)
            else:
                parsed_time_str = parsed_time.isoformat()

            timeline_entry = {
                'timestamp': parsed_time_str,
                'event_type': event.get('event_type', 'unknown'),
                'description': self._describe_event(event),
                'carrier': event.get('carrier', 'Unknown'),
                'location': event.get('location', 'Unknown'),
                'method': event.get('method', 'Unknown'),
                'authorized': event.get('authorized'),
                'severity': self._event_severity(event),
                'raw_event': event
            }

            timeline.append(timeline_entry)

        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])

        return timeline

    def _describe_event(self, event: Dict) -> str:
        """Generate a human-readable description of a SIM event."""
        event_type = event.get('event_type', '').lower()
        carrier = event.get('carrier', 'Unknown')
        phone = event.get('phone_number', 'Unknown')

        descriptions = {
            'sim_swap': f'SIM card swapped on {carrier} for {phone}',
            'port_out': f'Number {phone} ported out from {carrier}',
            'port_in': f'Number {phone} ported in to {carrier}',
            'sim_activation': f'New SIM activated on {carrier} for {phone}',
            'sim_deactivation': f'SIM deactivated on {carrier} for {phone}',
            'device_change': f'Device changed on {carrier} for {phone}',
            'account_change': f'Account details changed on {carrier} for {phone}',
        }

        return descriptions.get(event_type, f'{event_type} event on {carrier} for {phone}')

    def _event_severity(self, event: Dict) -> str:
        """Determine the severity level of a SIM event."""
        event_type = event.get('event_type', '').lower()
        authorized = event.get('authorized')

        high_risk_events = ['sim_swap', 'port_out']
        medium_risk_events = ['device_change', 'account_change', 'port_in']

        if event_type in high_risk_events:
            if authorized is False:
                return 'critical'
            return 'high'
        elif event_type in medium_risk_events:
            return 'medium'
        return 'low'

    def correlate_with_compromises(self, sim_events: List[Dict],
                                   compromises: List[Dict]) -> List[Dict]:
        """
        Correlate SIM swap events with account compromises.
        Flags swaps within 72 hours of an account compromise.

        Args:
            sim_events: List of SIM swap event dicts
            compromises: List of compromise event dicts with 'timestamp' and 'description'

        Returns:
            List of correlation dicts
        """
        correlations = []

        for sim_event in sim_events:
            sim_time = self._parse_timestamp(sim_event.get('timestamp'))
            if not sim_time:
                continue

            for compromise in compromises:
                comp_time = self._parse_timestamp(compromise.get('timestamp'))
                if not comp_time:
                    continue

                # Check if within 72-hour window
                time_diff = abs((comp_time - sim_time).total_seconds())
                hours_diff = time_diff / 3600

                if hours_diff <= 72:
                    # Determine if SIM event came before or after compromise
                    if sim_time <= comp_time:
                        relationship = 'sim_swap_before_compromise'
                        confidence = 'high' if hours_diff <= 24 else 'medium'
                    else:
                        relationship = 'sim_swap_after_compromise'
                        confidence = 'medium'

                    correlations.append({
                        'sim_event': sim_event,
                        'compromise': compromise,
                        'time_difference_hours': round(hours_diff, 2),
                        'relationship': relationship,
                        'confidence': confidence,
                        'description': (
                            f"SIM event ({sim_event.get('event_type', 'unknown')}) "
                            f"within {hours_diff:.1f} hours of compromise: "
                            f"{compromise.get('description', 'Unknown')}"
                        )
                    })

        # Sort by time difference
        correlations.sort(key=lambda x: x['time_difference_hours'])

        self.results['correlations'] = correlations
        return correlations

    def _parse_timestamp(self, timestamp) -> Optional[datetime]:
        """Parse a timestamp string into a datetime object."""
        if not timestamp:
            return None

        if isinstance(timestamp, datetime):
            return timestamp

        for fmt in ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d',
                     '%d/%m/%Y %H:%M:%S', '%d/%m/%Y %H:%M', '%d-%m-%Y',
                     '%m/%d/%Y %H:%M:%S', '%m/%d/%Y']:
            try:
                return datetime.strptime(str(timestamp), fmt)
            except (ValueError, TypeError):
                continue

        return None

    def calculate_risk_score(self, events: List[Dict]) -> Dict:
        """
        Calculate risk score based on SIM swap event patterns.

        Args:
            events: List of SIM events

        Returns:
            Dict with score (0-100) and risk factors
        """
        score = 0
        factors = []

        if not events:
            return {'score': 0, 'factors': ['No SIM events to analyze']}

        # Count event types
        event_types = defaultdict(int)
        for event in events:
            event_types[event.get('event_type', 'unknown').lower()] += 1

        # Multiple SIM swaps
        swap_count = event_types.get('sim_swap', 0)
        if swap_count >= 3:
            score += 40
            factors.append(f'Multiple SIM swaps detected ({swap_count})')
        elif swap_count >= 1:
            score += 20
            factors.append(f'SIM swap detected ({swap_count})')

        # Port-out events
        port_out_count = event_types.get('port_out', 0)
        if port_out_count > 0:
            score += 15
            factors.append(f'Port-out events detected ({port_out_count})')

        # Unauthorized events
        unauthorized = [e for e in events if e.get('authorized') is False]
        if unauthorized:
            score += 30
            factors.append(f'Unauthorized events detected ({len(unauthorized)})')

        # Rapid successive events
        timestamps = []
        for event in events:
            t = self._parse_timestamp(event.get('timestamp'))
            if t:
                timestamps.append(t)

        if len(timestamps) >= 2:
            timestamps.sort()
            for i in range(1, len(timestamps)):
                diff_hours = (timestamps[i] - timestamps[i - 1]).total_seconds() / 3600
                if diff_hours < 24:
                    score += 15
                    factors.append(f'Rapid successive events within {diff_hours:.1f} hours')
                    break

        # Events from different methods/channels
        methods = set(e.get('method', '').lower() for e in events if e.get('method'))
        if len(methods) > 1 and 'online' in methods:
            score += 10
            factors.append('Events from multiple channels including online')

        # Correlations with compromises
        if self.results.get('correlations'):
            high_confidence = [
                c for c in self.results['correlations']
                if c.get('confidence') == 'high'
            ]
            if high_confidence:
                score += 25
                factors.append(
                    f'High-confidence correlation with {len(high_confidence)} compromise(s)'
                )

        score = min(score, 100)

        return {'score': score, 'factors': factors}


def detect_sim_swap(phone_number: str, case_id: str = None) -> Dict:
    """
    Convenience function to investigate a phone number for SIM swap fraud.

    Args:
        phone_number: Phone number to investigate
        case_id: Optional case ID

    Returns:
        Dict with investigation results
    """
    detector = SimSwapDetector()
    return detector.investigate(phone_number, case_id)
