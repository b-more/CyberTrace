"""
ISP Request Manager Module
CyberTrace - Zambia Police Service

ISP/Telecom data request management system for legal data requests
to service providers. Handles request creation, tracking, SLA monitoring,
and reporting.
"""

import time
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta

logger = logging.getLogger('osint')


class ISPRequestManager:
    """ISP/Telecom Legal Data Request Management Tool"""

    def __init__(self):
        self.results = {
            'request': {},
            'requests': [],
            'overdue': [],
            'statistics': {},
            'metadata': {
                'processed_at': None,
                'processing_duration': 0,
                'api_calls_made': 0
            }
        }
        self.start_time = None
        self.api_calls = 0

        # SLA deadlines by provider (in days)
        self.provider_sla = {
            'airtel': 14,
            'mtn': 14,
            'zamtel': 14,
            'liquid_telecom': 21,
            'zol': 21,
            'microlink': 21,
            'hai': 21,
            'africonnect': 21,
            'default': 30
        }

    def generate_request_number(self) -> str:
        """
        Generate a unique request number in the format ZPS-REQ-YYYY-NNNN.

        Returns:
            String request number
        """
        year = datetime.utcnow().year
        sequence = 1

        try:
            from app import db
            from app.models import ISPRequest

            # Get the last request number for this year
            last_request = ISPRequest.query.filter(
                ISPRequest.request_number.like(f'ZPS-REQ-{year}-%')
            ).order_by(ISPRequest.id.desc()).first()

            if last_request and last_request.request_number:
                parts = last_request.request_number.split('-')
                if len(parts) == 4:
                    try:
                        sequence = int(parts[3]) + 1
                    except ValueError:
                        sequence = 1
        except ImportError:
            logger.debug("Database not available, using default sequence")
        except Exception as e:
            logger.warning(f"Could not query last request number: {e}")

        return f"ZPS-REQ-{year}-{sequence:04d}"

    def create_request(self, case_id: str, provider: str, request_type: str,
                       target: str, legal_authority: str) -> Dict:
        """
        Create a new ISP data request record.

        Args:
            case_id: ID of the related case
            provider: ISP/telecom provider name
            request_type: Type of request (subscriber_info, call_records, ip_logs,
                         cell_tower, content_data, preservation)
            target: Target identifier (phone number, IP address, email, etc.)
            legal_authority: Legal authority reference (court order number, etc.)

        Returns:
            Dict with created request details
        """
        self.start_time = time.time()
        self.results['metadata']['processed_at'] = datetime.utcnow().isoformat()

        request_number = self.generate_request_number()
        sla_days = self.provider_sla.get(provider.lower(), self.provider_sla['default'])
        deadline = datetime.utcnow() + timedelta(days=sla_days)

        request_data = {
            'request_number': request_number,
            'case_id': case_id,
            'provider': provider,
            'request_type': request_type,
            'target': target,
            'legal_authority': legal_authority,
            'status': 'pending',
            'priority': 'normal',
            'sla_deadline': deadline.isoformat(),
            'sla_days': sla_days,
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat(),
            'response_received': False,
            'response_data': None,
            'notes': []
        }

        # Try to persist to database
        try:
            from app import db
            from app.models import ISPRequest

            db_request = ISPRequest(
                request_number=request_number,
                case_id=case_id,
                provider=provider,
                request_type=request_type,
                target_identifier=target,
                legal_authority=legal_authority,
                status='pending',
                priority='normal',
                sla_deadline=deadline
            )
            db.session.add(db_request)
            db.session.commit()

            request_data['id'] = db_request.id
            logger.info(f"ISP request created: {request_number} for case {case_id}")
        except ImportError:
            logger.debug("Database not available, returning in-memory request")
        except Exception as e:
            logger.error(f"Failed to persist ISP request: {e}")
            try:
                db.session.rollback()
            except Exception:
                pass

        self.results['request'] = request_data
        self.results['metadata']['processing_duration'] = time.time() - self.start_time
        self.results['metadata']['api_calls_made'] = self.api_calls

        return request_data

    def get_overdue_requests(self) -> List[Dict]:
        """
        Find all requests that are past their SLA deadline.

        Returns:
            List of overdue request dicts
        """
        overdue = []

        try:
            from app import db
            from app.models import ISPRequest

            now = datetime.utcnow()

            overdue_records = ISPRequest.query.filter(
                ISPRequest.sla_deadline < now,
                ISPRequest.status.in_(['pending', 'submitted', 'acknowledged'])
            ).order_by(ISPRequest.sla_deadline.asc()).all()

            for req in overdue_records:
                days_overdue = (now - req.sla_deadline).days if req.sla_deadline else 0
                overdue.append({
                    'id': req.id,
                    'request_number': req.request_number,
                    'case_id': req.case_id,
                    'provider': req.provider,
                    'request_type': req.request_type,
                    'target': req.target_identifier,
                    'status': req.status,
                    'sla_deadline': req.sla_deadline.isoformat() if req.sla_deadline else None,
                    'days_overdue': days_overdue,
                    'priority': req.priority,
                    'created_at': req.created_at.isoformat() if req.created_at else None,
                    'urgency': 'critical' if days_overdue > 14 else (
                        'high' if days_overdue > 7 else 'medium'
                    )
                })

            logger.info(f"Found {len(overdue)} overdue ISP requests")

        except ImportError:
            logger.debug("Database not available for overdue request check")
        except Exception as e:
            logger.error(f"Failed to query overdue requests: {e}")

        self.results['overdue'] = overdue
        return overdue

    def get_request_statistics(self) -> Dict:
        """
        Get ISP request statistics (counts by status, provider, type).

        Returns:
            Dict with request statistics
        """
        stats = {
            'total': 0,
            'by_status': {},
            'by_provider': {},
            'by_type': {},
            'overdue_count': 0,
            'avg_response_days': None,
            'completion_rate': 0,
            'error': None
        }

        try:
            from app import db
            from app.models import ISPRequest
            from sqlalchemy import func

            # Total count
            stats['total'] = ISPRequest.query.count()

            # By status
            status_counts = db.session.query(
                ISPRequest.status,
                func.count(ISPRequest.id)
            ).group_by(ISPRequest.status).all()
            stats['by_status'] = {s: c for s, c in status_counts}

            # By provider
            provider_counts = db.session.query(
                ISPRequest.provider,
                func.count(ISPRequest.id)
            ).group_by(ISPRequest.provider).all()
            stats['by_provider'] = {p: c for p, c in provider_counts}

            # By type
            type_counts = db.session.query(
                ISPRequest.request_type,
                func.count(ISPRequest.id)
            ).group_by(ISPRequest.request_type).all()
            stats['by_type'] = {t: c for t, c in type_counts}

            # Overdue count
            now = datetime.utcnow()
            stats['overdue_count'] = ISPRequest.query.filter(
                ISPRequest.sla_deadline < now,
                ISPRequest.status.in_(['pending', 'submitted', 'acknowledged'])
            ).count()

            # Completion rate
            completed = stats['by_status'].get('completed', 0)
            if stats['total'] > 0:
                stats['completion_rate'] = round(
                    completed / stats['total'] * 100, 1
                )

            logger.info(f"ISP request statistics generated: {stats['total']} total")

        except ImportError:
            stats['error'] = 'Database not available'
            logger.debug("Database not available for statistics")
        except Exception as e:
            stats['error'] = f'Statistics query failed: {str(e)}'
            logger.error(f"Failed to generate ISP request statistics: {e}")

        self.results['statistics'] = stats
        return stats


def create_isp_request(case_id: str, provider: str, request_type: str,
                       target: str, legal_authority: str) -> Dict:
    """
    Convenience function to create an ISP data request.

    Args:
        case_id: ID of the related case
        provider: ISP/telecom provider name
        request_type: Type of data request
        target: Target identifier
        legal_authority: Legal authority reference

    Returns:
        Dict with request details
    """
    manager = ISPRequestManager()
    return manager.create_request(case_id, provider, request_type, target, legal_authority)
