"""
Victim Manager Module
CyberTrace - Zambia Police Service

Victim registration and loss tracking system for cybercrime cases.
Handles victim data management, financial loss aggregation,
geographic analysis, and statistical reporting.
"""

import time
import logging
from typing import Dict, List, Optional
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger('osint')


class VictimManager:
    """Victim Registration and Loss Tracking Tool"""

    def __init__(self):
        self.results = {
            'victim': {},
            'victims': [],
            'total_losses': 0,
            'loss_statistics': {},
            'province_data': {},
            'metadata': {
                'processed_at': None,
                'processing_duration': 0,
                'api_calls_made': 0
            }
        }
        self.start_time = None
        self.api_calls = 0

        # Zambia provinces for geographic analysis
        self.provinces = [
            'Central', 'Copperbelt', 'Eastern', 'Luapula',
            'Lusaka', 'Muchinga', 'Northern', 'North-Western',
            'Southern', 'Western'
        ]

    def add_victim(self, case_id: str, victim_data: Dict) -> Dict:
        """
        Register a new victim record for a case.

        Args:
            case_id: ID of the related case
            victim_data: Dict containing victim information:
                - name (str): Victim's full name
                - id_number (str): National ID or passport number
                - phone (str): Phone number
                - email (str): Email address
                - province (str): Province of residence
                - district (str): District of residence
                - loss_amount (float): Financial loss amount
                - loss_currency (str): Currency code (default ZMW)
                - loss_type (str): Type of loss (financial, data, identity, etc.)
                - report_date (str): Date of report
                - description (str): Description of how they were victimized
                - age (int): Victim's age
                - gender (str): Victim's gender

        Returns:
            Dict with created victim record
        """
        self.start_time = time.time()
        self.results['metadata']['processed_at'] = datetime.utcnow().isoformat()

        victim = {
            'case_id': case_id,
            'name': victim_data.get('name', ''),
            'id_number': victim_data.get('id_number', ''),
            'phone': victim_data.get('phone', ''),
            'email': victim_data.get('email', ''),
            'province': victim_data.get('province', ''),
            'district': victim_data.get('district', ''),
            'loss_amount': float(victim_data.get('loss_amount', 0)),
            'loss_currency': victim_data.get('loss_currency', 'ZMW'),
            'loss_type': victim_data.get('loss_type', 'financial'),
            'report_date': victim_data.get('report_date', datetime.utcnow().isoformat()),
            'description': victim_data.get('description', ''),
            'age': victim_data.get('age'),
            'gender': victim_data.get('gender', ''),
            'status': 'registered',
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat()
        }

        # Persist to database
        try:
            from app import db
            from app.models import Victim

            db_victim = Victim(
                case_id=case_id,
                name=victim['name'],
                id_number=victim['id_number'],
                phone=victim['phone'],
                email=victim['email'],
                province=victim['province'],
                district=victim['district'],
                loss_amount=victim['loss_amount'],
                loss_currency=victim['loss_currency'],
                loss_type=victim['loss_type'],
                report_date=datetime.fromisoformat(victim['report_date']) if isinstance(victim['report_date'], str) else victim['report_date'],
                description=victim['description'],
                age=victim['age'],
                gender=victim['gender'],
                status='registered'
            )
            db.session.add(db_victim)
            db.session.commit()

            victim['id'] = db_victim.id
            logger.info(f"Victim registered: {victim['name']} for case {case_id}")

        except ImportError:
            logger.debug("Database not available, returning in-memory victim record")
        except Exception as e:
            logger.error(f"Failed to persist victim record: {e}")
            try:
                from app import db
                db.session.rollback()
            except Exception:
                pass

        self.results['victim'] = victim
        self.results['metadata']['processing_duration'] = time.time() - self.start_time
        self.results['metadata']['api_calls_made'] = self.api_calls

        return victim

    def calculate_total_losses(self, case_id: str = None) -> Dict:
        """
        Aggregate total financial losses, optionally filtered by case.

        Args:
            case_id: Optional case ID to filter by

        Returns:
            Dict with total loss amounts
        """
        loss_data = {
            'total_loss': 0,
            'total_victims': 0,
            'average_loss': 0,
            'max_loss': 0,
            'min_loss': 0,
            'by_currency': {},
            'error': None
        }

        try:
            from app import db
            from app.models import Victim
            from sqlalchemy import func

            query = db.session.query(Victim)
            if case_id:
                query = query.filter_by(case_id=case_id)

            # Aggregate
            agg = query.with_entities(
                func.sum(Victim.loss_amount).label('total'),
                func.count(Victim.id).label('count'),
                func.avg(Victim.loss_amount).label('avg'),
                func.max(Victim.loss_amount).label('max'),
                func.min(Victim.loss_amount).label('min')
            ).first()

            if agg:
                loss_data['total_loss'] = float(agg.total or 0)
                loss_data['total_victims'] = int(agg.count or 0)
                loss_data['average_loss'] = round(float(agg.avg or 0), 2)
                loss_data['max_loss'] = float(agg.max or 0)
                loss_data['min_loss'] = float(agg.min or 0)

            # By currency
            currency_agg = query.with_entities(
                Victim.loss_currency,
                func.sum(Victim.loss_amount).label('total'),
                func.count(Victim.id).label('count')
            ).group_by(Victim.loss_currency).all()

            for curr in currency_agg:
                loss_data['by_currency'][curr.loss_currency or 'ZMW'] = {
                    'total': float(curr.total or 0),
                    'victim_count': int(curr.count or 0)
                }

            logger.info(
                f"Loss calculation: {loss_data['total_loss']} total "
                f"from {loss_data['total_victims']} victims"
            )

        except ImportError:
            loss_data['error'] = 'Database not available'
            logger.debug("Database not available for loss calculation")
        except Exception as e:
            loss_data['error'] = f'Loss calculation failed: {str(e)}'
            logger.error(f"Failed to calculate losses: {e}")

        self.results['total_losses'] = loss_data['total_loss']
        return loss_data

    def get_loss_statistics(self) -> Dict:
        """
        Get detailed loss statistics broken down by type, province, and amount ranges.

        Returns:
            Dict with loss statistics
        """
        stats = {
            'by_type': {},
            'by_province': {},
            'by_amount_range': {},
            'by_gender': {},
            'by_age_group': {},
            'total_victims': 0,
            'total_loss': 0,
            'error': None
        }

        try:
            from app import db
            from app.models import Victim
            from sqlalchemy import func, case as sql_case

            # By loss type
            type_agg = db.session.query(
                Victim.loss_type,
                func.sum(Victim.loss_amount).label('total'),
                func.count(Victim.id).label('count')
            ).group_by(Victim.loss_type).all()

            for row in type_agg:
                stats['by_type'][row.loss_type or 'unknown'] = {
                    'total_loss': float(row.total or 0),
                    'victim_count': int(row.count or 0)
                }

            # By province
            province_agg = db.session.query(
                Victim.province,
                func.sum(Victim.loss_amount).label('total'),
                func.count(Victim.id).label('count')
            ).group_by(Victim.province).all()

            for row in province_agg:
                stats['by_province'][row.province or 'Unknown'] = {
                    'total_loss': float(row.total or 0),
                    'victim_count': int(row.count or 0)
                }

            # By gender
            gender_agg = db.session.query(
                Victim.gender,
                func.sum(Victim.loss_amount).label('total'),
                func.count(Victim.id).label('count')
            ).group_by(Victim.gender).all()

            for row in gender_agg:
                stats['by_gender'][row.gender or 'Unknown'] = {
                    'total_loss': float(row.total or 0),
                    'victim_count': int(row.count or 0)
                }

            # Total
            total = db.session.query(
                func.sum(Victim.loss_amount).label('total'),
                func.count(Victim.id).label('count')
            ).first()

            stats['total_victims'] = int(total.count or 0)
            stats['total_loss'] = float(total.total or 0)

            # Amount ranges
            ranges = [
                ('0-1000', 0, 1000),
                ('1001-5000', 1001, 5000),
                ('5001-10000', 5001, 10000),
                ('10001-50000', 10001, 50000),
                ('50001-100000', 50001, 100000),
                ('100001+', 100001, 999999999)
            ]

            for label, low, high in ranges:
                count = Victim.query.filter(
                    Victim.loss_amount >= low,
                    Victim.loss_amount <= high
                ).count()
                if count > 0:
                    stats['by_amount_range'][label] = count

            logger.info(f"Loss statistics generated: {stats['total_victims']} victims")

        except ImportError:
            stats['error'] = 'Database not available'
            logger.debug("Database not available for loss statistics")
        except Exception as e:
            stats['error'] = f'Statistics query failed: {str(e)}'
            logger.error(f"Failed to generate loss statistics: {e}")

        self.results['loss_statistics'] = stats
        return stats

    def get_victim_count_by_province(self) -> Dict:
        """
        Get victim counts by province for geographic analysis.

        Returns:
            Dict mapping province names to victim counts
        """
        province_counts = {province: 0 for province in self.provinces}

        try:
            from app import db
            from app.models import Victim
            from sqlalchemy import func

            counts = db.session.query(
                Victim.province,
                func.count(Victim.id).label('count')
            ).group_by(Victim.province).all()

            for row in counts:
                province = row.province or 'Unknown'
                province_counts[province] = int(row.count or 0)

            logger.info("Province victim counts generated")

        except ImportError:
            logger.debug("Database not available for province counts")
        except Exception as e:
            logger.error(f"Failed to get province counts: {e}")

        self.results['province_data'] = province_counts
        return province_counts


def register_victim(case_id: str, data: Dict) -> Dict:
    """
    Convenience function to register a victim.

    Args:
        case_id: ID of the related case
        data: Victim data dict

    Returns:
        Dict with victim record
    """
    manager = VictimManager()
    return manager.add_victim(case_id, data)
