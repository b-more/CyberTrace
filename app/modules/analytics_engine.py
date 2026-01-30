"""
Analytics Engine Module
CyberTrace - Zambia Police Service

Comprehensive analytics and reporting engine for dashboard statistics,
performance metrics, trend analysis, financial loss summaries, and
executive report generation.
"""

import time
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger('osint')


class AnalyticsEngine:
    """Analytics and Reporting Engine"""

    def __init__(self):
        self.results = {
            'case_statistics': {},
            'investigation_statistics': {},
            'performance_metrics': {},
            'trend_data': {},
            'financial_summary': {},
            'threat_statistics': {},
            'executive_summary': {},
            'metadata': {
                'generated_at': None,
                'generation_duration': 0,
                'api_calls_made': 0
            }
        }
        self.start_time = None
        self.api_calls = 0

    def get_case_statistics(self, date_range: Optional[Tuple[str, str]] = None) -> Dict:
        """
        Get case statistics: total, by status, by type, by priority.

        Args:
            date_range: Optional tuple of (start_date, end_date) ISO strings

        Returns:
            Dict with case statistics
        """
        stats = {
            'total': 0,
            'by_status': {},
            'by_type': {},
            'by_priority': {},
            'recent_cases': [],
            'open_cases': 0,
            'closed_cases': 0,
            'closure_rate': 0,
            'error': None
        }

        try:
            from app import db
            from app.models import Case
            from sqlalchemy import func

            query = Case.query

            if date_range:
                start, end = date_range
                try:
                    start_dt = datetime.fromisoformat(start)
                    end_dt = datetime.fromisoformat(end)
                    query = query.filter(
                        Case.created_at >= start_dt,
                        Case.created_at <= end_dt
                    )
                except (ValueError, TypeError) as e:
                    logger.warning(f"Invalid date range: {e}")

            stats['total'] = query.count()

            # By status
            status_counts = query.with_entities(
                Case.status,
                func.count(Case.id)
            ).group_by(Case.status).all()
            stats['by_status'] = {s or 'unknown': c for s, c in status_counts}

            # By type
            type_counts = query.with_entities(
                Case.case_type,
                func.count(Case.id)
            ).group_by(Case.case_type).all()
            stats['by_type'] = {t or 'unknown': c for t, c in type_counts}

            # By priority
            priority_counts = query.with_entities(
                Case.priority,
                func.count(Case.id)
            ).group_by(Case.priority).all()
            stats['by_priority'] = {p or 'unknown': c for p, c in priority_counts}

            # Open vs closed
            stats['open_cases'] = query.filter(
                Case.status.in_(['open', 'in_progress', 'pending', 'active'])
            ).count()
            stats['closed_cases'] = query.filter(
                Case.status.in_(['closed', 'resolved', 'archived'])
            ).count()

            if stats['total'] > 0:
                stats['closure_rate'] = round(
                    stats['closed_cases'] / stats['total'] * 100, 1
                )

            # Recent cases (last 10)
            recent = query.order_by(Case.created_at.desc()).limit(10).all()
            for case in recent:
                stats['recent_cases'].append({
                    'id': case.id,
                    'case_number': getattr(case, 'case_number', str(case.id)),
                    'title': getattr(case, 'title', ''),
                    'status': case.status,
                    'case_type': case.case_type,
                    'priority': case.priority,
                    'created_at': case.created_at.isoformat() if case.created_at else None
                })

            logger.info(f"Case statistics generated: {stats['total']} total")

        except ImportError:
            stats['error'] = 'Database not available'
            logger.debug("Database not available for case statistics")
        except Exception as e:
            stats['error'] = f'Query failed: {str(e)}'
            logger.error(f"Case statistics query failed: {e}")

        self.results['case_statistics'] = stats
        return stats

    def get_investigation_statistics(self, date_range: Optional[Tuple[str, str]] = None) -> Dict:
        """
        Get investigation statistics: total, by type, success rate.

        Args:
            date_range: Optional tuple of (start_date, end_date) ISO strings

        Returns:
            Dict with investigation statistics
        """
        stats = {
            'total': 0,
            'by_type': {},
            'by_status': {},
            'success_rate': 0,
            'avg_duration': None,
            'error': None
        }

        try:
            from app import db
            from app.models import Investigation
            from sqlalchemy import func

            query = Investigation.query

            if date_range:
                start, end = date_range
                try:
                    start_dt = datetime.fromisoformat(start)
                    end_dt = datetime.fromisoformat(end)
                    query = query.filter(
                        Investigation.created_at >= start_dt,
                        Investigation.created_at <= end_dt
                    )
                except (ValueError, TypeError) as e:
                    logger.warning(f"Invalid date range: {e}")

            stats['total'] = query.count()

            # By type
            type_counts = query.with_entities(
                Investigation.investigation_type,
                func.count(Investigation.id)
            ).group_by(Investigation.investigation_type).all()
            stats['by_type'] = {t or 'unknown': c for t, c in type_counts}

            # By status
            status_counts = query.with_entities(
                Investigation.status,
                func.count(Investigation.id)
            ).group_by(Investigation.status).all()
            stats['by_status'] = {s or 'unknown': c for s, c in status_counts}

            # Success rate (completed investigations with results)
            completed = query.filter(
                Investigation.status.in_(['completed', 'success'])
            ).count()
            if stats['total'] > 0:
                stats['success_rate'] = round(completed / stats['total'] * 100, 1)

            logger.info(f"Investigation statistics generated: {stats['total']} total")

        except ImportError:
            stats['error'] = 'Database not available'
            logger.debug("Database not available for investigation statistics")
        except Exception as e:
            stats['error'] = f'Query failed: {str(e)}'
            logger.error(f"Investigation statistics query failed: {e}")

        self.results['investigation_statistics'] = stats
        return stats

    def get_performance_metrics(self, user_id: str = None) -> Dict:
        """
        Get performance metrics: cases closed, avg resolution time, investigations count.

        Args:
            user_id: Optional user ID to filter by

        Returns:
            Dict with performance metrics
        """
        metrics = {
            'cases_closed': 0,
            'cases_open': 0,
            'avg_resolution_time_days': None,
            'investigations_completed': 0,
            'investigations_pending': 0,
            'isp_requests_sent': 0,
            'isp_requests_completed': 0,
            'error': None
        }

        try:
            from app import db
            from app.models import Case, Investigation
            from sqlalchemy import func

            # Cases
            case_query = Case.query
            if user_id:
                case_query = case_query.filter_by(assigned_to=user_id)

            metrics['cases_closed'] = case_query.filter(
                Case.status.in_(['closed', 'resolved', 'archived'])
            ).count()

            metrics['cases_open'] = case_query.filter(
                Case.status.in_(['open', 'in_progress', 'pending', 'active'])
            ).count()

            # Average resolution time
            try:
                closed_cases = case_query.filter(
                    Case.status.in_(['closed', 'resolved']),
                    Case.closed_at.isnot(None),
                    Case.created_at.isnot(None)
                ).all()

                if closed_cases:
                    total_days = 0
                    count = 0
                    for case in closed_cases:
                        if case.closed_at and case.created_at:
                            delta = (case.closed_at - case.created_at).days
                            total_days += delta
                            count += 1
                    if count > 0:
                        metrics['avg_resolution_time_days'] = round(total_days / count, 1)
            except AttributeError:
                # Model might not have closed_at field
                pass

            # Investigations
            inv_query = Investigation.query
            if user_id:
                inv_query = inv_query.filter_by(created_by=user_id)

            metrics['investigations_completed'] = inv_query.filter(
                Investigation.status.in_(['completed', 'success'])
            ).count()

            metrics['investigations_pending'] = inv_query.filter(
                Investigation.status.in_(['pending', 'in_progress', 'running'])
            ).count()

            # ISP Requests
            try:
                from app.models import ISPRequest

                isp_query = ISPRequest.query
                metrics['isp_requests_sent'] = isp_query.count()
                metrics['isp_requests_completed'] = isp_query.filter_by(
                    status='completed'
                ).count()
            except (ImportError, Exception):
                pass

            logger.info("Performance metrics generated")

        except ImportError:
            metrics['error'] = 'Database not available'
            logger.debug("Database not available for performance metrics")
        except Exception as e:
            metrics['error'] = f'Query failed: {str(e)}'
            logger.error(f"Performance metrics query failed: {e}")

        self.results['performance_metrics'] = metrics
        return metrics

    def get_trend_data(self, metric: str, period: str = 'monthly') -> Dict:
        """
        Get time series trend data for charts.

        Args:
            metric: Metric to trend ('cases', 'investigations', 'losses', 'threats')
            period: Time period grouping ('daily', 'weekly', 'monthly')

        Returns:
            Dict with labels and data arrays for chart rendering
        """
        trend = {
            'metric': metric,
            'period': period,
            'labels': [],
            'data': [],
            'error': None
        }

        try:
            from app import db
            from sqlalchemy import func, extract

            if period == 'daily':
                date_group = func.date(None)  # Will be set per model
                lookback = timedelta(days=30)
            elif period == 'weekly':
                lookback = timedelta(days=90)
            else:  # monthly
                lookback = timedelta(days=365)

            cutoff = datetime.utcnow() - lookback

            if metric == 'cases':
                from app.models import Case

                if period == 'monthly':
                    results = db.session.query(
                        extract('year', Case.created_at).label('year'),
                        extract('month', Case.created_at).label('month'),
                        func.count(Case.id).label('count')
                    ).filter(
                        Case.created_at >= cutoff
                    ).group_by(
                        extract('year', Case.created_at),
                        extract('month', Case.created_at)
                    ).order_by(
                        extract('year', Case.created_at),
                        extract('month', Case.created_at)
                    ).all()

                    for row in results:
                        label = f"{int(row.year)}-{int(row.month):02d}"
                        trend['labels'].append(label)
                        trend['data'].append(int(row.count))

                elif period == 'daily':
                    results = db.session.query(
                        func.date(Case.created_at).label('date'),
                        func.count(Case.id).label('count')
                    ).filter(
                        Case.created_at >= cutoff
                    ).group_by(
                        func.date(Case.created_at)
                    ).order_by(
                        func.date(Case.created_at)
                    ).all()

                    for row in results:
                        trend['labels'].append(str(row.date))
                        trend['data'].append(int(row.count))

            elif metric == 'investigations':
                from app.models import Investigation

                if period == 'monthly':
                    results = db.session.query(
                        extract('year', Investigation.created_at).label('year'),
                        extract('month', Investigation.created_at).label('month'),
                        func.count(Investigation.id).label('count')
                    ).filter(
                        Investigation.created_at >= cutoff
                    ).group_by(
                        extract('year', Investigation.created_at),
                        extract('month', Investigation.created_at)
                    ).order_by(
                        extract('year', Investigation.created_at),
                        extract('month', Investigation.created_at)
                    ).all()

                    for row in results:
                        label = f"{int(row.year)}-{int(row.month):02d}"
                        trend['labels'].append(label)
                        trend['data'].append(int(row.count))

            elif metric == 'losses':
                from app.models import Victim

                if period == 'monthly':
                    results = db.session.query(
                        extract('year', Victim.created_at).label('year'),
                        extract('month', Victim.created_at).label('month'),
                        func.sum(Victim.loss_amount).label('total')
                    ).filter(
                        Victim.created_at >= cutoff
                    ).group_by(
                        extract('year', Victim.created_at),
                        extract('month', Victim.created_at)
                    ).order_by(
                        extract('year', Victim.created_at),
                        extract('month', Victim.created_at)
                    ).all()

                    for row in results:
                        label = f"{int(row.year)}-{int(row.month):02d}"
                        trend['labels'].append(label)
                        trend['data'].append(float(row.total or 0))

            elif metric == 'threats':
                from app.models import ThreatIndicator

                if period == 'monthly':
                    results = db.session.query(
                        extract('year', ThreatIndicator.created_at).label('year'),
                        extract('month', ThreatIndicator.created_at).label('month'),
                        func.count(ThreatIndicator.id).label('count')
                    ).filter(
                        ThreatIndicator.created_at >= cutoff
                    ).group_by(
                        extract('year', ThreatIndicator.created_at),
                        extract('month', ThreatIndicator.created_at)
                    ).order_by(
                        extract('year', ThreatIndicator.created_at),
                        extract('month', ThreatIndicator.created_at)
                    ).all()

                    for row in results:
                        label = f"{int(row.year)}-{int(row.month):02d}"
                        trend['labels'].append(label)
                        trend['data'].append(int(row.count))

            logger.info(f"Trend data generated for {metric}/{period}")

        except ImportError:
            trend['error'] = 'Database not available'
            logger.debug("Database not available for trend data")
        except Exception as e:
            trend['error'] = f'Query failed: {str(e)}'
            logger.error(f"Trend data query failed for {metric}: {e}")

        self.results['trend_data'] = trend
        return trend

    def get_financial_loss_summary(self, date_range: Optional[Tuple[str, str]] = None) -> Dict:
        """
        Get financial loss summary: total, by type, by province.

        Args:
            date_range: Optional tuple of (start_date, end_date) ISO strings

        Returns:
            Dict with financial loss summary
        """
        summary = {
            'total_loss': 0,
            'total_victims': 0,
            'average_loss': 0,
            'by_type': {},
            'by_province': {},
            'by_currency': {},
            'largest_loss': 0,
            'error': None
        }

        try:
            from app import db
            from app.models import Victim
            from sqlalchemy import func

            query = Victim.query

            if date_range:
                start, end = date_range
                try:
                    start_dt = datetime.fromisoformat(start)
                    end_dt = datetime.fromisoformat(end)
                    query = query.filter(
                        Victim.created_at >= start_dt,
                        Victim.created_at <= end_dt
                    )
                except (ValueError, TypeError):
                    pass

            # Totals
            agg = query.with_entities(
                func.sum(Victim.loss_amount).label('total'),
                func.count(Victim.id).label('count'),
                func.avg(Victim.loss_amount).label('avg'),
                func.max(Victim.loss_amount).label('max')
            ).first()

            if agg:
                summary['total_loss'] = float(agg.total or 0)
                summary['total_victims'] = int(agg.count or 0)
                summary['average_loss'] = round(float(agg.avg or 0), 2)
                summary['largest_loss'] = float(agg.max or 0)

            # By type
            type_agg = query.with_entities(
                Victim.loss_type,
                func.sum(Victim.loss_amount).label('total'),
                func.count(Victim.id).label('count')
            ).group_by(Victim.loss_type).all()

            for row in type_agg:
                summary['by_type'][row.loss_type or 'unknown'] = {
                    'total': float(row.total or 0),
                    'count': int(row.count or 0)
                }

            # By province
            province_agg = query.with_entities(
                Victim.province,
                func.sum(Victim.loss_amount).label('total'),
                func.count(Victim.id).label('count')
            ).group_by(Victim.province).all()

            for row in province_agg:
                summary['by_province'][row.province or 'Unknown'] = {
                    'total': float(row.total or 0),
                    'count': int(row.count or 0)
                }

            # By currency
            currency_agg = query.with_entities(
                Victim.loss_currency,
                func.sum(Victim.loss_amount).label('total'),
                func.count(Victim.id).label('count')
            ).group_by(Victim.loss_currency).all()

            for row in currency_agg:
                summary['by_currency'][row.loss_currency or 'ZMW'] = {
                    'total': float(row.total or 0),
                    'count': int(row.count or 0)
                }

            logger.info(f"Financial loss summary generated: {summary['total_loss']} total")

        except ImportError:
            summary['error'] = 'Database not available'
            logger.debug("Database not available for financial summary")
        except Exception as e:
            summary['error'] = f'Query failed: {str(e)}'
            logger.error(f"Financial loss summary query failed: {e}")

        self.results['financial_summary'] = summary
        return summary

    def get_threat_statistics(self, date_range: Optional[Tuple[str, str]] = None) -> Dict:
        """
        Get threat intelligence statistics.

        Args:
            date_range: Optional tuple of (start_date, end_date) ISO strings

        Returns:
            Dict with threat statistics
        """
        stats = {
            'total': 0,
            'active': 0,
            'by_type': {},
            'by_severity': {},
            'by_threat_type': {},
            'by_source': {},
            'error': None
        }

        try:
            from app import db
            from app.models import ThreatIndicator
            from sqlalchemy import func

            query = ThreatIndicator.query

            if date_range:
                start, end = date_range
                try:
                    start_dt = datetime.fromisoformat(start)
                    end_dt = datetime.fromisoformat(end)
                    query = query.filter(
                        ThreatIndicator.created_at >= start_dt,
                        ThreatIndicator.created_at <= end_dt
                    )
                except (ValueError, TypeError):
                    pass

            stats['total'] = query.count()
            stats['active'] = query.filter_by(is_active=True).count()

            # By indicator type
            type_counts = query.with_entities(
                ThreatIndicator.indicator_type,
                func.count(ThreatIndicator.id)
            ).group_by(ThreatIndicator.indicator_type).all()
            stats['by_type'] = {t or 'unknown': c for t, c in type_counts}

            # By severity
            severity_counts = query.with_entities(
                ThreatIndicator.severity,
                func.count(ThreatIndicator.id)
            ).group_by(ThreatIndicator.severity).all()
            stats['by_severity'] = {s or 'unknown': c for s, c in severity_counts}

            # By threat type
            threat_counts = query.with_entities(
                ThreatIndicator.threat_type,
                func.count(ThreatIndicator.id)
            ).group_by(ThreatIndicator.threat_type).all()
            stats['by_threat_type'] = {t or 'unknown': c for t, c in threat_counts}

            # By source
            source_counts = query.with_entities(
                ThreatIndicator.source,
                func.count(ThreatIndicator.id)
            ).group_by(ThreatIndicator.source).all()
            stats['by_source'] = {s or 'unknown': c for s, c in source_counts}

            logger.info(f"Threat statistics generated: {stats['total']} total")

        except ImportError:
            stats['error'] = 'Database not available'
            logger.debug("Database not available for threat statistics")
        except Exception as e:
            stats['error'] = f'Query failed: {str(e)}'
            logger.error(f"Threat statistics query failed: {e}")

        self.results['threat_statistics'] = stats
        return stats

    def generate_executive_summary(self, start_date: str, end_date: str) -> Dict:
        """
        Generate a comprehensive executive summary for a date range.

        Args:
            start_date: Start date ISO string
            end_date: End date ISO string

        Returns:
            Dict with executive summary covering all major areas
        """
        self.start_time = time.time()
        self.results['metadata']['generated_at'] = datetime.utcnow().isoformat()

        date_range = (start_date, end_date)

        summary = {
            'period': {
                'start': start_date,
                'end': end_date
            },
            'cases': {},
            'investigations': {},
            'financial': {},
            'threats': {},
            'performance': {},
            'highlights': [],
            'error': None
        }

        # Case statistics
        try:
            summary['cases'] = self.get_case_statistics(date_range)
        except Exception as e:
            summary['cases'] = {'error': str(e)}
            logger.error(f"Executive summary - case stats failed: {e}")

        # Investigation statistics
        try:
            summary['investigations'] = self.get_investigation_statistics(date_range)
        except Exception as e:
            summary['investigations'] = {'error': str(e)}
            logger.error(f"Executive summary - investigation stats failed: {e}")

        # Financial loss summary
        try:
            summary['financial'] = self.get_financial_loss_summary(date_range)
        except Exception as e:
            summary['financial'] = {'error': str(e)}
            logger.error(f"Executive summary - financial stats failed: {e}")

        # Threat statistics
        try:
            summary['threats'] = self.get_threat_statistics(date_range)
        except Exception as e:
            summary['threats'] = {'error': str(e)}
            logger.error(f"Executive summary - threat stats failed: {e}")

        # Performance metrics
        try:
            summary['performance'] = self.get_performance_metrics()
        except Exception as e:
            summary['performance'] = {'error': str(e)}
            logger.error(f"Executive summary - performance metrics failed: {e}")

        # Generate highlights
        highlights = []
        cases = summary.get('cases', {})
        if cases.get('total', 0) > 0:
            highlights.append(
                f"Total cases in period: {cases['total']} "
                f"(closure rate: {cases.get('closure_rate', 0)}%)"
            )

        financial = summary.get('financial', {})
        if financial.get('total_loss', 0) > 0:
            highlights.append(
                f"Total financial losses: ZMW {financial['total_loss']:,.2f} "
                f"across {financial.get('total_victims', 0)} victims"
            )

        threats = summary.get('threats', {})
        if threats.get('total', 0) > 0:
            highlights.append(
                f"Threat indicators tracked: {threats['total']} "
                f"({threats.get('active', 0)} active)"
            )

        investigations = summary.get('investigations', {})
        if investigations.get('total', 0) > 0:
            highlights.append(
                f"Investigations conducted: {investigations['total']} "
                f"(success rate: {investigations.get('success_rate', 0)}%)"
            )

        summary['highlights'] = highlights

        self.results['executive_summary'] = summary
        self.results['metadata']['generation_duration'] = time.time() - self.start_time
        self.results['metadata']['api_calls_made'] = self.api_calls

        return summary


def get_dashboard_stats() -> Dict:
    """
    Convenience function to get dashboard statistics.

    Returns:
        Dict with all dashboard-relevant statistics
    """
    engine = AnalyticsEngine()

    dashboard = {
        'cases': {},
        'investigations': {},
        'performance': {},
        'financial': {},
        'threats': {},
        'generated_at': datetime.utcnow().isoformat()
    }

    try:
        dashboard['cases'] = engine.get_case_statistics()
    except Exception as e:
        dashboard['cases'] = {'error': str(e)}

    try:
        dashboard['investigations'] = engine.get_investigation_statistics()
    except Exception as e:
        dashboard['investigations'] = {'error': str(e)}

    try:
        dashboard['performance'] = engine.get_performance_metrics()
    except Exception as e:
        dashboard['performance'] = {'error': str(e)}

    try:
        dashboard['financial'] = engine.get_financial_loss_summary()
    except Exception as e:
        dashboard['financial'] = {'error': str(e)}

    try:
        dashboard['threats'] = engine.get_threat_statistics()
    except Exception as e:
        dashboard['threats'] = {'error': str(e)}

    return dashboard
