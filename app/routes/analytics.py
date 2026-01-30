"""
Analytics Dashboard Routes
Zambia Police Service CyberTrace OSINT Platform

Comprehensive analytics, case statistics, performance metrics, and data export
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_login import current_user
from app import db
from app.models.case import Case
from app.models.investigation import Investigation
from app.models.audit_log import AuditLog
from app.utils.decorators import login_required, permission_required
from datetime import datetime
import os, tempfile, time

analytics_bp = Blueprint('analytics', __name__)


@analytics_bp.route('/')
@login_required
def dashboard():
    """Comprehensive analytics dashboard"""
    try:
        from app.modules.analytics_engine import AnalyticsEngine

        engine = AnalyticsEngine()
        stats = engine.get_comprehensive_stats()
    except Exception:
        # Fallback to basic stats from models
        from sqlalchemy import func

        total_cases = Case.query.count()
        open_cases = Case.query.filter_by(status='open').count()
        investigating_cases = Case.query.filter_by(status='investigating').count()
        closed_cases = Case.query.filter_by(status='closed').count()
        total_investigations = Investigation.query.count()
        completed_investigations = Investigation.query.filter_by(status='completed').count()

        stats = {
            'total_cases': total_cases,
            'open_cases': open_cases,
            'investigating_cases': investigating_cases,
            'closed_cases': closed_cases,
            'total_investigations': total_investigations,
            'completed_investigations': completed_investigations,
            'total_losses': 0,
            'success_rate': round((completed_investigations / total_investigations * 100), 1) if total_investigations > 0 else 0,
        }

    AuditLog.log_action(
        user_id=current_user.id,
        username=current_user.username,
        badge_number=current_user.badge_number,
        action='view_analytics_dashboard',
        action_category='system',
        resource_type='analytics',
        ip_address=request.remote_addr
    )

    # Provide chart_data for Plotly visualizations
    chart_data = {
        'cases_by_type': {},
        'cases_by_month': {},
        'investigations_by_type': {},
        'top_threats': {}
    }
    try:
        from sqlalchemy import func
        # Cases by type
        type_counts = db.session.query(Case.case_type, func.count(Case.id)).group_by(Case.case_type).all()
        chart_data['cases_by_type'] = {t: c for t, c in type_counts if t}
        # Investigations by type
        inv_counts = db.session.query(Investigation.investigation_type, func.count(Investigation.id)).group_by(Investigation.investigation_type).all()
        chart_data['investigations_by_type'] = {t: c for t, c in inv_counts if t}
    except Exception:
        pass

    return render_template('analytics/dashboard.html',
                         stats=stats,
                         chart_data=chart_data)


@analytics_bp.route('/cases')
@login_required
def case_stats():
    """Case-specific statistics and analysis"""
    from sqlalchemy import func

    # Case counts by status
    status_counts = db.session.query(
        Case.status,
        func.count(Case.id).label('count')
    ).group_by(Case.status).all()

    # Case counts by type/category
    try:
        type_counts = db.session.query(
            Case.case_type,
            func.count(Case.id).label('count')
        ).group_by(Case.case_type).all()
    except Exception:
        type_counts = []

    # Monthly case creation trend
    try:
        monthly_trend = db.session.query(
            func.strftime('%Y-%m', Case.created_at).label('month'),
            func.count(Case.id).label('count')
        ).group_by('month').order_by('month').limit(12).all()
    except Exception:
        # PostgreSQL compatible
        try:
            monthly_trend = db.session.query(
                func.to_char(Case.created_at, 'YYYY-MM').label('month'),
                func.count(Case.id).label('count')
            ).group_by('month').order_by('month').limit(12).all()
        except Exception:
            monthly_trend = []

    # Investigations per case
    investigation_stats = db.session.query(
        func.count(Investigation.id).label('total'),
        func.avg(Investigation.execution_time).label('avg_time')
    ).first()

    case_statistics = {
        'status_counts': [{'status': sc.status, 'count': sc.count} for sc in status_counts],
        'type_counts': [{'type': tc.case_type, 'count': tc.count} for tc in type_counts] if type_counts else [],
        'monthly_trend': [{'month': mt.month, 'count': mt.count} for mt in monthly_trend] if monthly_trend else [],
        'investigation_stats': {
            'total': investigation_stats.total if investigation_stats else 0,
            'avg_execution_time': round(investigation_stats.avg_time or 0, 2) if investigation_stats else 0
        }
    }

    # Build stats dict expected by the template
    stats = {
        'resolution_rate': 0,
        'avg_days_to_close': 0,
        'total_closed': 0,
        'by_priority': [],
        'by_status': case_statistics['status_counts'],
        'monthly_trends': [
            {
                'label': m['month'],
                'opened': m['count'],
                'closed': 0,
                'net_change': m['count'],
            } for m in case_statistics['monthly_trend']
        ],
    }
    # Calculate resolution rate
    total = sum(s['count'] for s in case_statistics['status_counts'])
    closed = sum(s['count'] for s in case_statistics['status_counts'] if s['status'] == 'closed')
    if total > 0:
        stats['resolution_rate'] = (closed / total) * 100
    stats['total_closed'] = closed

    return render_template('analytics/case_stats.html',
                         case_statistics=case_statistics,
                         stats=stats)


@analytics_bp.route('/performance')
@login_required
def performance():
    """System and investigator performance metrics"""
    from sqlalchemy import func

    # Investigations by type
    investigations_by_type = db.session.query(
        Investigation.investigation_type,
        func.count(Investigation.id).label('count'),
        func.avg(Investigation.execution_time).label('avg_time')
    ).group_by(Investigation.investigation_type).all()

    # Top investigators (by completed investigations)
    top_investigators = db.session.query(
        Investigation.investigator_id,
        func.count(Investigation.id).label('count')
    ).filter_by(
        status='completed'
    ).group_by(
        Investigation.investigator_id
    ).order_by(func.count(Investigation.id).desc()).limit(10).all()

    # Average response time
    avg_execution = db.session.query(
        func.avg(Investigation.execution_time)
    ).filter_by(status='completed').scalar() or 0

    # Success/failure rates
    total_investigations = Investigation.query.count()
    completed = Investigation.query.filter_by(status='completed').count()
    failed = Investigation.query.filter_by(status='failed').count()

    performance_data = {
        'investigations_by_type': [
            {
                'type': ibt.investigation_type,
                'count': ibt.count,
                'avg_time': round(ibt.avg_time or 0, 2)
            }
            for ibt in investigations_by_type
        ],
        'top_investigators': [
            {'investigator_id': ti.investigator_id, 'count': ti.count}
            for ti in top_investigators
        ],
        'avg_execution_time': round(avg_execution, 2),
        'total_investigations': total_investigations,
        'completed': completed,
        'failed': failed,
        'success_rate': round((completed / total_investigations * 100), 1) if total_investigations > 0 else 0
    }

    return render_template('analytics/performance.html',
                         performance=performance_data)


@analytics_bp.route('/export')
@login_required
def export_data():
    """Data export interface"""
    cases = Case.query.count()
    investigations = Investigation.query.count()

    export_info = {
        'total_cases': cases,
        'total_investigations': investigations,
        'export_formats': ['csv', 'json', 'pdf'],
        'export_types': [
            'cases', 'investigations', 'audit_logs',
            'financial_transactions', 'victim_records'
        ]
    }

    return render_template('analytics/export.html',
                         export_info=export_info)


@analytics_bp.route('/api/chart-data/<chart_type>')
@login_required
def chart_data(chart_type):
    """Return JSON data for AJAX chart loading"""
    from sqlalchemy import func

    try:
        if chart_type == 'case_status':
            data = db.session.query(
                Case.status,
                func.count(Case.id).label('count')
            ).group_by(Case.status).all()

            return jsonify({
                'success': True,
                'labels': [d.status for d in data],
                'values': [d.count for d in data]
            })

        elif chart_type == 'investigation_types':
            data = db.session.query(
                Investigation.investigation_type,
                func.count(Investigation.id).label('count')
            ).group_by(Investigation.investigation_type).all()

            return jsonify({
                'success': True,
                'labels': [d.investigation_type for d in data],
                'values': [d.count for d in data]
            })

        elif chart_type == 'monthly_cases':
            try:
                data = db.session.query(
                    func.strftime('%Y-%m', Case.created_at).label('month'),
                    func.count(Case.id).label('count')
                ).group_by('month').order_by('month').limit(12).all()
            except Exception:
                try:
                    data = db.session.query(
                        func.to_char(Case.created_at, 'YYYY-MM').label('month'),
                        func.count(Case.id).label('count')
                    ).group_by('month').order_by('month').limit(12).all()
                except Exception:
                    data = []

            return jsonify({
                'success': True,
                'labels': [d.month for d in data],
                'values': [d.count for d in data]
            })

        elif chart_type == 'investigation_success':
            completed = Investigation.query.filter_by(status='completed').count()
            failed = Investigation.query.filter_by(status='failed').count()
            pending = Investigation.query.filter_by(status='pending').count()

            return jsonify({
                'success': True,
                'labels': ['Completed', 'Failed', 'Pending'],
                'values': [completed, failed, pending]
            })

        elif chart_type == 'daily_activity':
            try:
                data = db.session.query(
                    func.strftime('%Y-%m-%d', AuditLog.timestamp).label('day'),
                    func.count(AuditLog.id).label('count')
                ).group_by('day').order_by('day').limit(30).all()
            except Exception:
                try:
                    data = db.session.query(
                        func.to_char(AuditLog.timestamp, 'YYYY-MM-DD').label('day'),
                        func.count(AuditLog.id).label('count')
                    ).group_by('day').order_by('day').limit(30).all()
                except Exception:
                    data = []

            return jsonify({
                'success': True,
                'labels': [d.day for d in data],
                'values': [d.count for d in data]
            })

        else:
            return jsonify({
                'success': False,
                'error': f'Unknown chart type: {chart_type}'
            }), 400

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
