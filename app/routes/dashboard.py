"""
Dashboard Routes
CyberTrace OSINT Platform - Zambia Police Service

Main dashboard and overview
"""

from flask import Blueprint, render_template, redirect, url_for
from flask_login import current_user
from app.models.case import Case
from app.models.investigation import Investigation
from app.models.evidence import Evidence
from app.utils.decorators import login_required, account_active_required
from sqlalchemy import func, desc
from datetime import datetime, timedelta

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
@login_required
@account_active_required
def index():
    """Main dashboard"""

    # Get statistics
    stats = get_dashboard_stats()

    # Get recent cases
    if current_user.role in ['admin', 'senior_investigator']:
        recent_cases = Case.query.order_by(desc(Case.created_at)).limit(5).all()
    else:
        # Show only assigned cases
        recent_cases = Case.query.filter(
            (Case.lead_investigator_id == current_user.id) |
            (Case.assigned_officers.contains([current_user.id]))
        ).order_by(desc(Case.created_at)).limit(5).all()

    # Get recent investigations
    recent_investigations = Investigation.query.filter_by(
        investigator_id=current_user.id
    ).order_by(desc(Investigation.created_at)).limit(5).all()

    return render_template(
        'dashboard/index.html',
        stats=stats,
        recent_cases=recent_cases,
        recent_investigations=recent_investigations,
        now=datetime.utcnow()
    )


def get_dashboard_stats():
    """
    Get dashboard statistics

    Returns:
        dict: Statistics data
    """
    stats = {}

    # Case statistics
    if current_user.role in ['admin', 'senior_investigator']:
        # All cases
        stats['total_cases'] = Case.query.count()
        stats['open_cases'] = Case.query.filter_by(status='open').count()
        stats['investigating_cases'] = Case.query.filter_by(status='investigating').count()
        stats['closed_cases'] = Case.query.filter_by(status='closed').count()
    else:
        # Only assigned cases
        stats['total_cases'] = Case.query.filter(
            (Case.lead_investigator_id == current_user.id) |
            (Case.assigned_officers.contains([current_user.id]))
        ).count()
        stats['open_cases'] = Case.query.filter(
            ((Case.lead_investigator_id == current_user.id) |
             (Case.assigned_officers.contains([current_user.id]))) &
            (Case.status == 'open')
        ).count()
        stats['investigating_cases'] = Case.query.filter(
            ((Case.lead_investigator_id == current_user.id) |
             (Case.assigned_officers.contains([current_user.id]))) &
            (Case.status == 'investigating')
        ).count()
        stats['closed_cases'] = Case.query.filter(
            ((Case.lead_investigator_id == current_user.id) |
             (Case.assigned_officers.contains([current_user.id]))) &
            (Case.status == 'closed')
        ).count()

    # Investigation statistics
    stats['total_investigations'] = Investigation.query.filter_by(
        investigator_id=current_user.id
    ).count()

    stats['investigations_this_month'] = Investigation.query.filter(
        Investigation.investigator_id == current_user.id,
        Investigation.created_at >= datetime.utcnow() - timedelta(days=30)
    ).count()

    # Evidence statistics
    stats['total_evidence'] = Evidence.query.filter_by(
        collected_by=current_user.id
    ).count()

    # Recent activity (last 7 days)
    week_ago = datetime.utcnow() - timedelta(days=7)
    stats['investigations_this_week'] = Investigation.query.filter(
        Investigation.investigator_id == current_user.id,
        Investigation.created_at >= week_ago
    ).count()

    return stats
