"""
Correlation Engine Routes
Zambia Police Service CyberTrace OSINT Platform

Cross-case correlation, threat actor profiling, and network visualization
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

correlation_bp = Blueprint('correlation', __name__)


@correlation_bp.route('/')
@login_required
def dashboard():
    """Correlation engine dashboard with summary statistics"""
    try:
        from app.modules.correlation_engine import CorrelationEngine
        engine = CorrelationEngine()
        stats = engine.get_statistics()
    except Exception:
        stats = {
            'total_indicators': 0,
            'total_matches': 0,
            'unreviewed_matches': 0,
            'pending_review': 0,
            'confirmed_matches': 0,
            'threat_actors': 0,
            'linked_cases': 0
        }

    # Get recent correlation matches
    try:
        from app.models.correlation import CorrelationMatch
        recent_matches = CorrelationMatch.query.order_by(
            CorrelationMatch.created_at.desc()
        ).limit(10).all()
    except Exception:
        recent_matches = []

    AuditLog.log_action(
        user_id=current_user.id,
        username=current_user.username,
        badge_number=current_user.badge_number,
        action='view_correlation_dashboard',
        action_category='investigation',
        resource_type='correlation',
        ip_address=request.remote_addr
    )

    return render_template('correlation/dashboard.html',
                         stats=stats,
                         recent_matches=recent_matches)


@correlation_bp.route('/run', methods=['POST'])
@login_required
def run_correlation():
    """Run the correlation engine to find cross-case matches"""
    try:
        from app.modules.correlation_engine import CorrelationEngine

        start_time = time.time()
        engine = CorrelationEngine()
        results = engine.find_matches()
        execution_time = time.time() - start_time

        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='run_correlation_engine',
            action_category='investigation',
            resource_type='correlation',
            details={
                'matches_found': results.get('matches_found', 0),
                'execution_time': execution_time,
                'cases_analyzed': results.get('cases_analyzed', 0)
            },
            ip_address=request.remote_addr
        )

        flash(f'Correlation analysis completed! {results.get("matches_found", 0)} potential matches found.', 'success')

    except Exception as e:
        flash(f'Correlation analysis failed: {str(e)}', 'danger')

        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='correlation_engine_failed',
            action_category='investigation',
            resource_type='correlation',
            details={'error': str(e)},
            status='failure',
            error_message=str(e),
            ip_address=request.remote_addr
        )

    return redirect(url_for('correlation.view_matches'))


@correlation_bp.route('/matches')
@login_required
def view_matches():
    """View correlation match results"""
    try:
        from app.models.correlation import CorrelationMatch

        page = request.args.get('page', 1, type=int)
        status_filter = request.args.get('status', 'all')

        query = CorrelationMatch.query

        if status_filter == 'pending':
            query = query.filter_by(reviewed=False)
        elif status_filter == 'reviewed':
            query = query.filter_by(reviewed=True)

        matches = query.order_by(
            CorrelationMatch.created_at.desc()
        ).paginate(page=page, per_page=20, error_out=False)
    except Exception:
        matches = None

    return render_template('correlation/matches.html',
                         matches=matches,
                         status_filter=request.args.get('status', 'all'))


@correlation_bp.route('/<match_id>/review', methods=['POST'])
@login_required
def review_match(match_id):
    """Review and update a correlation match"""
    try:
        from app.models.correlation import CorrelationMatch

        match = CorrelationMatch.query.get_or_404(match_id)

        reviewed_status = request.form.get('confirmed', 'false') == 'true'
        review_notes = request.form.get('notes', '')

        match.reviewed = True
        match.confirmed = reviewed_status
        match.reviewed_by = current_user.id
        match.reviewed_at = datetime.utcnow()
        if review_notes:
            match.review_notes = review_notes

        db.session.commit()

        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='review_correlation_match',
            action_category='investigation',
            resource_type='correlation_match',
            resource_id=str(match_id),
            details={
                'confirmed': reviewed_status,
                'notes': review_notes
            },
            ip_address=request.remote_addr
        )

        flash('Correlation match reviewed successfully.', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Failed to review match: {str(e)}', 'danger')

    return redirect(url_for('correlation.view_matches'))


@correlation_bp.route('/actors')
@login_required
def list_actors():
    """List threat actor profiles"""
    try:
        from app.models.correlation import ThreatActorProfile

        actors = ThreatActorProfile.query.order_by(
            ThreatActorProfile.created_at.desc()
        ).all()
    except Exception:
        actors = []

    return render_template('correlation/actor_list.html',
                         actors=actors)


@correlation_bp.route('/actors/<actor_id>')
@login_required
def view_actor(actor_id):
    """View threat actor profile details"""
    try:
        from app.models.correlation import ThreatActorProfile

        actor = ThreatActorProfile.query.get_or_404(actor_id)

        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='view_threat_actor',
            action_category='investigation',
            resource_type='threat_actor',
            resource_id=str(actor_id),
            details={'actor_name': actor.name if hasattr(actor, 'name') else str(actor_id)},
            ip_address=request.remote_addr
        )

        return render_template('correlation/actor_profile.html',
                             actor=actor)

    except Exception as e:
        flash(f'Failed to load threat actor profile: {str(e)}', 'danger')
        return redirect(url_for('correlation.list_actors'))


@correlation_bp.route('/network')
@login_required
def network_viz():
    """Network visualization of correlated entities"""
    try:
        from app.modules.correlation_engine import CorrelationEngine

        engine = CorrelationEngine()
        network_data = engine.get_network_data()
    except Exception:
        network_data = {'nodes': [], 'links': []}

    return render_template('correlation/network_viz.html',
                         network_data=network_data)
