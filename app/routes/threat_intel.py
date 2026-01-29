"""
Threat Intelligence Routes
Zambia Police Service CyberTrace OSINT Platform

Routes for threat intelligence dashboard, search, and public reporting
"""

from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from sqlalchemy import desc, func
from datetime import datetime, timedelta

from app import db, csrf
from app.models.threat_intel import ThreatIntel
from app.models.audit_log import AuditLog
from app.modules.threat_intelligence import ThreatIntelligenceService
from app.utils.decorators import admin_required

threat_intel_bp = Blueprint('threat_intel', __name__)


@threat_intel_bp.route('/threat-intel/help')
def help_guide():
    """Interactive help guide for threat intelligence"""
    return render_template('threat_intel/help.html')


@threat_intel_bp.route('/threat-intel/dashboard')
@login_required
def dashboard():
    """Threat Intelligence Dashboard"""
    # Get statistics
    stats = ThreatIntel.get_statistics()

    # Get recent threats (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_threats = ThreatIntel.query.filter(
        ThreatIntel.created_at >= thirty_days_ago,
        ThreatIntel.status == 'active'
    ).order_by(desc(ThreatIntel.created_at)).limit(10).all()

    # Get critical threats
    critical_threats = ThreatIntel.query.filter_by(
        severity='critical',
        status='active'
    ).order_by(desc(ThreatIntel.last_seen)).limit(10).all()

    # Get top threat types (last 30 days)
    threat_type_stats = db.session.query(
        ThreatIntel.threat_type,
        func.count(ThreatIntel.id).label('count')
    ).filter(
        ThreatIntel.created_at >= thirty_days_ago,
        ThreatIntel.status == 'active'
    ).group_by(ThreatIntel.threat_type).all()

    # Get threats by region (Zambia)
    regional_stats = db.session.query(
        ThreatIntel.region,
        func.count(ThreatIntel.id).label('count')
    ).filter(
        ThreatIntel.country_code == 'ZM',
        ThreatIntel.status == 'active'
    ).group_by(ThreatIntel.region).all()

    # Log access
    AuditLog.log_action(
        user_id=current_user.id,
        username=current_user.username,
        badge_number=current_user.badge_number,
        action='view',
        action_category='threat_intelligence',
        resource_type='threat_intelligence',
        resource_id='dashboard',
        details={'page': 'dashboard'},
        ip_address=request.remote_addr
    )

    return render_template(
        'threat_intel/dashboard.html',
        stats=stats,
        recent_threats=recent_threats,
        critical_threats=critical_threats,
        threat_type_stats=threat_type_stats,
        regional_stats=regional_stats
    )


@threat_intel_bp.route('/threat-intel/search', methods=['GET', 'POST'])
@login_required
def search():
    """Search threat intelligence"""
    results = None
    search_performed = False

    if request.method == 'POST':
        indicator = request.form.get('indicator', '').strip()
        indicator_type = request.form.get('indicator_type', 'auto')
        search_external = request.form.get('search_external') == 'on'

        if not indicator:
            flash('Please enter an indicator to search', 'warning')
            return redirect(url_for('threat_intel.search'))

        search_performed = True

        # Search local database
        local_results = []
        if indicator_type == 'auto' or indicator_type == 'phone_number':
            local_results.extend(ThreatIntel.find_by_indicator('phone_number', indicator))
        if indicator_type == 'auto' or indicator_type == 'email_address':
            local_results.extend(ThreatIntel.find_by_indicator('email_address', indicator))
        if indicator_type == 'auto' or indicator_type == 'domain':
            local_results.extend(ThreatIntel.find_by_indicator('domain', indicator))
        if indicator_type == 'auto' or indicator_type == 'ip_address':
            local_results.extend(ThreatIntel.find_by_indicator('ip_address', indicator))

        # Search external sources if requested
        external_results = None
        if search_external:
            try:
                ti_service = ThreatIntelligenceService()

                # Auto-detect type if needed
                if indicator_type == 'auto':
                    if '@' in indicator:
                        detected_type = 'email_address'
                    elif indicator.replace('.', '').replace('+', '').replace('-', '').isdigit():
                        detected_type = 'phone_number'
                    elif '.' in indicator and not indicator.replace('.', '').isdigit():
                        detected_type = 'domain'
                    else:
                        detected_type = 'ip_address'
                else:
                    detected_type = indicator_type

                external_results = ti_service.check_indicator(indicator, detected_type)
            except Exception as e:
                flash(f'Error checking external sources: {str(e)}', 'danger')

        results = {
            'local': local_results,
            'external': external_results,
            'indicator': indicator,
            'indicator_type': indicator_type
        }

        # Log search
        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='search',
            action_category='threat_intelligence',
            resource_type='threat_intelligence',
            resource_identifier=indicator,
            details={
                'indicator_type': indicator_type,
                'search_external': search_external,
                'local_results': len(local_results),
                'external_found': external_results.get('sources_found', []) if external_results else []
            },
            ip_address=request.remote_addr
        )

    return render_template(
        'threat_intel/search.html',
        results=results,
        search_performed=search_performed
    )


@threat_intel_bp.route('/threat-intel/report/<threat_id>')
@login_required
def view_report(threat_id):
    """View detailed threat report"""
    threat = ThreatIntel.query.get_or_404(threat_id)

    # Log access
    AuditLog.log_action(
        user_id=current_user.id,
        username=current_user.username,
        badge_number=current_user.badge_number,
        action='view',
        action_category='threat_intelligence',
        resource_type='threat_intelligence',
        resource_id=threat.id,
        details={'indicator': threat.get_primary_indicator()},
        ip_address=request.remote_addr
    )

    return render_template('threat_intel/report.html', threat=threat)


@threat_intel_bp.route('/threat-intel/verify/<threat_id>', methods=['POST'])
@login_required
@admin_required
def verify_threat(threat_id):
    """Verify a threat (admin only)"""
    threat = ThreatIntel.query.get_or_404(threat_id)

    threat.mark_verified(current_user.id)

    # Log verification
    AuditLog.log_action(
        user_id=current_user.id,
        username=current_user.username,
        badge_number=current_user.badge_number,
        action='update',
        action_category='threat_intelligence',
        resource_type='threat_intelligence',
        resource_id=threat.id,
        details={'action': 'verified', 'indicator': threat.get_primary_indicator()},
        ip_address=request.remote_addr
    )

    flash('Threat verified successfully', 'success')
    return redirect(url_for('threat_intel.view_report', threat_id=threat_id))


@threat_intel_bp.route('/threat-intel/false-positive/<threat_id>', methods=['POST'])
@login_required
@admin_required
def mark_false_positive(threat_id):
    """Mark threat as false positive (admin only)"""
    threat = ThreatIntel.query.get_or_404(threat_id)
    reason = request.form.get('reason', 'Marked as false positive by investigator')

    threat.mark_false_positive(reason)

    # Log action
    AuditLog.log_action(
        user_id=current_user.id,
        username=current_user.username,
        badge_number=current_user.badge_number,
        action='update',
        action_category='threat_intelligence',
        resource_type='threat_intelligence',
        resource_id=threat.id,
        details={'action': 'false_positive', 'reason': reason},
        ip_address=request.remote_addr
    )

    flash('Threat marked as false positive', 'success')
    return redirect(url_for('threat_intel.dashboard'))


# Public Reporting Routes (No login required)

@threat_intel_bp.route('/threat-intel/public/report', methods=['GET', 'POST'])
def public_report():
    """Public threat reporting form"""
    if request.method == 'POST':
        # Get form data
        indicator_type = request.form.get('indicator_type')
        indicator_value = request.form.get('indicator_value', '').strip()
        threat_type = request.form.get('threat_type')
        description = request.form.get('description', '').strip()
        financial_loss = request.form.get('financial_loss', '0')
        reporter_name = request.form.get('reporter_name', 'Anonymous')
        reporter_contact = request.form.get('reporter_contact', '')

        if not indicator_value or not threat_type:
            flash('Please provide the indicator and threat type', 'danger')
            return redirect(url_for('threat_intel.public_report'))

        try:
            # Create threat intelligence entry
            threat_data = {
                'threat_type': threat_type,
                'description': description,
                'source': 'public_report',
                'status': 'investigating',  # Requires verification
                'confidence_score': 30,  # Low confidence until verified
                'verified': False,
                'source_details': {
                    'reporter_name': reporter_name,
                    'reporter_contact': reporter_contact,
                    'report_date': datetime.utcnow().isoformat()
                }
            }

            # Add financial loss if provided
            try:
                threat_data['financial_loss'] = float(financial_loss) if financial_loss else 0.0
            except ValueError:
                threat_data['financial_loss'] = 0.0

            # Set the appropriate indicator field
            if indicator_type == 'phone_number':
                threat_data['phone_number'] = indicator_value
            elif indicator_type == 'email_address':
                threat_data['email_address'] = indicator_value
            elif indicator_type == 'domain':
                threat_data['domain'] = indicator_value
            elif indicator_type == 'url':
                threat_data['url'] = indicator_value
            else:
                flash('Invalid indicator type', 'danger')
                return redirect(url_for('threat_intel.public_report'))

            threat = ThreatIntel(**threat_data)
            db.session.add(threat)
            db.session.commit()

            # Log public report
            AuditLog.log_action(
                user_id='public',
                username='Public Reporter',
                badge_number='N/A',
                action='create',
                action_category='threat_intelligence',
                resource_type='threat_intelligence',
                resource_id=threat.id,
                details={
                    'source': 'public_report',
                    'indicator_type': indicator_type,
                    'threat_type': threat_type
                },
                ip_address=request.remote_addr
            )

            return redirect(url_for('threat_intel.report_success'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error submitting report: {str(e)}', 'danger')
            return redirect(url_for('threat_intel.public_report'))

    return render_template('threat_intel/public_report.html')


@threat_intel_bp.route('/threat-intel/public/success')
def report_success():
    """Thank you page after public report submission"""
    return render_template('threat_intel/report_success.html')


# API Endpoints

@threat_intel_bp.route('/threat-intel/api/check', methods=['POST'])
@login_required
@csrf.exempt
def api_check():
    """API endpoint to check indicator against threat intelligence"""
    data = request.get_json()

    if not data or 'indicator' not in data or 'type' not in data:
        return jsonify({
            'success': False,
            'error': 'Missing required fields: indicator and type'
        }), 400

    indicator = data['indicator']
    indicator_type = data['type']

    try:
        ti_service = ThreatIntelligenceService()
        results = ti_service.check_indicator(indicator, indicator_type)

        return jsonify({
            'success': True,
            'results': results
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@threat_intel_bp.route('/threat-intel/api/stats')
@login_required
def api_stats():
    """API endpoint for threat intelligence statistics"""
    stats = ThreatIntel.get_statistics()
    return jsonify({
        'success': True,
        'stats': stats
    })
