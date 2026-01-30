"""
Domain & IP Investigation Routes
Zambia Police Service CyberTrace OSINT Platform

Domain and IP address OSINT investigation operations
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

domain_ip_bp = Blueprint('domain_ip', __name__)


def _get_user_cases():
    """Get cases accessible by the current user"""
    if current_user.role in ['admin', 'senior_investigator']:
        cases = Case.query.filter(Case.status.in_(['open', 'investigating'])).order_by(Case.created_at.desc()).all()
    else:
        cases = Case.query.filter(
            ((Case.lead_investigator_id == current_user.id) |
             (Case.assigned_officers.contains([current_user.id]))) &
            (Case.status.in_(['open', 'investigating']))
        ).order_by(Case.created_at.desc()).all()
    return cases


@domain_ip_bp.route('/domain', methods=['GET', 'POST'])
@login_required
def domain_search():
    """Domain OSINT search"""
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        case_id = request.form.get('case_id')

        if not domain:
            flash('Domain name is required.', 'danger')
            return redirect(url_for('domain_ip.domain_search'))

        if not case_id:
            flash('Please select a case to link this investigation.', 'danger')
            return redirect(url_for('domain_ip.domain_search'))

        # Verify case exists and user has access
        case = Case.query.get(case_id)
        if not case:
            flash('Invalid case selected.', 'danger')
            return redirect(url_for('domain_ip.domain_search'))

        if not current_user.can_access_case(case):
            flash('You do not have permission to access this case.', 'danger')
            return redirect(url_for('domain_ip.domain_search'))

        try:
            from app.modules.domain_ip_osint import DomainIPOSINT

            start_time = time.time()
            osint = DomainIPOSINT()
            results = osint.investigate_domain(domain)
            execution_time = time.time() - start_time

            # Create investigation record
            investigation = Investigation(
                case_id=case_id,
                investigator_id=current_user.id,
                investigation_type='domain',
                target_identifier=domain,
                tool_used='Domain OSINT Module',
                raw_results=results,
                processed_results={
                    'whois': results.get('whois', {}),
                    'dns_records': results.get('dns_records', {}),
                    'subdomains': results.get('subdomains', []),
                    'ssl_info': results.get('ssl_info', {}),
                    'technologies': results.get('technologies', [])
                },
                status='completed',
                execution_time=execution_time,
                api_calls_made=results.get('metadata', {}).get('api_calls_made', 0),
                confidence_score=85
            )

            investigation.generate_evidence_hash()
            db.session.add(investigation)
            db.session.commit()

            # Mark completed
            investigation.mark_completed(investigation.processed_results, execution_time)

            # Log the investigation
            AuditLog.log_investigation(
                user=current_user,
                investigation_type='domain',
                target=domain,
                case_id=case_id,
                case_number=case.case_number,
                success=True,
                details={
                    'investigation_id': str(investigation.id),
                    'execution_time': execution_time,
                    'api_calls_made': results.get('metadata', {}).get('api_calls_made', 0)
                },
                ip_address=request.remote_addr
            )

            flash(f'Domain investigation completed successfully! Investigation ID: {investigation.id}', 'success')
            return redirect(url_for('domain_ip.view_domain_result', investigation_id=investigation.id))

        except Exception as e:
            db.session.rollback()
            flash(f'Investigation failed: {str(e)}', 'danger')

            AuditLog.log_action(
                user_id=current_user.id,
                username=current_user.username,
                badge_number=current_user.badge_number,
                action='domain_osint_failed',
                action_category='investigation',
                resource_type='investigation',
                details={'domain': domain, 'error': str(e)},
                status='failure',
                error_message=str(e),
                ip_address=request.remote_addr
            )

            return redirect(url_for('domain_ip.domain_search'))

    # GET request
    cases = _get_user_cases()
    recent_investigations = Investigation.query.filter_by(
        investigator_id=current_user.id,
        investigation_type='domain'
    ).order_by(Investigation.created_at.desc()).limit(5).all()

    return render_template('domain_ip/domain_search.html',
                         cases=cases,
                         recent_investigations=recent_investigations)


@domain_ip_bp.route('/domain/<investigation_id>')
@login_required
def view_domain_result(investigation_id):
    """View domain OSINT investigation results"""
    investigation = Investigation.query.get_or_404(investigation_id)

    case = Case.query.get(investigation.case_id)
    if not current_user.can_access_case(case):
        flash('You do not have permission to view this investigation.', 'danger')
        return redirect(url_for('investigations.index'))

    AuditLog.log_case_access(
        user=current_user,
        case=case,
        action='view_investigation',
        ip_address=request.remote_addr
    )

    return render_template('domain_ip/domain_result.html',
                         investigation=investigation,
                         case=case)


@domain_ip_bp.route('/domain/<investigation_id>/pdf')
@login_required
def domain_pdf(investigation_id):
    """Download PDF report for domain investigation"""
    investigation = Investigation.query.get_or_404(investigation_id)

    case = Case.query.get(investigation.case_id)
    if not current_user.can_access_case(case):
        flash('You do not have permission to access this investigation.', 'danger')
        return redirect(url_for('investigations.index'))

    flash('PDF generation coming soon.', 'info')
    return redirect(url_for('domain_ip.view_domain_result', investigation_id=investigation_id))


@domain_ip_bp.route('/ip', methods=['GET', 'POST'])
@login_required
def ip_search():
    """IP address OSINT search"""
    if request.method == 'POST':
        ip_address = request.form.get('ip_address', '').strip()
        case_id = request.form.get('case_id')

        if not ip_address:
            flash('IP address is required.', 'danger')
            return redirect(url_for('domain_ip.ip_search'))

        if not case_id:
            flash('Please select a case to link this investigation.', 'danger')
            return redirect(url_for('domain_ip.ip_search'))

        case = Case.query.get(case_id)
        if not case:
            flash('Invalid case selected.', 'danger')
            return redirect(url_for('domain_ip.ip_search'))

        if not current_user.can_access_case(case):
            flash('You do not have permission to access this case.', 'danger')
            return redirect(url_for('domain_ip.ip_search'))

        try:
            from app.modules.domain_ip_osint import DomainIPOSINT

            start_time = time.time()
            osint = DomainIPOSINT()
            results = osint.investigate_ip(ip_address)
            execution_time = time.time() - start_time

            investigation = Investigation(
                case_id=case_id,
                investigator_id=current_user.id,
                investigation_type='ip',
                target_identifier=ip_address,
                tool_used='IP OSINT Module',
                raw_results=results,
                processed_results={
                    'geolocation': results.get('geolocation', {}),
                    'whois': results.get('whois', {}),
                    'reverse_dns': results.get('reverse_dns', {}),
                    'ports': results.get('ports', []),
                    'reputation': results.get('reputation', {})
                },
                status='completed',
                execution_time=execution_time,
                api_calls_made=results.get('metadata', {}).get('api_calls_made', 0),
                confidence_score=85
            )

            investigation.generate_evidence_hash()
            db.session.add(investigation)
            db.session.commit()

            investigation.mark_completed(investigation.processed_results, execution_time)

            AuditLog.log_investigation(
                user=current_user,
                investigation_type='ip',
                target=ip_address,
                case_id=case_id,
                case_number=case.case_number,
                success=True,
                details={
                    'investigation_id': str(investigation.id),
                    'execution_time': execution_time
                },
                ip_address=request.remote_addr
            )

            flash(f'IP investigation completed successfully! Investigation ID: {investigation.id}', 'success')
            return redirect(url_for('domain_ip.view_ip_result', investigation_id=investigation.id))

        except Exception as e:
            db.session.rollback()
            flash(f'Investigation failed: {str(e)}', 'danger')

            AuditLog.log_action(
                user_id=current_user.id,
                username=current_user.username,
                badge_number=current_user.badge_number,
                action='ip_osint_failed',
                action_category='investigation',
                resource_type='investigation',
                details={'ip_address': ip_address, 'error': str(e)},
                status='failure',
                error_message=str(e),
                ip_address=request.remote_addr
            )

            return redirect(url_for('domain_ip.ip_search'))

    # GET request
    cases = _get_user_cases()
    recent_investigations = Investigation.query.filter_by(
        investigator_id=current_user.id,
        investigation_type='ip'
    ).order_by(Investigation.created_at.desc()).limit(5).all()

    return render_template('domain_ip/ip_search.html',
                         cases=cases,
                         recent_investigations=recent_investigations)


@domain_ip_bp.route('/ip/<investigation_id>')
@login_required
def view_ip_result(investigation_id):
    """View IP OSINT investigation results"""
    investigation = Investigation.query.get_or_404(investigation_id)

    case = Case.query.get(investigation.case_id)
    if not current_user.can_access_case(case):
        flash('You do not have permission to view this investigation.', 'danger')
        return redirect(url_for('investigations.index'))

    AuditLog.log_case_access(
        user=current_user,
        case=case,
        action='view_investigation',
        ip_address=request.remote_addr
    )

    return render_template('domain_ip/ip_result.html',
                         investigation=investigation,
                         case=case)
