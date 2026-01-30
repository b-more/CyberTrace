"""
Cryptocurrency Investigation Routes
Zambia Police Service CyberTrace OSINT Platform

Cryptocurrency wallet tracing and transaction analysis operations
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

crypto_bp = Blueprint('crypto', __name__)


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


def _detect_chain(address):
    """Detect blockchain from wallet address format"""
    if address.startswith('0x') and len(address) == 42:
        return 'ethereum'
    elif address.startswith(('1', '3', 'bc1')):
        return 'bitcoin'
    elif address.startswith(('T',)) and len(address) == 34:
        return 'tron'
    elif address.startswith(('r',)):
        return 'ripple'
    else:
        return 'unknown'


@crypto_bp.route('/', methods=['GET', 'POST'])
@login_required
def search():
    """Cryptocurrency wallet OSINT search"""
    if request.method == 'POST':
        address = request.form.get('address', '').strip()
        case_id = request.form.get('case_id')

        if not address:
            flash('Cryptocurrency address is required.', 'danger')
            return redirect(url_for('crypto.search'))

        if not case_id:
            flash('Please select a case to link this investigation.', 'danger')
            return redirect(url_for('crypto.search'))

        case = Case.query.get(case_id)
        if not case:
            flash('Invalid case selected.', 'danger')
            return redirect(url_for('crypto.search'))

        if not current_user.can_access_case(case):
            flash('You do not have permission to access this case.', 'danger')
            return redirect(url_for('crypto.search'))

        try:
            from app.modules.crypto_tracer import CryptoTracer

            chain = _detect_chain(address)

            start_time = time.time()
            tracer = CryptoTracer()
            results = tracer.investigate_wallet(address, chain=chain)
            execution_time = time.time() - start_time

            investigation = Investigation(
                case_id=case_id,
                investigator_id=current_user.id,
                investigation_type='crypto',
                target_identifier=address,
                tool_used='Crypto Tracer Module',
                raw_results=results,
                processed_results={
                    'chain': chain,
                    'balance': results.get('balance', {}),
                    'transaction_count': results.get('transaction_count', 0),
                    'first_seen': results.get('first_seen'),
                    'last_seen': results.get('last_seen'),
                    'risk_score': results.get('risk_score', 0),
                    'associated_addresses': results.get('associated_addresses', []),
                    'tags': results.get('tags', [])
                },
                status='completed',
                execution_time=execution_time,
                api_calls_made=results.get('metadata', {}).get('api_calls_made', 0),
                confidence_score=80
            )

            investigation.generate_evidence_hash()
            db.session.add(investigation)
            db.session.commit()

            investigation.mark_completed(investigation.processed_results, execution_time)

            AuditLog.log_investigation(
                user=current_user,
                investigation_type='crypto',
                target=address,
                case_id=case_id,
                case_number=case.case_number,
                success=True,
                details={
                    'investigation_id': str(investigation.id),
                    'chain': chain,
                    'execution_time': execution_time,
                    'transaction_count': results.get('transaction_count', 0)
                },
                ip_address=request.remote_addr
            )

            flash(f'Cryptocurrency investigation completed successfully! Investigation ID: {investigation.id}', 'success')
            return redirect(url_for('crypto.view_result', investigation_id=investigation.id))

        except Exception as e:
            db.session.rollback()
            flash(f'Investigation failed: {str(e)}', 'danger')

            AuditLog.log_action(
                user_id=current_user.id,
                username=current_user.username,
                badge_number=current_user.badge_number,
                action='crypto_osint_failed',
                action_category='investigation',
                resource_type='investigation',
                details={'address': address, 'error': str(e)},
                status='failure',
                error_message=str(e),
                ip_address=request.remote_addr
            )

            return redirect(url_for('crypto.search'))

    # GET request
    cases = _get_user_cases()
    recent_investigations = Investigation.query.filter_by(
        investigator_id=current_user.id,
        investigation_type='crypto'
    ).order_by(Investigation.created_at.desc()).limit(5).all()

    return render_template('crypto/search.html',
                         cases=cases,
                         recent_investigations=recent_investigations)


@crypto_bp.route('/<investigation_id>')
@login_required
def view_result(investigation_id):
    """View cryptocurrency investigation results"""
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

    return render_template('crypto/result.html',
                         investigation=investigation,
                         case=case)


@crypto_bp.route('/<investigation_id>/graph')
@login_required
def tx_graph(investigation_id):
    """View cryptocurrency transaction graph"""
    investigation = Investigation.query.get_or_404(investigation_id)

    case = Case.query.get(investigation.case_id)
    if not current_user.can_access_case(case):
        flash('You do not have permission to view this investigation.', 'danger')
        return redirect(url_for('investigations.index'))

    return render_template('crypto/tx_graph.html',
                         investigation=investigation,
                         case=case)


@crypto_bp.route('/<investigation_id>/pdf')
@login_required
def pdf_report(investigation_id):
    """Download PDF report for cryptocurrency investigation"""
    investigation = Investigation.query.get_or_404(investigation_id)

    case = Case.query.get(investigation.case_id)
    if not current_user.can_access_case(case):
        flash('You do not have permission to access this investigation.', 'danger')
        return redirect(url_for('investigations.index'))

    flash('PDF generation coming soon.', 'info')
    return redirect(url_for('crypto.view_result', investigation_id=investigation_id))
