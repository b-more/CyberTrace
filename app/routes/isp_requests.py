"""
ISP Request Management Routes
Zambia Police Service CyberTrace OSINT Platform

ISP data request creation, tracking, and fulfillment operations
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

isp_requests_bp = Blueprint('isp_requests', __name__)


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


@isp_requests_bp.route('/')
@login_required
def list_requests():
    """List ISP data requests filtered by user role"""
    try:
        from app.models.isp_request import ISPRequest

        if current_user.role in ['admin', 'senior_investigator']:
            requests_list = ISPRequest.query.order_by(
                ISPRequest.created_at.desc()
            ).all()
        else:
            requests_list = ISPRequest.query.filter_by(
                requested_by=current_user.id
            ).order_by(ISPRequest.created_at.desc()).all()
    except Exception:
        requests_list = []

    # Compute stats for the dashboard cards
    stats = {
        'total': len(requests_list),
        'pending': sum(1 for r in requests_list if getattr(r, 'status', '') == 'pending'),
        'overdue': sum(1 for r in requests_list if getattr(r, 'status', '') == 'overdue'),
        'fulfilled': sum(1 for r in requests_list if getattr(r, 'status', '') == 'fulfilled'),
    }

    return render_template('isp_requests/list.html',
                         requests=requests_list,
                         stats=stats)


@isp_requests_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_request():
    """Create a new ISP data request"""
    if request.method == 'POST':
        case_id = request.form.get('case_id')
        isp_name = request.form.get('isp_name', '').strip()
        request_type = request.form.get('request_type', '').strip()
        target_identifier = request.form.get('target_identifier', '').strip()
        date_range_start = request.form.get('date_range_start')
        date_range_end = request.form.get('date_range_end')
        justification = request.form.get('justification', '').strip()
        legal_authority = request.form.get('legal_authority', '').strip()

        if not case_id:
            flash('Please select a case.', 'danger')
            return redirect(url_for('isp_requests.create_request'))

        if not isp_name or not request_type or not target_identifier:
            flash('ISP name, request type, and target identifier are required.', 'danger')
            return redirect(url_for('isp_requests.create_request'))

        if not justification:
            flash('Justification is required for ISP data requests.', 'danger')
            return redirect(url_for('isp_requests.create_request'))

        case = Case.query.get(case_id)
        if not case:
            flash('Invalid case selected.', 'danger')
            return redirect(url_for('isp_requests.create_request'))

        if not current_user.can_access_case(case):
            flash('You do not have permission to access this case.', 'danger')
            return redirect(url_for('isp_requests.create_request'))

        try:
            from app.models.isp_request import ISPRequest

            isp_req = ISPRequest(
                case_id=case_id,
                requested_by=current_user.id,
                isp_name=isp_name,
                request_type=request_type,
                target_identifier=target_identifier,
                date_range_start=datetime.fromisoformat(date_range_start) if date_range_start else None,
                date_range_end=datetime.fromisoformat(date_range_end) if date_range_end else None,
                justification=justification,
                legal_authority=legal_authority,
                status='draft'
            )
            db.session.add(isp_req)
            db.session.commit()

            AuditLog.log_action(
                user_id=current_user.id,
                username=current_user.username,
                badge_number=current_user.badge_number,
                action='create_isp_request',
                action_category='investigation',
                resource_type='isp_request',
                resource_id=str(isp_req.id),
                resource_identifier=case.case_number,
                details={
                    'isp_name': isp_name,
                    'request_type': request_type,
                    'target_identifier': target_identifier
                },
                ip_address=request.remote_addr
            )

            flash(f'ISP request created successfully for case {case.case_number}.', 'success')
            return redirect(url_for('isp_requests.view_request', request_id=isp_req.id))

        except Exception as e:
            db.session.rollback()
            flash(f'Failed to create ISP request: {str(e)}', 'danger')
            return redirect(url_for('isp_requests.create_request'))

    # GET request
    cases = _get_user_cases()
    return render_template('isp_requests/create.html', cases=cases)


@isp_requests_bp.route('/<request_id>')
@login_required
def view_request(request_id):
    """View ISP request details"""
    try:
        from app.models.isp_request import ISPRequest

        isp_req = ISPRequest.query.get_or_404(request_id)

        case = Case.query.get(isp_req.case_id)
        if not current_user.can_access_case(case):
            flash('You do not have permission to view this request.', 'danger')
            return redirect(url_for('isp_requests.list_requests'))

        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='view_isp_request',
            action_category='investigation',
            resource_type='isp_request',
            resource_id=str(request_id),
            ip_address=request.remote_addr
        )

        return render_template('isp_requests/detail.html',
                             isp_request=isp_req,
                             case=case)

    except Exception as e:
        flash(f'Failed to load ISP request: {str(e)}', 'danger')
        return redirect(url_for('isp_requests.list_requests'))


@isp_requests_bp.route('/<request_id>/submit', methods=['POST'])
@login_required
def submit_request(request_id):
    """Submit an ISP request (change status to submitted)"""
    try:
        from app.models.isp_request import ISPRequest

        isp_req = ISPRequest.query.get_or_404(request_id)

        case = Case.query.get(isp_req.case_id)
        if not current_user.can_access_case(case):
            flash('You do not have permission to submit this request.', 'danger')
            return redirect(url_for('isp_requests.list_requests'))

        isp_req.status = 'submitted'
        isp_req.submitted_at = datetime.utcnow()
        isp_req.submitted_by = current_user.id
        db.session.commit()

        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='submit_isp_request',
            action_category='investigation',
            resource_type='isp_request',
            resource_id=str(request_id),
            resource_identifier=case.case_number,
            details={
                'isp_name': isp_req.isp_name,
                'status': 'submitted'
            },
            ip_address=request.remote_addr
        )

        flash('ISP request submitted successfully.', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Failed to submit ISP request: {str(e)}', 'danger')

    return redirect(url_for('isp_requests.view_request', request_id=request_id))


@isp_requests_bp.route('/<request_id>/fulfill', methods=['POST'])
@login_required
def fulfill_request(request_id):
    """Mark an ISP request as fulfilled"""
    try:
        from app.models.isp_request import ISPRequest

        isp_req = ISPRequest.query.get_or_404(request_id)

        case = Case.query.get(isp_req.case_id)
        if not current_user.can_access_case(case):
            flash('You do not have permission to fulfill this request.', 'danger')
            return redirect(url_for('isp_requests.list_requests'))

        isp_req.status = 'fulfilled'
        isp_req.fulfilled_at = datetime.utcnow()
        isp_req.fulfilled_by = current_user.id
        fulfillment_notes = request.form.get('notes', '')
        if fulfillment_notes:
            isp_req.fulfillment_notes = fulfillment_notes
        db.session.commit()

        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='fulfill_isp_request',
            action_category='investigation',
            resource_type='isp_request',
            resource_id=str(request_id),
            resource_identifier=case.case_number,
            details={
                'isp_name': isp_req.isp_name,
                'status': 'fulfilled'
            },
            ip_address=request.remote_addr
        )

        flash('ISP request marked as fulfilled.', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Failed to fulfill ISP request: {str(e)}', 'danger')

    return redirect(url_for('isp_requests.view_request', request_id=request_id))


@isp_requests_bp.route('/templates')
@login_required
def list_templates():
    """List ISP request templates"""
    try:
        from app.models.isp_request import ISPRequestTemplate
        templates = ISPRequestTemplate.query.order_by(
            ISPRequestTemplate.name.asc()
        ).all()
    except Exception:
        templates = []

    return render_template('isp_requests/templates.html',
                         templates=templates)
