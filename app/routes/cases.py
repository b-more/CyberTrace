"""
Case Management Routes
CyberTrace OSINT Platform - Zambia Police Service

Case CRUD operations and management
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file
from flask_login import current_user
from app import db
from app.models.case import Case
from app.models.audit_log import AuditLog
from app.utils.decorators import login_required, permission_required
from datetime import datetime
import os
import tempfile
import time

cases_bp = Blueprint('cases', __name__)


@cases_bp.route('/')
@login_required
def list_cases():
    """List all cases"""
    # Filter based on user role
    if current_user.role in ['admin', 'senior_investigator']:
        cases = Case.query.order_by(Case.created_at.desc()).all()
    else:
        # Show only assigned cases
        cases = Case.query.filter(
            (Case.lead_investigator_id == current_user.id) |
            (Case.assigned_officers.contains([current_user.id]))
        ).order_by(Case.created_at.desc()).all()

    return render_template('cases/list.html', cases=cases)


@cases_bp.route('/<case_id>')
@login_required
def view_case(case_id):
    """View case details"""
    from app.models.investigation import Investigation

    case = Case.query.get_or_404(case_id)

    # Check access
    if not current_user.can_access_case(case):
        flash('You do not have access to this case.', 'danger')
        return redirect(url_for('cases.list_cases'))

    # Get investigations sorted by created_at descending
    investigations = Investigation.query.filter_by(
        case_id=case_id
    ).order_by(Investigation.created_at.desc()).all()

    # Log case access
    AuditLog.log_case_access(current_user, case, 'view', request.remote_addr)

    return render_template('cases/detail.html', case=case, investigations=investigations)


@cases_bp.route('/create', methods=['GET', 'POST'])
@login_required
@permission_required('create_case')
def create_case():
    """Create new case"""
    if request.method == 'POST':
        # Get form data
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        case_type = request.form.get('case_type', 'cybercrime')
        priority = request.form.get('priority', 'medium')

        # Validate
        if not title or not description:
            flash('Title and description are required.', 'danger')
            return render_template('cases/create.html')

        # Generate case number
        case_number = Case.generate_case_number()

        # Create case
        new_case = Case(
            case_number=case_number,
            title=title,
            description=description,
            case_type=case_type,
            priority=priority,
            lead_investigator_id=current_user.id,
            status='open'
        )

        db.session.add(new_case)
        db.session.commit()

        # Log action
        AuditLog.log_case_access(current_user, new_case, 'create', request.remote_addr)

        flash(f'Case {case_number} created successfully!', 'success')
        return redirect(url_for('cases.view_case', case_id=new_case.id))

    return render_template('cases/create.html')


@cases_bp.route('/case-management-guide/download')
@login_required
def download_case_management_guide():
    """Download Case Management User Guide PDF"""
    from app.utils.case_guide_pdf_generator import CaseManagementGuidePDF

    try:
        # Create temporary file for PDF
        temp_dir = tempfile.gettempdir()
        pdf_filename = f'case_management_guide_{current_user.id}_{int(time.time())}.pdf'
        pdf_path = os.path.join(temp_dir, pdf_filename)

        # Generate PDF guide
        pdf_generator = CaseManagementGuidePDF()
        pdf_generator.generate(pdf_path)

        # Log PDF download with user information
        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='download_case_management_guide',
            action_category='export',
            resource_type='user_guide',
            resource_id='case_management_guide',
            resource_identifier='Case Management User Guide',
            details={
                'guide_type': 'case_management',
                'guide_version': '1.0',
                'user_role': current_user.role,
                'user_department': current_user.department
            },
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            request_method=request.method,
            request_path=request.path
        )

        # Send file
        return send_file(
            pdf_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'Case_Management_User_Guide_ZPS_CyberTrace.pdf'
        )

    except Exception as e:
        flash(f'Failed to generate guide PDF: {str(e)}', 'danger')
        return redirect(url_for('cases.list_cases'))
