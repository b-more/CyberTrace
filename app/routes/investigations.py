"""
Investigation Routes
CyberTrace OSINT Platform - Zambia Police Service

OSINT investigation operations
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import current_user
from app import csrf
from app import db
from app.models.investigation import Investigation
from app.models.case import Case
from app.models.audit_log import AuditLog
from app.utils.decorators import login_required
from app.utils.pdf_generator import InvestigationPDFReport
from app.modules.email_osint import investigate_email
from app.modules.phone_osint import investigate_phone
import json
import time
import os
import tempfile

investigations_bp = Blueprint('investigations', __name__)


@investigations_bp.route('/')
@login_required
def index():
    """Investigation dashboard"""
    return render_template('investigations/index.html')


@investigations_bp.route('/user-guide')
@login_required
def user_guide():
    """User guide for CyberTrace"""
    return render_template('user_guide.html')


@investigations_bp.route('/phone-osint-guide')
@login_required
def phone_osint_guide():
    """Phone OSINT investigation guide"""
    return render_template('investigations/phone_osint_guide.html')


@investigations_bp.route('/email', methods=['GET', 'POST'])
@login_required
def email_search():
    """Email OSINT search"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        case_id = request.form.get('case_id')

        if not email:
            flash('Email address is required.', 'danger')
            return redirect(url_for('investigations.email_search'))

        if not case_id:
            flash('Please select a case to link this investigation.', 'danger')
            return redirect(url_for('investigations.email_search'))

        # Verify case exists and user has access
        case = Case.query.get(case_id)
        if not case:
            flash('Invalid case selected.', 'danger')
            return redirect(url_for('investigations.email_search'))

        # Check user has access to this case
        if not current_user.can_access_case(case):
            flash('You do not have permission to access this case.', 'danger')
            return redirect(url_for('investigations.email_search'))

        try:
            # Run email OSINT investigation
            start_time = time.time()
            results = investigate_email(email, case_id)
            execution_time = time.time() - start_time

            # Create investigation record
            investigation = Investigation(
                case_id=case_id,
                investigator_id=current_user.id,
                investigation_type='email',
                target_identifier=email,
                tool_used='Email OSINT Module',
                raw_results=results,
                processed_results={
                    'summary': results.get('validation', {}),
                    'breach_count': len([b for b in results.get('breaches', []) if 'error' not in b]),
                    'domain_info': results.get('domain_info', {}),
                    'risk_assessment': results.get('reputation', {})
                },
                status='completed' if results.get('is_valid') else 'failed',
                execution_time=execution_time,
                api_calls_made=results.get('metadata', {}).get('api_calls_made', 0),
                confidence_score=80 if results.get('is_valid') else 0
            )

            # Generate evidence hash
            investigation.generate_evidence_hash()

            # Save to database
            db.session.add(investigation)
            db.session.commit()

            # Log the investigation
            AuditLog.log_investigation(
                user=current_user,
                investigation_type='email',
                target=email,
                case_id=case_id,
                case_number=case.case_number,
                success=True,
                details={
                    'investigation_id': str(investigation.id),
                    'execution_time': execution_time,
                    'api_calls_made': results.get('metadata', {}).get('api_calls_made', 0),
                    'breach_count': len([b for b in results.get('breaches', []) if 'error' not in b]),
                    'risk_score': results.get('reputation', {}).get('risk_score', 0)
                },
                ip_address=request.remote_addr
            )

            flash(f'Email investigation completed successfully! Investigation ID: {investigation.id}', 'success')
            return redirect(url_for('investigations.view_email_result', investigation_id=investigation.id))

        except Exception as e:
            db.session.rollback()
            flash(f'Investigation failed: {str(e)}', 'danger')

            # Log failure
            AuditLog.log_action(
                user_id=current_user.id,
                username=current_user.username,
                badge_number=current_user.badge_number,
                action='email_osint_failed',
                action_category='investigation',
                resource_type='investigation',
                details={'email': email, 'error': str(e)},
                status='failure',
                error_message=str(e),
                ip_address=request.remote_addr
            )

            return redirect(url_for('investigations.email_search'))

    # GET request - show search form
    # Get user's cases for dropdown
    if current_user.role in ['admin', 'senior_investigator']:
        cases = Case.query.filter(Case.status.in_(['open', 'investigating'])).order_by(Case.created_at.desc()).all()
    else:
        cases = Case.query.filter(
            ((Case.lead_investigator_id == current_user.id) |
             (Case.assigned_officers.contains([current_user.id]))) &
            (Case.status.in_(['open', 'investigating']))
        ).order_by(Case.created_at.desc()).all()

    # Get recent email investigations by this user
    recent_investigations = Investigation.query.filter_by(
        investigator_id=current_user.id,
        investigation_type='email'
    ).order_by(Investigation.created_at.desc()).limit(5).all()

    return render_template('investigations/email_search.html',
                         cases=cases,
                         recent_investigations=recent_investigations)


@investigations_bp.route('/email-osint-guide/download')
@login_required
def download_email_osint_guide():
    """Download Email OSINT Investigation User Guide PDF"""
    from app.utils.guide_pdf_generator import EmailOSINTGuidePDF

    try:
        # Create temporary file for PDF
        temp_dir = tempfile.gettempdir()
        pdf_filename = f'email_osint_guide_{current_user.id}_{int(time.time())}.pdf'
        pdf_path = os.path.join(temp_dir, pdf_filename)

        # Generate PDF guide
        pdf_generator = EmailOSINTGuidePDF()
        pdf_generator.generate(pdf_path)

        # Log PDF download with user information
        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='download_email_osint_guide',
            action_category='export',
            resource_type='user_guide',
            resource_id='email_osint_guide',
            resource_identifier='Email OSINT Investigation User Guide',
            details={
                'guide_type': 'email_osint',
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
            download_name=f'Email_OSINT_User_Guide_ZPS_CyberTrace.pdf'
        )

    except Exception as e:
        flash(f'Failed to generate guide PDF: {str(e)}', 'danger')
        return redirect(url_for('investigations.email_search'))


@investigations_bp.route('/email/<investigation_id>')
@login_required
def view_email_result(investigation_id):
    """View email OSINT investigation results"""
    investigation = Investigation.query.get_or_404(investigation_id)

    # Check access permission
    case = Case.query.get(investigation.case_id)
    if not current_user.can_access_case(case):
        flash('You do not have permission to view this investigation.', 'danger')
        return redirect(url_for('investigations.index'))

    # Log access
    AuditLog.log_case_access(
        user=current_user,
        case=case,
        action='view_investigation',
        ip_address=request.remote_addr
    )

    return render_template('investigations/email_result.html',
                         investigation=investigation,
                         case=case)


@investigations_bp.route('/email/<investigation_id>/pdf')
@login_required
def download_email_pdf(investigation_id):
    """Download PDF report for email investigation"""
    investigation = Investigation.query.get_or_404(investigation_id)

    # Check access permission
    case = Case.query.get(investigation.case_id)
    if not current_user.can_access_case(case):
        flash('You do not have permission to access this investigation.', 'danger')
        return redirect(url_for('investigations.index'))

    try:
        # Create temporary file for PDF
        temp_dir = tempfile.gettempdir()
        pdf_filename = f'investigation_{investigation_id}.pdf'
        pdf_path = os.path.join(temp_dir, pdf_filename)

        # Generate PDF report
        pdf_generator = InvestigationPDFReport(
            investigation=investigation,
            case=case,
            investigator=investigation.investigator
        )
        pdf_generator.generate(pdf_path)

        # Log PDF download
        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='download_investigation_pdf',
            action_category='export',
            resource_type='investigation',
            resource_id=str(investigation.id),
            resource_identifier=investigation.target_identifier,
            details={'case_number': case.case_number},
            ip_address=request.remote_addr
        )

        # Send file
        return send_file(
            pdf_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'CyberTrace_Investigation_{case.case_number}_{investigation.target_identifier.replace("@", "_")}.pdf'
        )

    except Exception as e:
        flash(f'Failed to generate PDF report: {str(e)}', 'danger')
        return redirect(url_for('investigations.view_email_result', investigation_id=investigation_id))


@investigations_bp.route('/email-header-analyzer', methods=['GET', 'POST'])
@login_required
def email_header_analyzer():
    """Email header analysis tool"""
    from app.modules.email_header_analyzer import analyze_email_headers

    if request.method == 'POST':
        headers_text = request.form.get('headers', '').strip()
        case_id = request.form.get('case_id')

        if not headers_text:
            flash('Please paste email headers to analyze.', 'danger')
            return redirect(url_for('investigations.email_header_analyzer'))

        try:
            # Analyze headers
            analysis_results = analyze_email_headers(headers_text)

            # If case is selected, save as investigation
            if case_id:
                case = Case.query.get(case_id)
                if case and current_user.can_access_case(case):
                    investigation = Investigation(
                        case_id=case_id,
                        investigator_id=current_user.id,
                        investigation_type='email_header',
                        target_identifier=analysis_results.get('analysis', {}).get('from', 'Unknown'),
                        tool_used='Email Header Analyzer',
                        raw_results=analysis_results,
                        processed_results={
                            'authenticity_score': analysis_results.get('authenticity', {}).get('score', 0),
                            'assessment': analysis_results.get('authenticity', {}).get('assessment', 'Unknown'),
                            'warning_count': len(analysis_results.get('warnings', [])),
                            'spf': analysis_results.get('security', {}).get('spf', 'NONE'),
                            'dkim': analysis_results.get('security', {}).get('dkim', 'NONE'),
                            'dmarc': analysis_results.get('security', {}).get('dmarc', 'NONE')
                        },
                        status='completed',
                        execution_time=0.1,
                        confidence_score=100 - analysis_results.get('authenticity', {}).get('score', 0)
                    )

                    investigation.generate_evidence_hash()
                    db.session.add(investigation)
                    db.session.commit()

                    flash('Email header analysis completed and saved to case!', 'success')
                    return redirect(url_for('investigations.view_header_result', investigation_id=investigation.id))

            # Display results without saving
            return render_template('investigations/header_result.html',
                                 analysis=analysis_results,
                                 case=None,
                                 saved=False)

        except Exception as e:
            flash(f'Header analysis failed: {str(e)}', 'danger')
            return redirect(url_for('investigations.email_header_analyzer'))

    # GET request
    if current_user.role in ['admin', 'senior_investigator']:
        cases = Case.query.filter(Case.status.in_(['open', 'investigating'])).order_by(Case.created_at.desc()).all()
    else:
        cases = Case.query.filter(
            ((Case.lead_investigator_id == current_user.id) |
             (Case.assigned_officers.contains([current_user.id]))) &
            (Case.status.in_(['open', 'investigating']))
        ).order_by(Case.created_at.desc()).all()

    return render_template('investigations/email_header_analyzer.html', cases=cases)


@investigations_bp.route('/email-header/<investigation_id>')
@login_required
def view_header_result(investigation_id):
    """View email header analysis results"""
    investigation = Investigation.query.get_or_404(investigation_id)

    # Check access permission
    case = Case.query.get(investigation.case_id)
    if not current_user.can_access_case(case):
        flash('You do not have permission to view this investigation.', 'danger')
        return redirect(url_for('investigations.index'))

    return render_template('investigations/header_result.html',
                         analysis=investigation.raw_results,
                         investigation=investigation,
                         case=case,
                         saved=True)


@investigations_bp.route('/email/bulk', methods=['GET', 'POST'])
@login_required
def bulk_email_investigation():
    """Bulk email OSINT investigation"""
    if request.method == 'POST':
        emails_text = request.form.get('emails', '').strip()
        case_id = request.form.get('case_id')

        if not emails_text or not case_id:
            flash('Please provide both emails and select a case.', 'danger')
            return redirect(url_for('investigations.bulk_email_investigation'))

        # Verify case access
        case = Case.query.get(case_id)
        if not case or not current_user.can_access_case(case):
            flash('Invalid case or no access permission.', 'danger')
            return redirect(url_for('investigations.bulk_email_investigation'))

        # Parse emails (one per line or comma-separated)
        email_list = []
        for line in emails_text.split('\n'):
            for email in line.split(','):
                email = email.strip()
                if email and '@' in email:
                    email_list.append(email)

        if not email_list:
            flash('No valid email addresses found.', 'danger')
            return redirect(url_for('investigations.bulk_email_investigation'))

        if len(email_list) > 50:
            flash('Maximum 50 emails per bulk investigation.', 'warning')
            email_list = email_list[:50]

        # Run investigations
        investigation_objects = []
        successful = 0
        failed = 0

        for email in email_list:
            try:
                # Run investigation
                results = investigate_email(email, case_id)
                execution_time = results.get('metadata', {}).get('investigation_duration', 0)

                # Create investigation record
                investigation = Investigation(
                    case_id=case_id,
                    investigator_id=current_user.id,
                    investigation_type='email',
                    target_identifier=email,
                    tool_used='Email OSINT Module (Bulk)',
                    raw_results=results,
                    processed_results={
                        'summary': results.get('validation', {}),
                        'breach_count': len([b for b in results.get('breaches', []) if 'error' not in b]),
                        'risk_score': results.get('reputation', {}).get('risk_score', 0)
                    },
                    status='completed' if results.get('is_valid') else 'failed',
                    execution_time=execution_time,
                    api_calls_made=results.get('metadata', {}).get('api_calls_made', 0),
                    confidence_score=80 if results.get('is_valid') else 0
                )

                investigation.generate_evidence_hash()
                db.session.add(investigation)
                investigation_objects.append(investigation)
                successful += 1

            except Exception as e:
                failed += 1
                continue

        # Commit all investigations to get IDs
        db.session.commit()

        # Now collect the IDs after commit
        investigation_ids = [str(inv.id) for inv in investigation_objects]

        # Log bulk investigation
        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='bulk_email_investigation',
            action_category='investigation',
            resource_type='case',
            resource_id=str(case_id),
            resource_identifier=case.case_number,
            details={
                'total_emails': len(email_list),
                'successful': successful,
                'failed': failed,
                'investigation_ids': investigation_ids
            },
            ip_address=request.remote_addr
        )

        flash(f'Bulk investigation completed! {successful} successful, {failed} failed.', 'success')
        return redirect(url_for('investigations.bulk_results', case_id=case_id, ids=','.join(investigation_ids)))

    # GET request
    if current_user.role in ['admin', 'senior_investigator']:
        cases = Case.query.filter(Case.status.in_(['open', 'investigating'])).order_by(Case.created_at.desc()).all()
    else:
        cases = Case.query.filter(
            ((Case.lead_investigator_id == current_user.id) |
             (Case.assigned_officers.contains([current_user.id]))) &
            (Case.status.in_(['open', 'investigating']))
        ).order_by(Case.created_at.desc()).all()

    return render_template('investigations/bulk_email.html', cases=cases)


@investigations_bp.route('/bulk-results/<case_id>')
@login_required
def bulk_results(case_id):
    """View bulk investigation results"""
    case = Case.query.get_or_404(case_id)

    if not current_user.can_access_case(case):
        flash('You do not have permission to view this case.', 'danger')
        return redirect(url_for('investigations.index'))

    # Get investigation IDs from query parameter
    ids_param = request.args.get('ids', '')
    investigation_ids = ids_param.split(',') if ids_param else []

    # Fetch investigations
    investigations = []
    if investigation_ids:
        investigations = Investigation.query.filter(
            Investigation.id.in_(investigation_ids)
        ).all()
    else:
        # Show all recent investigations for this case
        investigations = Investigation.query.filter_by(
            case_id=case_id
        ).order_by(Investigation.created_at.desc()).limit(50).all()

    return render_template('investigations/bulk_results.html',
                         case=case,
                         investigations=investigations)


@investigations_bp.route('/investigations-guide/download')
@login_required
def download_investigations_guide():
    """Download OSINT Investigations User Guide PDF"""
    from app.utils.investigations_guide_pdf_generator import InvestigationsGuidePDF

    try:
        # Create temporary file for PDF
        temp_dir = tempfile.gettempdir()
        pdf_filename = f'investigations_guide_{current_user.id}_{int(time.time())}.pdf'
        pdf_path = os.path.join(temp_dir, pdf_filename)

        # Generate PDF guide
        pdf_generator = InvestigationsGuidePDF()
        pdf_generator.generate(pdf_path)

        # Log PDF download
        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='download_investigations_guide',
            action_category='export',
            resource_type='user_guide',
            resource_id='investigations_guide',
            resource_identifier='OSINT Investigations User Guide',
            details={
                'guide_type': 'osint_investigations',
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
            download_name=f'OSINT_Investigations_User_Guide_ZPS_CyberTrace.pdf'
        )

    except Exception as e:
        flash(f'Failed to generate guide PDF: {str(e)}', 'danger')
        return redirect(url_for('investigations.index'))


# ==================== PHONE OSINT ROUTES ====================

@investigations_bp.route('/phone', methods=['GET', 'POST'])
@login_required
def phone_search():
    """Phone OSINT search"""
    if request.method == 'POST':
        phone_number = request.form.get('phone_number', '').strip()
        case_id = request.form.get('case_id')

        if not phone_number:
            flash('Phone number is required.', 'danger')
            return redirect(url_for('investigations.phone_search'))

        if not case_id:
            flash('Please select a case to link this investigation.', 'danger')
            return redirect(url_for('investigations.phone_search'))

        # Verify case exists and user has access
        case = Case.query.get(case_id)
        if not case:
            flash('Invalid case selected.', 'danger')
            return redirect(url_for('investigations.phone_search'))

        # Check user has access to this case
        if not current_user.can_access_case(case):
            flash('You do not have permission to access this case.', 'danger')
            return redirect(url_for('investigations.phone_search'))

        try:
            # Run phone OSINT investigation
            start_time = time.time()
            results = investigate_phone(phone_number, case_id)
            execution_time = time.time() - start_time

            # Extract key metrics
            validation = results.get('validation', {})
            risk = results.get('risk_assessment', {})

            # Create investigation record
            investigation = Investigation(
                case_id=case_id,
                investigator_id=current_user.id,
                investigation_type='phone',
                target_identifier=validation.get('international_format', phone_number),
                tool_used='Phone OSINT Module',
                raw_results=results,
                processed_results={
                    'validation': validation,
                    'risk_assessment': risk,
                    'carrier': results.get('carrier', {}),
                    'location': results.get('location', {})
                },
                status='completed' if validation.get('is_valid') else 'failed',
                execution_time=execution_time,
                api_calls_made=results.get('metadata', {}).get('api_calls_made', 0),
                confidence_score=90 if validation.get('is_valid') else 30
            )

            # Generate evidence hash
            investigation.generate_evidence_hash()

            # Save to database
            db.session.add(investigation)
            db.session.commit()

            # Log the investigation
            AuditLog.log_investigation(
                user=current_user,
                investigation_type='phone',
                target=phone_number,
                case_id=case_id,
                case_number=case.case_number,
                success=True,
                details={
                    'investigation_id': str(investigation.id),
                    'execution_time': execution_time,
                    'is_valid': validation.get('is_valid', False),
                    'number_type': validation.get('number_type', 'Unknown'),
                    'risk_score': risk.get('risk_score', 0),
                    'country': results.get('location', {}).get('country', 'Unknown')
                },
                ip_address=request.remote_addr
            )

            flash(f'Phone investigation completed successfully! Investigation ID: {investigation.id}', 'success')
            return redirect(url_for('investigations.view_phone_result', investigation_id=investigation.id))

        except Exception as e:
            db.session.rollback()
            flash(f'Investigation failed: {str(e)}', 'danger')

            # Log failure
            AuditLog.log_action(
                user_id=current_user.id,
                username=current_user.username,
                badge_number=current_user.badge_number,
                action='phone_osint_failed',
                action_category='investigation',
                resource_type='investigation',
                details={'phone_number': phone_number, 'error': str(e)},
                status='failure',
                error_message=str(e),
                ip_address=request.remote_addr
            )

            return redirect(url_for('investigations.phone_search'))

    # GET request - show search form
    # Get user's cases for dropdown
    if current_user.role in ['admin', 'senior_investigator']:
        cases = Case.query.filter(Case.status.in_(['open', 'investigating'])).order_by(Case.created_at.desc()).all()
    else:
        cases = Case.query.filter(
            ((Case.lead_investigator_id == current_user.id) |
             (Case.assigned_officers.contains([current_user.id]))) &
            (Case.status.in_(['open', 'investigating']))
        ).order_by(Case.created_at.desc()).all()

    # Get recent phone investigations by this user
    recent_investigations = Investigation.query.filter_by(
        investigator_id=current_user.id,
        investigation_type='phone'
    ).order_by(Investigation.created_at.desc()).limit(5).all()

    return render_template('investigations/phone_search.html',
                         cases=cases,
                         recent_investigations=recent_investigations)


@investigations_bp.route('/phone/<investigation_id>')
@login_required
def view_phone_result(investigation_id):
    """View phone OSINT investigation results"""
    investigation = Investigation.query.get_or_404(investigation_id)

    # Check access permission
    case = Case.query.get(investigation.case_id)
    if not current_user.can_access_case(case):
        flash('You do not have permission to view this investigation.', 'danger')
        return redirect(url_for('investigations.index'))

    # Log access
    AuditLog.log_case_access(
        user=current_user,
        case=case,
        action='view_investigation',
        ip_address=request.remote_addr
    )

    return render_template('investigations/phone_result.html',
                         investigation=investigation,
                         case=case)


@investigations_bp.route('/phone/<investigation_id>/pdf')
@login_required
def download_phone_pdf(investigation_id):
    """Download PDF report for phone investigation"""
    investigation = Investigation.query.get_or_404(investigation_id)

    # Check access permission
    case = Case.query.get(investigation.case_id)
    if not current_user.can_access_case(case):
        flash('You do not have permission to access this investigation.', 'danger')
        return redirect(url_for('investigations.index'))

    try:
        # Create temporary file for PDF
        temp_dir = tempfile.gettempdir()
        pdf_filename = f'phone_investigation_{investigation_id}.pdf'
        pdf_path = os.path.join(temp_dir, pdf_filename)

        # Generate PDF report using phone-specific generator
        from app.utils.phone_investigation_pdf_generator import PhoneInvestigationPDFReport

        pdf_generator = PhoneInvestigationPDFReport(
            investigation=investigation,
            case=case,
            investigator=investigation.investigator
        )
        pdf_generator.generate(pdf_path)

        # Log PDF download
        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='download_investigation_pdf',
            action_category='export',
            resource_type='investigation',
            resource_id=str(investigation.id),
            resource_identifier=investigation.target_identifier,
            details={'case_number': case.case_number, 'investigation_type': 'phone'},
            ip_address=request.remote_addr
        )

        # Send file
        return send_file(
            pdf_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'CyberTrace_Phone_Investigation_{case.case_number}_{investigation.target_identifier.replace("+", "")}.pdf'
        )

    except Exception as e:
        flash(f'Failed to generate PDF report: {str(e)}', 'danger')
        return redirect(url_for('investigations.view_phone_result', investigation_id=investigation_id))


@investigations_bp.route('/phone-osint-guide/download')
@login_required
def download_phone_osint_guide():
    """Download Phone OSINT Investigation User Guide PDF"""
    from app.utils.phone_guide_pdf_generator import PhoneOSINTGuidePDF

    try:
        # Create temporary file for PDF
        temp_dir = tempfile.gettempdir()
        pdf_filename = f'phone_osint_guide_{current_user.id}_{int(time.time())}.pdf'
        pdf_path = os.path.join(temp_dir, pdf_filename)

        # Generate PDF guide
        pdf_generator = PhoneOSINTGuidePDF()
        pdf_generator.generate(pdf_path)

        # Log PDF download with user information
        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='download_phone_osint_guide',
            action_category='export',
            resource_type='user_guide',
            resource_id='phone_osint_guide',
            resource_identifier='Phone OSINT Investigation User Guide',
            details={
                'guide_type': 'phone_osint',
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
            download_name=f'Phone_OSINT_User_Guide_ZPS_CyberTrace.pdf'
        )

    except Exception as e:
        flash(f'Failed to generate guide PDF: {str(e)}', 'danger')
        return redirect(url_for('investigations.phone_search'))


@investigations_bp.route('/social-media', methods=['GET', 'POST'])
@login_required
@csrf.exempt
def social_media_search():
    """Social Media OSINT Investigation"""
    from app.models.case import Case
    from app.modules.social_media_osint import perform_social_media_investigation, get_available_platforms

    # Get cases for dropdown (exclude archived and closed cases)
    cases = Case.query.filter(Case.status.in_(['open', 'investigating', 'pending'])).order_by(Case.created_at.desc()).all()

    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            case_id = request.form.get('case_id')
            notes = request.form.get('notes', '')

            # Get selected platforms
            platforms = request.form.getlist('platforms')

            if not username:
                flash('Username is required', 'danger')
                return redirect(url_for('investigations.social_media_search'))

            if not case_id:
                flash('Please select a case', 'danger')
                return redirect(url_for('investigations.social_media_search'))

            # Get case
            case = Case.query.get_or_404(case_id)

            # Check case access
            if not current_user.can_access_case(case):
                flash('You do not have permission to access this case', 'danger')
                return redirect(url_for('investigations.social_media_search'))

            # Perform investigation
            results = perform_social_media_investigation(
                username=username,
                platforms=platforms if platforms else None
            )

            if not results['success']:
                flash(f"Investigation failed: {results.get('error', 'Unknown error')}", 'danger')
                return redirect(url_for('investigations.social_media_search'))

            # Save investigation to database
            investigation = Investigation(
                case_id=case.id,
                investigator_id=current_user.id,
                investigation_type='social_media',
                target_identifier=results['username'],
                status='completed',
                raw_results=results,
                processed_results=results,
                notes=notes
            )

            db.session.add(investigation)
            db.session.commit()

            # Log investigation
            AuditLog.log_investigation(
                user=current_user,
                investigation_type='social_media',
                target=results['username'],
                case_id=case.id,
                case_number=case.case_number,
                success=True,
                details={
                    'platforms_searched': results['statistics']['platforms_searched'],
                    'total_searches': results['statistics']['total_searches']
                },
                ip_address=request.remote_addr
            )

            flash('Social media investigation completed successfully', 'success')
            return redirect(url_for('investigations.social_media_results', investigation_id=investigation.id))

        except Exception as e:
            db.session.rollback()
            flash(f'Investigation failed: {str(e)}', 'danger')
            return redirect(url_for('investigations.social_media_search'))

    # Get available platforms
    platforms = get_available_platforms()

    return render_template(
        'investigations/social_media_search.html',
        cases=cases,
        platforms=platforms
    )


@investigations_bp.route('/social-media/<investigation_id>')
@login_required
def social_media_results(investigation_id):
    """View social media investigation results"""
    from app.models.case import Case

    investigation = Investigation.query.get_or_404(investigation_id)
    case = Case.query.get_or_404(investigation.case_id)

    # Check access
    if not current_user.can_access_case(case):
        flash('You do not have permission to view this investigation', 'danger')
        return redirect(url_for('dashboard.index'))

    return render_template(
        'investigations/social_media_results.html',
        investigation=investigation,
        case=case,
        results=investigation.processed_results
    )
