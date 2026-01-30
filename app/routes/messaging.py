"""
Messaging Forensics Routes
Zambia Police Service CyberTrace OSINT Platform

Chat export parsing, message analysis, and conversation forensics
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, jsonify, current_app
from flask_login import current_user
from app import db
from app.models.case import Case
from app.models.investigation import Investigation
from app.models.audit_log import AuditLog
from app.models.messaging_forensics import MessagingExport
from app.utils.decorators import login_required, permission_required
from datetime import datetime
import os, tempfile, time
import hashlib

messaging_bp = Blueprint('messaging', __name__)


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


@messaging_bp.route('/', methods=['GET', 'POST'])
@login_required
def upload():
    """Upload and parse messaging platform exports"""
    if request.method == 'POST':
        case_id = request.form.get('case_id')
        platform = request.form.get('platform', 'whatsapp')

        if not case_id:
            flash('Please select a case to link this analysis.', 'danger')
            return redirect(url_for('messaging.upload'))

        case = Case.query.get(case_id)
        if not case:
            flash('Invalid case selected.', 'danger')
            return redirect(url_for('messaging.upload'))

        if not current_user.can_access_case(case):
            flash('You do not have permission to access this case.', 'danger')
            return redirect(url_for('messaging.upload'))

        file = request.files.get('file')
        if not file or not file.filename:
            flash('Please upload a chat export file.', 'danger')
            return redirect(url_for('messaging.upload'))

        try:
            from werkzeug.utils import secure_filename

            filename = secure_filename(file.filename)
            upload_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], str(case_id))
            os.makedirs(upload_dir, exist_ok=True)
            file_path = os.path.join(upload_dir, filename)
            file.save(file_path)

            # Compute file hash for integrity
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            from app.modules.messaging_forensics import MessagingForensics

            start_time = time.time()
            forensics = MessagingForensics()
            results = forensics.parse_whatsapp_export(file_path)
            execution_time = time.time() - start_time

            # Create MessagingExport record
            export = MessagingExport(
                case_id=case_id,
                platform=platform,
                filename=filename,
                file_hash=file_hash,
                chat_type=results.get('chat_type', 'individual'),
                participant_count=results.get('participant_count', 0),
                message_count=results.get('message_count', 0),
                date_range_start=datetime.fromisoformat(results['date_range_start']) if results.get('date_range_start') else None,
                date_range_end=datetime.fromisoformat(results['date_range_end']) if results.get('date_range_end') else None,
                extracted_links=results.get('extracted_links', []),
                extracted_phones=results.get('extracted_phones', []),
                extracted_data=results.get('extracted_data', {}),
                uploaded_by=current_user.id
            )
            db.session.add(export)
            db.session.flush()

            # Create Investigation record
            investigation = Investigation(
                case_id=case_id,
                investigator_id=current_user.id,
                investigation_type='messaging',
                target_identifier=f'{platform}:{filename}',
                tool_used='Messaging Forensics Module',
                raw_results=results,
                processed_results={
                    'platform': platform,
                    'filename': filename,
                    'file_hash': file_hash,
                    'message_count': results.get('message_count', 0),
                    'participant_count': results.get('participant_count', 0),
                    'chat_type': results.get('chat_type', 'individual'),
                    'extracted_links_count': len(results.get('extracted_links', [])),
                    'extracted_phones_count': len(results.get('extracted_phones', []))
                },
                status='completed',
                execution_time=execution_time,
                confidence_score=90
            )

            investigation.generate_evidence_hash()
            db.session.add(investigation)
            db.session.flush()

            # Link export to investigation
            export.investigation_id = investigation.id
            db.session.commit()

            investigation.mark_completed(investigation.processed_results, execution_time)

            AuditLog.log_investigation(
                user=current_user,
                investigation_type='messaging',
                target=f'{platform}:{filename}',
                case_id=case_id,
                case_number=case.case_number,
                success=True,
                details={
                    'investigation_id': str(investigation.id),
                    'platform': platform,
                    'message_count': results.get('message_count', 0),
                    'execution_time': execution_time
                },
                ip_address=request.remote_addr
            )

            flash(f'Chat export parsed successfully! {results.get("message_count", 0)} messages analyzed.', 'success')
            return redirect(url_for('messaging.view_result', investigation_id=investigation.id))

        except Exception as e:
            db.session.rollback()
            flash(f'Analysis failed: {str(e)}', 'danger')

            AuditLog.log_action(
                user_id=current_user.id,
                username=current_user.username,
                badge_number=current_user.badge_number,
                action='messaging_forensics_failed',
                action_category='investigation',
                resource_type='investigation',
                details={'platform': platform, 'error': str(e)},
                status='failure',
                error_message=str(e),
                ip_address=request.remote_addr
            )

            return redirect(url_for('messaging.upload'))

    # GET request
    cases = _get_user_cases()
    recent_investigations = Investigation.query.filter_by(
        investigator_id=current_user.id,
        investigation_type='messaging'
    ).order_by(Investigation.created_at.desc()).limit(5).all()

    return render_template('messaging/upload.html',
                         cases=cases,
                         recent_investigations=recent_investigations)


@messaging_bp.route('/<investigation_id>')
@login_required
def view_result(investigation_id):
    """View messaging forensics results"""
    investigation = Investigation.query.get_or_404(investigation_id)

    case = Case.query.get(investigation.case_id)
    if not current_user.can_access_case(case):
        flash('You do not have permission to view this investigation.', 'danger')
        return redirect(url_for('investigations.index'))

    # Get associated messaging export
    export = MessagingExport.query.filter_by(
        investigation_id=investigation_id
    ).first()

    AuditLog.log_case_access(
        user=current_user,
        case=case,
        action='view_investigation',
        ip_address=request.remote_addr
    )

    return render_template('messaging/result.html',
                         investigation=investigation,
                         case=case,
                         export=export)


@messaging_bp.route('/<investigation_id>/conversation')
@login_required
def view_conversation(investigation_id):
    """View parsed conversation from messaging export"""
    investigation = Investigation.query.get_or_404(investigation_id)

    case = Case.query.get(investigation.case_id)
    if not current_user.can_access_case(case):
        flash('You do not have permission to view this investigation.', 'danger')
        return redirect(url_for('investigations.index'))

    export = MessagingExport.query.filter_by(
        investigation_id=investigation_id
    ).first()

    return render_template('messaging/conversation.html',
                         investigation=investigation,
                         case=case,
                         export=export)
