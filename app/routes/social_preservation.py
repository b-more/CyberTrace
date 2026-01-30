"""
Social Media Preservation Routes
Zambia Police Service CyberTrace OSINT Platform

Social media content capture, preservation, and legal flagging operations
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_login import current_user
from app import db
from app.models.case import Case
from app.models.investigation import Investigation
from app.models.audit_log import AuditLog
from app.models.social_preservation import PreservedContent, ContentFlag
from app.utils.decorators import login_required, permission_required
from datetime import datetime
import os, tempfile, time

social_pres_bp = Blueprint('social_preservation', __name__)


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


@social_pres_bp.route('/', methods=['GET', 'POST'])
@login_required
def capture():
    """Capture and preserve social media content"""
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        case_id = request.form.get('case_id')
        capture_type = request.form.get('capture_type', 'post')

        if not url:
            flash('URL is required.', 'danger')
            return redirect(url_for('social_preservation.capture'))

        if not case_id:
            flash('Please select a case to link this capture.', 'danger')
            return redirect(url_for('social_preservation.capture'))

        case = Case.query.get(case_id)
        if not case:
            flash('Invalid case selected.', 'danger')
            return redirect(url_for('social_preservation.capture'))

        if not current_user.can_access_case(case):
            flash('You do not have permission to access this case.', 'danger')
            return redirect(url_for('social_preservation.capture'))

        try:
            from app.modules.social_preservation import SocialPreservation

            start_time = time.time()
            preserver = SocialPreservation()
            results = preserver.capture_url(url)
            execution_time = time.time() - start_time

            # Create PreservedContent record
            preserved = PreservedContent(
                case_id=case_id,
                url=url,
                platform=results.get('platform', 'unknown'),
                capture_type=capture_type,
                screenshot_path=results.get('screenshot_path'),
                screenshot_hash=results.get('screenshot_hash'),
                html_content=results.get('html_content'),
                html_hash=results.get('html_hash'),
                extracted_text=results.get('extracted_text'),
                author_info=results.get('author_info'),
                engagement_data=results.get('engagement_data'),
                content_flags=results.get('content_flags'),
                wayback_url=results.get('wayback_url'),
                is_available=results.get('is_available', True),
                captured_by=current_user.id
            )
            db.session.add(preserved)
            db.session.flush()

            # Create Investigation record
            investigation = Investigation(
                case_id=case_id,
                investigator_id=current_user.id,
                investigation_type='social_preservation',
                target_identifier=url,
                tool_used='Social Preservation Module',
                raw_results=results,
                processed_results={
                    'platform': results.get('platform', 'unknown'),
                    'capture_type': capture_type,
                    'has_screenshot': bool(results.get('screenshot_path')),
                    'has_html': bool(results.get('html_content')),
                    'has_wayback': bool(results.get('wayback_url')),
                    'author_info': results.get('author_info'),
                    'preserved_content_id': str(preserved.id)
                },
                status='completed',
                execution_time=execution_time,
                confidence_score=90
            )

            investigation.generate_evidence_hash()
            db.session.add(investigation)
            db.session.commit()

            investigation.mark_completed(investigation.processed_results, execution_time)

            AuditLog.log_investigation(
                user=current_user,
                investigation_type='social_preservation',
                target=url,
                case_id=case_id,
                case_number=case.case_number,
                success=True,
                details={
                    'investigation_id': str(investigation.id),
                    'preserved_content_id': str(preserved.id),
                    'platform': results.get('platform', 'unknown'),
                    'execution_time': execution_time
                },
                ip_address=request.remote_addr
            )

            flash(f'Social media content preserved successfully!', 'success')
            return redirect(url_for('social_preservation.view_result', capture_id=preserved.id))

        except Exception as e:
            db.session.rollback()
            flash(f'Capture failed: {str(e)}', 'danger')

            AuditLog.log_action(
                user_id=current_user.id,
                username=current_user.username,
                badge_number=current_user.badge_number,
                action='social_preservation_failed',
                action_category='investigation',
                resource_type='investigation',
                details={'url': url, 'error': str(e)},
                status='failure',
                error_message=str(e),
                ip_address=request.remote_addr
            )

            return redirect(url_for('social_preservation.capture'))

    # GET request
    cases = _get_user_cases()

    return render_template('social_preservation/capture.html',
                         cases=cases)


@social_pres_bp.route('/<capture_id>')
@login_required
def view_result(capture_id):
    """View preserved social media content"""
    preserved = PreservedContent.query.get_or_404(capture_id)

    case = Case.query.get(preserved.case_id)
    if not current_user.can_access_case(case):
        flash('You do not have permission to view this content.', 'danger')
        return redirect(url_for('investigations.index'))

    flags = ContentFlag.query.filter_by(capture_id=capture_id).all()

    AuditLog.log_case_access(
        user=current_user,
        case=case,
        action='view_preserved_content',
        ip_address=request.remote_addr
    )

    return render_template('social_preservation/result.html',
                         preserved=preserved,
                         case=case,
                         flags=flags)


@social_pres_bp.route('/list/<case_id>')
@login_required
def archive_list(case_id):
    """List all preserved content for a case"""
    case = Case.query.get_or_404(case_id)

    if not current_user.can_access_case(case):
        flash('You do not have permission to access this case.', 'danger')
        return redirect(url_for('social_preservation.capture'))

    preserved_content = PreservedContent.query.filter_by(
        case_id=case_id
    ).order_by(PreservedContent.captured_at.desc()).all()

    AuditLog.log_case_access(
        user=current_user,
        case=case,
        action='view_preserved_archive',
        ip_address=request.remote_addr
    )

    return render_template('social_preservation/archive_list.html',
                         case=case,
                         preserved_content=preserved_content)


@social_pres_bp.route('/<capture_id>/flag', methods=['POST'])
@login_required
def add_flag(capture_id):
    """Add a legal flag to preserved content"""
    preserved = PreservedContent.query.get_or_404(capture_id)

    case = Case.query.get(preserved.case_id)
    if not current_user.can_access_case(case):
        flash('You do not have permission to flag this content.', 'danger')
        return redirect(url_for('investigations.index'))

    flag_type = request.form.get('flag_type', '').strip()
    legal_reference = request.form.get('legal_reference', '').strip()
    severity = request.form.get('severity', 'medium').strip()
    flagged_content = request.form.get('flagged_content', '').strip()
    context = request.form.get('context', '').strip()

    if not flag_type or not legal_reference or not flagged_content:
        flash('Flag type, legal reference, and flagged content are required.', 'danger')
        return redirect(url_for('social_preservation.view_result', capture_id=capture_id))

    try:
        flag = ContentFlag(
            capture_id=capture_id,
            flag_type=flag_type,
            legal_reference=legal_reference,
            severity=severity,
            flagged_content=flagged_content,
            context=context,
            flagged_by=current_user.id
        )
        db.session.add(flag)
        db.session.commit()

        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='flag_preserved_content',
            action_category='investigation',
            resource_type='content_flag',
            resource_id=str(flag.id),
            resource_identifier=case.case_number,
            details={
                'capture_id': capture_id,
                'flag_type': flag_type,
                'severity': severity,
                'legal_reference': legal_reference
            },
            ip_address=request.remote_addr
        )

        flash('Content flag added successfully.', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Failed to add flag: {str(e)}', 'danger')

    return redirect(url_for('social_preservation.view_result', capture_id=capture_id))
