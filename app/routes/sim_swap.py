"""
SIM Swap Detection Routes
Zambia Police Service CyberTrace OSINT Platform

SIM swap fraud detection, carrier data import, and timeline analysis
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, jsonify, current_app
from flask_login import current_user
from app import db
from app.models.case import Case
from app.models.investigation import Investigation
from app.models.audit_log import AuditLog
from app.models.sim_swap import SimSwapEvent
from app.utils.decorators import login_required, permission_required
from datetime import datetime
import os, tempfile, time

sim_swap_bp = Blueprint('sim_swap', __name__)


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


@sim_swap_bp.route('/', methods=['GET', 'POST'])
@login_required
def search():
    """SIM swap detection search"""
    if request.method == 'POST':
        phone_number = request.form.get('phone_number', '').strip()
        case_id = request.form.get('case_id')

        if not phone_number:
            flash('Phone number is required.', 'danger')
            return redirect(url_for('sim_swap.search'))

        if not case_id:
            flash('Please select a case to link this investigation.', 'danger')
            return redirect(url_for('sim_swap.search'))

        case = Case.query.get(case_id)
        if not case:
            flash('Invalid case selected.', 'danger')
            return redirect(url_for('sim_swap.search'))

        if not current_user.can_access_case(case):
            flash('You do not have permission to access this case.', 'danger')
            return redirect(url_for('sim_swap.search'))

        try:
            from app.modules.sim_swap_detector import SimSwapDetector

            start_time = time.time()
            detector = SimSwapDetector()
            results = detector.investigate(phone_number)
            execution_time = time.time() - start_time

            investigation = Investigation(
                case_id=case_id,
                investigator_id=current_user.id,
                investigation_type='sim_swap',
                target_identifier=phone_number,
                tool_used='SIM Swap Detector Module',
                raw_results=results,
                processed_results={
                    'phone_number': phone_number,
                    'swap_detected': results.get('swap_detected', False),
                    'swap_count': results.get('swap_count', 0),
                    'carrier_info': results.get('carrier_info', {}),
                    'risk_score': results.get('risk_score', 0),
                    'timeline': results.get('timeline', []),
                    'associated_compromises': results.get('associated_compromises', [])
                },
                status='completed',
                execution_time=execution_time,
                api_calls_made=results.get('metadata', {}).get('api_calls_made', 0),
                confidence_score=75
            )

            investigation.generate_evidence_hash()
            db.session.add(investigation)
            db.session.commit()

            investigation.mark_completed(investigation.processed_results, execution_time)

            AuditLog.log_investigation(
                user=current_user,
                investigation_type='sim_swap',
                target=phone_number,
                case_id=case_id,
                case_number=case.case_number,
                success=True,
                details={
                    'investigation_id': str(investigation.id),
                    'execution_time': execution_time,
                    'swap_detected': results.get('swap_detected', False),
                    'swap_count': results.get('swap_count', 0)
                },
                ip_address=request.remote_addr
            )

            flash(f'SIM swap investigation completed successfully! Investigation ID: {investigation.id}', 'success')
            return redirect(url_for('sim_swap.view_result', investigation_id=investigation.id))

        except Exception as e:
            db.session.rollback()
            flash(f'Investigation failed: {str(e)}', 'danger')

            AuditLog.log_action(
                user_id=current_user.id,
                username=current_user.username,
                badge_number=current_user.badge_number,
                action='sim_swap_detection_failed',
                action_category='investigation',
                resource_type='investigation',
                details={'phone_number': phone_number, 'error': str(e)},
                status='failure',
                error_message=str(e),
                ip_address=request.remote_addr
            )

            return redirect(url_for('sim_swap.search'))

    # GET request
    cases = _get_user_cases()
    recent_investigations = Investigation.query.filter_by(
        investigator_id=current_user.id,
        investigation_type='sim_swap'
    ).order_by(Investigation.created_at.desc()).limit(5).all()

    return render_template('sim_swap/search.html',
                         cases=cases,
                         recent_investigations=recent_investigations)


@sim_swap_bp.route('/import', methods=['POST'])
@login_required
def import_data():
    """Import carrier CSV data for SIM swap events"""
    case_id = request.form.get('case_id')

    if not case_id:
        flash('Please select a case to link the SIM swap data.', 'danger')
        return redirect(url_for('sim_swap.search'))

    case = Case.query.get(case_id)
    if not case:
        flash('Invalid case selected.', 'danger')
        return redirect(url_for('sim_swap.search'))

    if not current_user.can_access_case(case):
        flash('You do not have permission to access this case.', 'danger')
        return redirect(url_for('sim_swap.search'))

    file = request.files.get('file')
    if not file or not file.filename:
        flash('Please upload a carrier CSV file.', 'danger')
        return redirect(url_for('sim_swap.search'))

    try:
        from werkzeug.utils import secure_filename
        import csv
        import io

        filename = secure_filename(file.filename)
        upload_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], str(case_id))
        os.makedirs(upload_dir, exist_ok=True)
        file_path = os.path.join(upload_dir, filename)
        file.save(file_path)

        # Parse the CSV and create SimSwapEvent records
        imported_count = 0
        with open(file_path, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                event = SimSwapEvent(
                    case_id=case_id,
                    phone_number=row.get('phone_number', ''),
                    carrier=row.get('carrier', 'Unknown'),
                    old_iccid=row.get('old_iccid'),
                    new_iccid=row.get('new_iccid'),
                    old_imsi=row.get('old_imsi'),
                    new_imsi=row.get('new_imsi'),
                    swap_date=datetime.fromisoformat(row['swap_date']) if row.get('swap_date') else datetime.utcnow(),
                    swap_type=row.get('swap_type', 'suspicious'),
                    detection_method='carrier_data_import',
                    carrier_data=row,
                    notes=row.get('notes')
                )
                db.session.add(event)
                imported_count += 1

        db.session.commit()

        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='import_sim_swap_data',
            action_category='investigation',
            resource_type='sim_swap_event',
            resource_id=str(case_id),
            resource_identifier=case.case_number,
            details={
                'filename': filename,
                'imported_count': imported_count
            },
            ip_address=request.remote_addr
        )

        flash(f'Successfully imported {imported_count} SIM swap events for case {case.case_number}.', 'success')
        return redirect(url_for('sim_swap.view_timeline', case_id=case_id))

    except Exception as e:
        db.session.rollback()
        flash(f'Import failed: {str(e)}', 'danger')

        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='import_sim_swap_failed',
            action_category='investigation',
            resource_type='sim_swap_event',
            details={'error': str(e)},
            status='failure',
            error_message=str(e),
            ip_address=request.remote_addr
        )

        return redirect(url_for('sim_swap.search'))


@sim_swap_bp.route('/<investigation_id>')
@login_required
def view_result(investigation_id):
    """View SIM swap investigation results"""
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

    return render_template('sim_swap/result.html',
                         investigation=investigation,
                         case=case)


@sim_swap_bp.route('/timeline/<case_id>')
@login_required
def view_timeline(case_id):
    """View SIM swap event timeline for a case"""
    case = Case.query.get_or_404(case_id)

    if not current_user.can_access_case(case):
        flash('You do not have permission to access this case.', 'danger')
        return redirect(url_for('sim_swap.search'))

    events = SimSwapEvent.query.filter_by(
        case_id=case_id
    ).order_by(SimSwapEvent.swap_date.asc()).all()

    AuditLog.log_case_access(
        user=current_user,
        case=case,
        action='view_sim_swap_timeline',
        ip_address=request.remote_addr
    )

    return render_template('sim_swap/timeline.html',
                         case=case,
                         events=events)
