"""
Digital Forensics Routes
Zambia Police Service CyberTrace OSINT Platform

Image and document forensic analysis, EXIF extraction, and manipulation detection
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, jsonify, current_app
from flask_login import current_user
from app import db
from app.models.case import Case
from app.models.investigation import Investigation
from app.models.audit_log import AuditLog
from app.models.image_forensics import ForensicImage, ForensicDocument
from app.utils.decorators import login_required, permission_required
from datetime import datetime
import os, tempfile, time
import hashlib

forensics_bp = Blueprint('forensics', __name__)

# Image MIME types for file type detection
IMAGE_MIME_TYPES = {'image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/tiff', 'image/webp'}
DOCUMENT_MIME_TYPES = {
    'application/pdf', 'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation'
}


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


def _detect_file_type(filename, mime_type):
    """Detect whether file is an image or document"""
    if mime_type in IMAGE_MIME_TYPES:
        return 'image'
    elif mime_type in DOCUMENT_MIME_TYPES:
        return 'document'
    # Fallback to extension
    ext = os.path.splitext(filename)[1].lower()
    if ext in ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'):
        return 'image'
    elif ext in ('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'):
        return 'document'
    return 'unknown'


@forensics_bp.route('/', methods=['GET', 'POST'])
@login_required
def upload():
    """Upload file for forensic analysis"""
    if request.method == 'POST':
        case_id = request.form.get('case_id')

        if not case_id:
            flash('Please select a case to link this analysis.', 'danger')
            return redirect(url_for('forensics.upload'))

        case = Case.query.get(case_id)
        if not case:
            flash('Invalid case selected.', 'danger')
            return redirect(url_for('forensics.upload'))

        if not current_user.can_access_case(case):
            flash('You do not have permission to access this case.', 'danger')
            return redirect(url_for('forensics.upload'))

        file = request.files.get('file')
        if not file or not file.filename:
            flash('Please upload a file for analysis.', 'danger')
            return redirect(url_for('forensics.upload'))

        try:
            from werkzeug.utils import secure_filename

            filename = secure_filename(file.filename)
            upload_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], str(case_id))
            os.makedirs(upload_dir, exist_ok=True)
            file_path = os.path.join(upload_dir, filename)
            file.save(file_path)

            # Compute file hash and size
            with open(file_path, 'rb') as f:
                file_data = f.read()
                file_hash = hashlib.sha256(file_data).hexdigest()
                file_size = len(file_data)

            mime_type = file.content_type or 'application/octet-stream'
            file_type = _detect_file_type(filename, mime_type)

            if file_type == 'image':
                return _process_image(case, case_id, filename, file_path, file_hash, file_size, mime_type)
            elif file_type == 'document':
                return _process_document(case, case_id, filename, file_path, file_hash, file_size, mime_type)
            else:
                flash('Unsupported file type. Please upload an image or document.', 'danger')
                return redirect(url_for('forensics.upload'))

        except Exception as e:
            db.session.rollback()
            flash(f'Analysis failed: {str(e)}', 'danger')

            AuditLog.log_action(
                user_id=current_user.id,
                username=current_user.username,
                badge_number=current_user.badge_number,
                action='forensics_analysis_failed',
                action_category='investigation',
                resource_type='investigation',
                details={'filename': filename if 'filename' in dir() else 'unknown', 'error': str(e)},
                status='failure',
                error_message=str(e),
                ip_address=request.remote_addr
            )

            return redirect(url_for('forensics.upload'))

    # GET request
    cases = _get_user_cases()
    recent_investigations = Investigation.query.filter_by(
        investigator_id=current_user.id
    ).filter(
        Investigation.investigation_type.in_(['image_forensics', 'document_forensics'])
    ).order_by(Investigation.created_at.desc()).limit(5).all()

    return render_template('forensics/upload.html',
                         cases=cases,
                         recent_investigations=recent_investigations)


def _process_image(case, case_id, filename, file_path, file_hash, file_size, mime_type):
    """Process image file for forensic analysis"""
    from app.modules.image_forensics import ImageForensics

    start_time = time.time()
    analyzer = ImageForensics()
    results = analyzer.analyze_image(file_path)
    execution_time = time.time() - start_time

    # Create ForensicImage record
    forensic_image = ForensicImage(
        case_id=case_id,
        original_filename=filename,
        stored_filename=filename,
        file_hash=file_hash,
        file_size=file_size,
        mime_type=mime_type,
        exif_data=results.get('exif_data'),
        gps_latitude=results.get('gps', {}).get('latitude'),
        gps_longitude=results.get('gps', {}).get('longitude'),
        gps_location_name=results.get('gps', {}).get('location_name'),
        device_make=results.get('device', {}).get('make'),
        device_model=results.get('device', {}).get('model'),
        capture_date=datetime.fromisoformat(results['capture_date']) if results.get('capture_date') else None,
        modification_history=results.get('modification_history'),
        ela_result=results.get('ela_result'),
        manipulation_detected=results.get('manipulation_detected'),
        manipulation_confidence=results.get('manipulation_confidence'),
        ocr_text=results.get('ocr_text'),
        reverse_search_results=results.get('reverse_search_results'),
        risk_score=results.get('risk_score', 0),
        analyzed_by=current_user.id
    )
    db.session.add(forensic_image)
    db.session.flush()

    # Create Investigation record
    investigation = Investigation(
        case_id=case_id,
        investigator_id=current_user.id,
        investigation_type='image_forensics',
        target_identifier=filename,
        tool_used='Image Forensics Module',
        raw_results=results,
        processed_results={
            'file_hash': file_hash,
            'file_size': file_size,
            'has_exif': bool(results.get('exif_data')),
            'has_gps': bool(results.get('gps', {}).get('latitude')),
            'manipulation_detected': results.get('manipulation_detected'),
            'risk_score': results.get('risk_score', 0),
            'forensic_image_id': str(forensic_image.id)
        },
        status='completed',
        execution_time=execution_time,
        confidence_score=85
    )

    investigation.generate_evidence_hash()
    db.session.add(investigation)
    db.session.flush()

    forensic_image.investigation_id = investigation.id
    db.session.commit()

    investigation.mark_completed(investigation.processed_results, execution_time)

    AuditLog.log_investigation(
        user=current_user,
        investigation_type='image_forensics',
        target=filename,
        case_id=case_id,
        case_number=case.case_number,
        success=True,
        details={
            'investigation_id': str(investigation.id),
            'file_hash': file_hash,
            'manipulation_detected': results.get('manipulation_detected'),
            'execution_time': execution_time
        },
        ip_address=request.remote_addr
    )

    flash(f'Image forensic analysis completed successfully!', 'success')
    return redirect(url_for('forensics.view_image_result', investigation_id=investigation.id))


def _process_document(case, case_id, filename, file_path, file_hash, file_size, mime_type):
    """Process document file for forensic analysis"""
    from app.modules.image_forensics import ImageForensics

    start_time = time.time()
    analyzer = ImageForensics()
    results = analyzer.analyze_document(file_path)
    execution_time = time.time() - start_time

    # Create ForensicDocument record
    forensic_doc = ForensicDocument(
        case_id=case_id,
        original_filename=filename,
        stored_filename=filename,
        file_hash=file_hash,
        file_size=file_size,
        mime_type=mime_type,
        doc_metadata=results.get('metadata'),
        author=results.get('author'),
        creator_tool=results.get('creator_tool'),
        creation_date=datetime.fromisoformat(results['creation_date']) if results.get('creation_date') else None,
        modification_date=datetime.fromisoformat(results['modification_date']) if results.get('modification_date') else None,
        page_count=results.get('page_count'),
        extracted_text=results.get('extracted_text'),
        embedded_objects=results.get('embedded_objects'),
        risk_score=results.get('risk_score', 0),
        analyzed_by=current_user.id
    )
    db.session.add(forensic_doc)
    db.session.flush()

    # Create Investigation record
    investigation = Investigation(
        case_id=case_id,
        investigator_id=current_user.id,
        investigation_type='document_forensics',
        target_identifier=filename,
        tool_used='Document Forensics Module',
        raw_results=results,
        processed_results={
            'file_hash': file_hash,
            'file_size': file_size,
            'author': results.get('author'),
            'creator_tool': results.get('creator_tool'),
            'page_count': results.get('page_count'),
            'risk_score': results.get('risk_score', 0),
            'forensic_document_id': str(forensic_doc.id)
        },
        status='completed',
        execution_time=execution_time,
        confidence_score=85
    )

    investigation.generate_evidence_hash()
    db.session.add(investigation)
    db.session.flush()

    forensic_doc.investigation_id = investigation.id
    db.session.commit()

    investigation.mark_completed(investigation.processed_results, execution_time)

    AuditLog.log_investigation(
        user=current_user,
        investigation_type='document_forensics',
        target=filename,
        case_id=case_id,
        case_number=case.case_number,
        success=True,
        details={
            'investigation_id': str(investigation.id),
            'file_hash': file_hash,
            'author': results.get('author'),
            'execution_time': execution_time
        },
        ip_address=request.remote_addr
    )

    flash(f'Document forensic analysis completed successfully!', 'success')
    return redirect(url_for('forensics.view_document_result', investigation_id=investigation.id))


@forensics_bp.route('/image/<investigation_id>')
@login_required
def view_image_result(investigation_id):
    """View image forensic analysis results"""
    investigation = Investigation.query.get_or_404(investigation_id)

    case = Case.query.get(investigation.case_id)
    if not current_user.can_access_case(case):
        flash('You do not have permission to view this investigation.', 'danger')
        return redirect(url_for('investigations.index'))

    forensic_image = ForensicImage.query.filter_by(
        investigation_id=investigation_id
    ).first()

    AuditLog.log_case_access(
        user=current_user,
        case=case,
        action='view_investigation',
        ip_address=request.remote_addr
    )

    return render_template('forensics/image_result.html',
                         investigation=investigation,
                         case=case,
                         forensic_image=forensic_image)


@forensics_bp.route('/document/<investigation_id>')
@login_required
def view_document_result(investigation_id):
    """View document forensic analysis results"""
    investigation = Investigation.query.get_or_404(investigation_id)

    case = Case.query.get(investigation.case_id)
    if not current_user.can_access_case(case):
        flash('You do not have permission to view this investigation.', 'danger')
        return redirect(url_for('investigations.index'))

    forensic_doc = ForensicDocument.query.filter_by(
        investigation_id=investigation_id
    ).first()

    AuditLog.log_case_access(
        user=current_user,
        case=case,
        action='view_investigation',
        ip_address=request.remote_addr
    )

    return render_template('forensics/document_result.html',
                         investigation=investigation,
                         case=case,
                         forensic_document=forensic_doc)
