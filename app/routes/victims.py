"""
Victim Management Routes
Zambia Police Service CyberTrace OSINT Platform

Victim registration, statement management, and loss statistics
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, jsonify, current_app
from flask_login import current_user
from app import db
from app.models.case import Case
from app.models.investigation import Investigation
from app.models.audit_log import AuditLog
from app.utils.decorators import login_required, permission_required
from datetime import datetime
import os, tempfile, time

victims_bp = Blueprint('victims', __name__)


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


def _get_accessible_case_ids():
    """Get list of case IDs accessible by the current user"""
    cases = _get_user_cases()
    return [c.id for c in cases]


@victims_bp.route('/')
@login_required
def list_victims():
    """List victim records for accessible cases"""
    try:
        from app.models.victim import Victim

        accessible_case_ids = _get_accessible_case_ids()

        if current_user.role in ['admin', 'senior_investigator']:
            victims = Victim.query.order_by(Victim.created_at.desc()).all()
        else:
            victims = Victim.query.filter(
                Victim.case_id.in_(accessible_case_ids)
            ).order_by(Victim.created_at.desc()).all()
    except Exception:
        victims = []

    # Compute stats for dashboard cards
    stats = {
        'total_victims': len(victims),
        'total_losses': sum(getattr(v, 'financial_loss', 0) or 0 for v in victims),
        'pending_statements': sum(1 for v in victims if getattr(v, 'statement_status', '') == 'pending'),
        'by_type': {},
    }
    for v in victims:
        vtype = getattr(v, 'victim_type', 'unknown') or 'unknown'
        stats['by_type'][vtype] = stats['by_type'].get(vtype, 0) + 1

    return render_template('victims/list.html',
                         victims=victims,
                         stats=stats)


@victims_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_victim():
    """Create a new victim record"""
    if request.method == 'POST':
        case_id = request.form.get('case_id')
        full_name = request.form.get('full_name', '').strip()
        id_number = request.form.get('id_number', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        email = request.form.get('email', '').strip()
        address = request.form.get('address', '').strip()
        age = request.form.get('age', type=int)
        gender = request.form.get('gender', '').strip()
        occupation = request.form.get('occupation', '').strip()
        financial_loss = request.form.get('financial_loss', type=float, default=0)
        currency = request.form.get('currency', 'ZMW').strip()
        fraud_type = request.form.get('fraud_type', '').strip()
        description = request.form.get('description', '').strip()

        if not case_id:
            flash('Please select a case.', 'danger')
            return redirect(url_for('victims.create_victim'))

        if not full_name:
            flash('Victim full name is required.', 'danger')
            return redirect(url_for('victims.create_victim'))

        case = Case.query.get(case_id)
        if not case:
            flash('Invalid case selected.', 'danger')
            return redirect(url_for('victims.create_victim'))

        if not current_user.can_access_case(case):
            flash('You do not have permission to access this case.', 'danger')
            return redirect(url_for('victims.create_victim'))

        try:
            from app.models.victim import Victim

            victim = Victim(
                case_id=case_id,
                full_name=full_name,
                id_number=id_number if id_number else None,
                phone_number=phone_number if phone_number else None,
                email=email if email else None,
                address=address if address else None,
                age=age,
                gender=gender if gender else None,
                occupation=occupation if occupation else None,
                financial_loss=financial_loss,
                currency=currency,
                fraud_type=fraud_type if fraud_type else None,
                description=description if description else None,
                registered_by=current_user.id
            )
            db.session.add(victim)
            db.session.commit()

            AuditLog.log_action(
                user_id=current_user.id,
                username=current_user.username,
                badge_number=current_user.badge_number,
                action='create_victim_record',
                action_category='case_management',
                resource_type='victim',
                resource_id=str(victim.id),
                resource_identifier=case.case_number,
                details={
                    'victim_name': full_name,
                    'financial_loss': financial_loss,
                    'currency': currency,
                    'fraud_type': fraud_type
                },
                ip_address=request.remote_addr
            )

            flash(f'Victim record created successfully for case {case.case_number}.', 'success')
            return redirect(url_for('victims.view_victim', victim_id=victim.id))

        except Exception as e:
            db.session.rollback()
            flash(f'Failed to create victim record: {str(e)}', 'danger')
            return redirect(url_for('victims.create_victim'))

    # GET request
    cases = _get_user_cases()
    return render_template('victims/create.html', cases=cases)


@victims_bp.route('/<victim_id>')
@login_required
def view_victim(victim_id):
    """View victim record details"""
    try:
        from app.models.victim import Victim, VictimStatement

        victim = Victim.query.get_or_404(victim_id)

        case = Case.query.get(victim.case_id)
        if not current_user.can_access_case(case):
            flash('You do not have permission to view this victim record.', 'danger')
            return redirect(url_for('victims.list_victims'))

        statements = VictimStatement.query.filter_by(
            victim_id=victim_id
        ).order_by(VictimStatement.created_at.desc()).all()

        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='view_victim_record',
            action_category='case_management',
            resource_type='victim',
            resource_id=str(victim_id),
            resource_identifier=case.case_number,
            ip_address=request.remote_addr
        )

        return render_template('victims/detail.html',
                             victim=victim,
                             case=case,
                             statements=statements)

    except Exception as e:
        flash(f'Failed to load victim record: {str(e)}', 'danger')
        return redirect(url_for('victims.list_victims'))


@victims_bp.route('/<victim_id>/statement', methods=['POST'])
@login_required
def add_statement(victim_id):
    """Add a victim statement (text or file upload)"""
    try:
        from app.models.victim import Victim, VictimStatement

        victim = Victim.query.get_or_404(victim_id)

        case = Case.query.get(victim.case_id)
        if not current_user.can_access_case(case):
            flash('You do not have permission to add statements to this victim record.', 'danger')
            return redirect(url_for('victims.list_victims'))

        statement_text = request.form.get('statement_text', '').strip()
        statement_type = request.form.get('statement_type', 'written')
        file = request.files.get('file')

        if not statement_text and (not file or not file.filename):
            flash('Please provide a statement text or upload a file.', 'danger')
            return redirect(url_for('victims.view_victim', victim_id=victim_id))

        file_path = None
        filename = None

        if file and file.filename:
            from werkzeug.utils import secure_filename

            filename = secure_filename(file.filename)
            upload_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], str(victim.case_id), 'statements')
            os.makedirs(upload_dir, exist_ok=True)
            file_path = os.path.join(upload_dir, filename)
            file.save(file_path)

        statement = VictimStatement(
            victim_id=victim_id,
            statement_type=statement_type,
            statement_text=statement_text if statement_text else None,
            file_path=file_path,
            filename=filename,
            recorded_by=current_user.id
        )
        db.session.add(statement)
        db.session.commit()

        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='add_victim_statement',
            action_category='case_management',
            resource_type='victim_statement',
            resource_id=str(statement.id),
            resource_identifier=case.case_number,
            details={
                'victim_id': victim_id,
                'statement_type': statement_type,
                'has_file': bool(file_path),
                'has_text': bool(statement_text)
            },
            ip_address=request.remote_addr
        )

        flash('Victim statement added successfully.', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Failed to add statement: {str(e)}', 'danger')

    return redirect(url_for('victims.view_victim', victim_id=victim_id))


@victims_bp.route('/stats')
@login_required
def victim_stats():
    """View victim and financial loss statistics"""
    try:
        from app.models.victim import Victim
        from sqlalchemy import func

        accessible_case_ids = _get_accessible_case_ids()

        if current_user.role in ['admin', 'senior_investigator']:
            base_query = Victim.query
        else:
            base_query = Victim.query.filter(Victim.case_id.in_(accessible_case_ids))

        total_victims = base_query.count()

        loss_stats = db.session.query(
            func.sum(Victim.financial_loss).label('total_loss'),
            func.avg(Victim.financial_loss).label('avg_loss'),
            func.max(Victim.financial_loss).label('max_loss'),
            func.count(Victim.id).label('count')
        ).filter(
            Victim.case_id.in_(accessible_case_ids) if current_user.role not in ['admin', 'senior_investigator'] else True
        ).first()

        # Loss by fraud type
        loss_by_type = db.session.query(
            Victim.fraud_type,
            func.count(Victim.id).label('count'),
            func.sum(Victim.financial_loss).label('total_loss')
        ).filter(
            Victim.case_id.in_(accessible_case_ids) if current_user.role not in ['admin', 'senior_investigator'] else True
        ).group_by(Victim.fraud_type).all()

        stats = {
            'total_victims': total_victims,
            'total_loss': loss_stats.total_loss or 0 if loss_stats else 0,
            'avg_loss': loss_stats.avg_loss or 0 if loss_stats else 0,
            'max_loss': loss_stats.max_loss or 0 if loss_stats else 0,
            'loss_by_type': [
                {'fraud_type': lt.fraud_type or 'Unspecified', 'count': lt.count, 'total_loss': lt.total_loss or 0}
                for lt in loss_by_type
            ]
        }

    except Exception:
        stats = {
            'total_victims': 0,
            'total_loss': 0,
            'avg_loss': 0,
            'max_loss': 0,
            'loss_by_type': []
        }

    return render_template('victims/stats.html',
                         stats=stats)
