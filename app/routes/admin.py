"""
Administration Routes
CyberTrace OSINT Platform - Zambia Police Service

User management, system settings, and audit logs
"""

from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask_login import current_user
from flask_wtf.csrf import CSRFProtect
from app.models.user import User
from app.models.audit_log import AuditLog
from app.utils.decorators import login_required, admin_required
from app import db
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
from sqlalchemy import desc, or_

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Get CSRF instance
from app import csrf


@admin_bp.route('/users')
@login_required
@admin_required
def list_users():
    """List all users"""
    search = request.args.get('search', '')
    role_filter = request.args.get('role', '')
    status_filter = request.args.get('status', '')

    query = User.query

    # Apply search filter
    if search:
        query = query.filter(
            or_(
                User.full_name.ilike(f'%{search}%'),
                User.badge_number.ilike(f'%{search}%'),
                User.email.ilike(f'%{search}%'),
                User.username.ilike(f'%{search}%')
            )
        )

    # Apply role filter
    if role_filter:
        query = query.filter_by(role=role_filter)

    # Apply status filter
    if status_filter == 'active':
        query = query.filter_by(is_active=True)
    elif status_filter == 'inactive':
        query = query.filter_by(is_active=False)
    elif status_filter == 'locked':
        query = query.filter_by(is_locked=True)

    users = query.order_by(User.full_name).all()

    # Get statistics
    stats = {
        'total_users': User.query.count(),
        'active_users': User.query.filter_by(is_active=True).count(),
        'inactive_users': User.query.filter_by(is_active=False).count(),
        'locked_users': User.query.filter_by(is_locked=True).count(),
        'admins': User.query.filter_by(role='admin').count(),
        'investigators': User.query.filter(User.role.in_(['senior_investigator', 'investigator'])).count()
    }

    return render_template(
        'admin/users_list.html',
        users=users,
        stats=stats,
        search=search,
        role_filter=role_filter,
        status_filter=status_filter
    )


@admin_bp.route('/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
@csrf.exempt
def create_user():
    """Create a new user"""
    if request.method == 'POST':
        try:
            # Validate required fields
            required_fields = ['badge_number', 'full_name', 'email', 'username', 'password', 'role', 'rank', 'department']
            for field in required_fields:
                if not request.form.get(field):
                    flash(f'{field.replace("_", " ").title()} is required', 'error')
                    return redirect(url_for('admin.create_user'))

            # Check for duplicate badge number
            if User.query.filter_by(badge_number=request.form.get('badge_number')).first():
                flash('Badge number already exists', 'error')
                return redirect(url_for('admin.create_user'))

            # Check for duplicate username
            if User.query.filter_by(username=request.form.get('username')).first():
                flash('Username already exists', 'error')
                return redirect(url_for('admin.create_user'))

            # Check for duplicate email
            if User.query.filter_by(email=request.form.get('email')).first():
                flash('Email already exists', 'error')
                return redirect(url_for('admin.create_user'))

            # Create new user
            user = User(
                badge_number=request.form.get('badge_number'),
                full_name=request.form.get('full_name'),
                email=request.form.get('email'),
                username=request.form.get('username'),
                password_hash=generate_password_hash(request.form.get('password')),
                role=request.form.get('role'),
                rank=request.form.get('rank'),
                department=request.form.get('department'),
                is_active=True,
                created_at=datetime.utcnow()
            )

            db.session.add(user)
            db.session.commit()

            # Log the action
            audit_log = AuditLog(
                user_id=current_user.id,
                username=current_user.username,
                badge_number=current_user.badge_number,
                action='user_created',
                action_category='user_management',
                resource_type='user',
                resource_id=user.id,
                resource_identifier=user.badge_number,
                details={'message': f'Created user {user.full_name} ({user.badge_number})'},
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            db.session.add(audit_log)
            db.session.commit()

            flash(f'User {user.full_name} created successfully', 'success')
            return redirect(url_for('admin.list_users'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {str(e)}', 'error')
            return redirect(url_for('admin.create_user'))

    return render_template('admin/user_create.html')


@admin_bp.route('/users/<string:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
@csrf.exempt
def edit_user(user_id):
    """Edit user details"""
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        try:
            # Update user details
            user.full_name = request.form.get('full_name', user.full_name)
            user.email = request.form.get('email', user.email)
            user.role = request.form.get('role', user.role)
            user.rank = request.form.get('rank', user.rank)
            user.department = request.form.get('department', user.department)
            user.phone_number = request.form.get('phone_number', user.phone_number)

            # Update password if provided
            if request.form.get('new_password'):
                user.password_hash = generate_password_hash(request.form.get('new_password'))

            db.session.commit()

            # Log the action
            audit_log = AuditLog(
                user_id=current_user.id,
                username=current_user.username,
                badge_number=current_user.badge_number,
                action='user_updated',
                action_category='user_management',
                resource_type='user',
                resource_id=user.id,
                resource_identifier=user.badge_number,
                details={'message': f'Updated user {user.full_name} ({user.badge_number})'},
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            db.session.add(audit_log)
            db.session.commit()

            flash(f'User {user.full_name} updated successfully', 'success')
            return redirect(url_for('admin.list_users'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error updating user: {str(e)}', 'error')

    return render_template('admin/user_edit.html', user=user)


@admin_bp.route('/users/<string:user_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
@csrf.exempt
def toggle_user_status(user_id):
    """Activate or deactivate a user"""
    user = User.query.get_or_404(user_id)

    # Prevent deactivating yourself
    if user.id == current_user.id:
        flash('You cannot deactivate your own account', 'error')
        return redirect(url_for('admin.list_users'))

    try:
        user.is_active = not user.is_active
        db.session.commit()

        status = 'activated' if user.is_active else 'deactivated'

        # Log the action
        audit_log = AuditLog(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action=f'user_{status}',
            action_category='user_management',
            resource_type='user',
            resource_id=user.id,
            resource_identifier=user.badge_number,
            details={'message': f'{status.title()} user {user.full_name} ({user.badge_number})'},
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        db.session.add(audit_log)
        db.session.commit()

        flash(f'User {user.full_name} {status} successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating user status: {str(e)}', 'error')

    return redirect(url_for('admin.list_users'))


@admin_bp.route('/users/<string:user_id>/unlock', methods=['POST'])
@login_required
@admin_required
@csrf.exempt
def unlock_user(user_id):
    """Unlock a locked user account"""
    user = User.query.get_or_404(user_id)

    try:
        user.is_locked = False
        user.failed_login_attempts = 0
        db.session.commit()

        # Log the action
        audit_log = AuditLog(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='user_unlocked',
            action_category='user_management',
            resource_type='user',
            resource_id=user.id,
            resource_identifier=user.badge_number,
            details={'message': f'Unlocked user {user.full_name} ({user.badge_number})'},
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        db.session.add(audit_log)
        db.session.commit()

        flash(f'User {user.full_name} unlocked successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error unlocking user: {str(e)}', 'error')

    return redirect(url_for('admin.list_users'))


@admin_bp.route('/users/<string:user_id>/reset-password', methods=['POST'])
@login_required
@admin_required
@csrf.exempt
def reset_user_password(user_id):
    """Reset user password to a default value"""
    user = User.query.get_or_404(user_id)

    try:
        # Set default password (badge number)
        default_password = user.badge_number
        user.password_hash = generate_password_hash(default_password)
        db.session.commit()

        # Log the action
        audit_log = AuditLog(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='password_reset',
            action_category='user_management',
            resource_type='user',
            resource_id=user.id,
            resource_identifier=user.badge_number,
            details={'message': f'Reset password for user {user.full_name} ({user.badge_number})'},
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        db.session.add(audit_log)
        db.session.commit()

        flash(f'Password reset for {user.full_name}. New password is their badge number.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error resetting password: {str(e)}', 'error')

    return redirect(url_for('admin.list_users'))


@admin_bp.route('/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def system_settings():
    """System settings management"""
    if request.method == 'POST':
        try:
            # This would typically update a Settings model or config file
            # For now, we'll just show a success message
            flash('System settings updated successfully', 'success')
            return redirect(url_for('admin.system_settings'))
        except Exception as e:
            flash(f'Error updating settings: {str(e)}', 'error')

    # Get current settings from environment
    import os
    import sys
    import flask

    settings = {
        'app_name': os.getenv('APP_NAME', 'CyberTrace'),
        'organization': os.getenv('ORGANIZATION', 'Zambia Police Service'),
        'enable_2fa': os.getenv('ENABLE_2FA', 'True') == 'True',
        'email_osint': os.getenv('ENABLE_EMAIL_OSINT', 'True') == 'True',
        'phone_osint': os.getenv('ENABLE_PHONE_OSINT', 'True') == 'True',
        'social_media_osint': os.getenv('ENABLE_SOCIAL_MEDIA_OSINT', 'False') == 'True',
        'domain_ip_osint': os.getenv('ENABLE_DOMAIN_IP_OSINT', 'False') == 'True',
        'hunter_api_key': os.getenv('HUNTER_API_KEY', ''),
        'numverify_api_key': os.getenv('NUMVERIFY_API_KEY', ''),
    }

    return render_template(
        'admin/system_settings.html',
        settings=settings,
        python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        flask_version=flask.__version__
    )


@admin_bp.route('/audit-logs')
@login_required
@admin_required
def audit_logs():
    """View audit logs"""
    page = request.args.get('page', 1, type=int)
    per_page = 50

    # Filters
    action_filter = request.args.get('action', '')
    user_filter = request.args.get('user', '')
    entity_filter = request.args.get('entity', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')

    query = AuditLog.query

    # Apply filters
    if action_filter:
        query = query.filter_by(action=action_filter)

    if user_filter:
        query = query.filter_by(user_id=user_filter)

    if entity_filter:
        query = query.filter_by(resource_type=entity_filter)

    if date_from:
        date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
        query = query.filter(AuditLog.timestamp >= date_from_obj)

    if date_to:
        date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
        query = query.filter(AuditLog.timestamp < date_to_obj)

    # Paginate results
    logs = query.order_by(desc(AuditLog.timestamp)).paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Get unique actions and resource types for filters
    unique_actions = db.session.query(AuditLog.action).distinct().all()
    unique_entities = db.session.query(AuditLog.resource_type).distinct().all()

    # Get all users for filter
    users = User.query.order_by(User.full_name).all()

    return render_template(
        'admin/audit_logs.html',
        logs=logs,
        unique_actions=[a[0] for a in unique_actions],
        unique_entities=[e[0] for e in unique_entities],
        users=users,
        action_filter=action_filter,
        user_filter=user_filter,
        entity_filter=entity_filter,
        date_from=date_from,
        date_to=date_to
    )
