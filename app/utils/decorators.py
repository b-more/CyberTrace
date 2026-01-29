"""
Utility Decorators
CyberTrace OSINT Platform - Zambia Police Service

Custom decorators for authentication, authorization, and access control
"""

from functools import wraps
from flask import flash, redirect, url_for, abort, request
from flask_login import current_user


def login_required(f):
    """
    Decorator to require user login
    Redirects to login page if not authenticated
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def permission_required(permission):
    """
    Decorator to require specific permission

    Args:
        permission (str): Permission name to check

    Usage:
        @permission_required('create_case')
        def create_case():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('auth.login', next=request.url))

            if not current_user.has_permission(permission):
                flash('You do not have permission to access this resource.', 'danger')
                abort(403)

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def role_required(*roles):
    """
    Decorator to require specific role(s)

    Args:
        *roles: One or more role names

    Usage:
        @role_required('admin', 'senior_investigator')
        def admin_function():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('auth.login', next=request.url))

            if current_user.role not in roles:
                flash('You do not have the required role to access this resource.', 'danger')
                abort(403)

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    """
    Decorator to require admin role
    Shortcut for @role_required('admin')
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login', next=request.url))

        if current_user.role != 'admin':
            flash('Administrator access required.', 'danger')
            abort(403)

        return f(*args, **kwargs)
    return decorated_function


def terms_required(f):
    """
    Decorator to require terms and conditions acceptance
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login', next=request.url))

        if not current_user.terms_accepted:
            flash('You must accept the terms and conditions to continue.', 'warning')
            return redirect(url_for('auth.accept_terms', next=request.url))

        return f(*args, **kwargs)
    return decorated_function


def account_active_required(f):
    """
    Decorator to check if user account is active
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login', next=request.url))

        if not current_user.is_active:
            flash('Your account has been deactivated. Contact administrator.', 'danger')
            return redirect(url_for('auth.login'))

        if current_user.is_account_locked():
            flash('Your account is temporarily locked due to failed login attempts.', 'warning')
            return redirect(url_for('auth.login'))

        return f(*args, **kwargs)
    return decorated_function


def case_access_required(f):
    """
    Decorator to check if user can access a specific case
    Expects case_id in route parameters
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login', next=request.url))

        from app.models.case import Case

        case_id = kwargs.get('case_id')
        if not case_id:
            abort(400)

        case = Case.query.get_or_404(case_id)

        if not current_user.can_access_case(case):
            flash('You do not have access to this case.', 'danger')
            abort(403)

        return f(*args, **kwargs)
    return decorated_function
