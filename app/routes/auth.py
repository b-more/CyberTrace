"""
Authentication Routes
CyberTrace OSINT Platform - Zambia Police Service

Handles user authentication, login, logout, and account management
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, current_user
from app import db, csrf
from app.models.user import User
from app.models.audit_log import AuditLog
from app.utils.validators import validate_password_strength
import pyotp
import qrcode
import io
import base64

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    # Redirect if already logged in
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        badge_number = request.form.get('badge_number', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)

        if not badge_number or not password:
            flash('Please provide both badge number and password.', 'danger')
            return render_template('auth/login.html')

        # Find user
        user = User.query.filter_by(badge_number=badge_number).first()

        if not user:
            # Log failed attempt
            AuditLog.log_login(
                badge_number,
                request.remote_addr,
                request.headers.get('User-Agent'),
                success=False,
                error_message='Invalid badge number'
            )
            flash('Invalid badge number or password.', 'danger')
            return render_template('auth/login.html')

        # Check if account is locked
        if user.is_account_locked():
            flash('Your account is temporarily locked due to multiple failed login attempts. Please try again later.', 'warning')
            return render_template('auth/login.html')

        # Check if account is active
        if not user.is_active:
            flash('Your account has been deactivated. Please contact the administrator.', 'danger')
            return render_template('auth/login.html')

        # Verify password
        if not user.check_password(password):
            # Record failed attempt
            user.record_login_attempt(False, request.remote_addr)

            # Log failed attempt
            AuditLog.log_login(
                user,
                request.remote_addr,
                request.headers.get('User-Agent'),
                success=False,
                error_message='Invalid password'
            )

            flash('Invalid badge number or password.', 'danger')
            return render_template('auth/login.html')

        # Check if 2FA is enabled
        if user.is_2fa_enabled:
            # Store user ID in session for 2FA verification
            session['2fa_user_id'] = user.id
            session['2fa_remember'] = remember
            return redirect(url_for('auth.verify_2fa'))

        # Login successful
        login_user(user, remember=remember)
        user.record_login_attempt(True, request.remote_addr)

        # Log successful login
        AuditLog.log_login(
            user,
            request.remote_addr,
            request.headers.get('User-Agent'),
            success=True
        )

        flash(f'Welcome back, {user.full_name}!', 'success')

        # Check if terms need to be accepted
        if not user.terms_accepted:
            return redirect(url_for('auth.accept_terms'))

        # Redirect to next page or dashboard
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect(url_for('dashboard.index'))

    return render_template('auth/login.html')


@auth_bp.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    """Verify 2FA token"""
    user_id = session.get('2fa_user_id')

    if not user_id:
        flash('Please log in first.', 'warning')
        return redirect(url_for('auth.login'))

    user = User.query.get(user_id)
    if not user:
        session.pop('2fa_user_id', None)
        flash('Invalid session. Please log in again.', 'danger')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        token = request.form.get('token', '').strip()

        if not token:
            flash('Please enter the 6-digit code.', 'danger')
            return render_template('auth/verify_2fa.html')

        # Verify TOTP token
        if user.verify_totp(token):
            # Login successful
            remember = session.get('2fa_remember', False)
            login_user(user, remember=remember)
            user.record_login_attempt(True, request.remote_addr)

            # Clear 2FA session
            session.pop('2fa_user_id', None)
            session.pop('2fa_remember', None)

            # Log successful login
            AuditLog.log_login(
                user,
                request.remote_addr,
                request.headers.get('User-Agent'),
                success=True
            )

            flash(f'Welcome back, {user.full_name}!', 'success')

            # Check terms
            if not user.terms_accepted:
                return redirect(url_for('auth.accept_terms'))

            # Redirect
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard.index'))
        else:
            flash('Invalid verification code. Please try again.', 'danger')
            return render_template('auth/verify_2fa.html')

    return render_template('auth/verify_2fa.html')


@auth_bp.route('/logout')
def logout():
    """User logout"""
    if current_user.is_authenticated:
        # Log logout
        AuditLog.log_logout(
            current_user,
            request.remote_addr,
            request.headers.get('User-Agent')
        )

        logout_user()
        flash('You have been logged out successfully.', 'info')

    return redirect(url_for('auth.login'))


@auth_bp.route('/accept-terms', methods=['GET', 'POST'])
@csrf.exempt
def accept_terms():
    """Terms and conditions acceptance"""
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))

    if current_user.terms_accepted:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        accept = request.form.get('accept_terms')

        if accept == 'yes':
            current_user.accept_terms()
            flash('Terms and conditions accepted.', 'success')
            return redirect(url_for('dashboard.index'))
        else:
            flash('You must accept the terms and conditions to continue.', 'warning')

    return render_template('auth/terms.html')


@auth_bp.route('/change-password', methods=['GET', 'POST'])
def change_password():
    """Change password"""
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validate current password
        if not current_user.check_password(current_password):
            flash('Current password is incorrect.', 'danger')
            return render_template('auth/change_password.html')

        # Validate new password
        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return render_template('auth/change_password.html')

        # Check password strength
        is_valid, errors = validate_password_strength(new_password)
        if not is_valid:
            for error in errors:
                flash(error, 'danger')
            return render_template('auth/change_password.html')

        # Update password
        current_user.set_password(new_password)
        db.session.commit()

        # Log action
        AuditLog.log_action(
            user_id=current_user.id,
            username=current_user.username,
            badge_number=current_user.badge_number,
            action='change_password',
            action_category='authentication',
            ip_address=request.remote_addr
        )

        flash('Password changed successfully.', 'success')
        return redirect(url_for('dashboard.index'))

    return render_template('auth/change_password.html')


@auth_bp.route('/setup-2fa', methods=['GET', 'POST'])
def setup_2fa():
    """Set up two-factor authentication"""
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'enable':
            # Generate TOTP secret if not exists
            if not current_user.totp_secret:
                current_user.generate_totp_secret()
                db.session.commit()

            # Get QR code URI
            totp_uri = current_user.get_totp_uri()

            # Generate QR code
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(totp_uri)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")

            # Convert to base64 for display
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            img_base64 = base64.b64encode(buffer.getvalue()).decode()

            return render_template(
                'auth/setup_2fa.html',
                qr_code=img_base64,
                secret=current_user.totp_secret,
                enabling=True
            )

        elif action == 'confirm':
            token = request.form.get('token', '').strip()

            if current_user.verify_totp(token):
                current_user.is_2fa_enabled = True
                db.session.commit()

                # Log action
                AuditLog.log_action(
                    user_id=current_user.id,
                    username=current_user.username,
                    badge_number=current_user.badge_number,
                    action='enable_2fa',
                    action_category='authentication',
                    ip_address=request.remote_addr
                )

                flash('Two-factor authentication enabled successfully!', 'success')
                return redirect(url_for('dashboard.index'))
            else:
                flash('Invalid verification code. Please try again.', 'danger')
                return redirect(url_for('auth.setup_2fa'))

        elif action == 'disable':
            token = request.form.get('token', '').strip()

            if current_user.verify_totp(token):
                current_user.is_2fa_enabled = False
                db.session.commit()

                # Log action
                AuditLog.log_action(
                    user_id=current_user.id,
                    username=current_user.username,
                    badge_number=current_user.badge_number,
                    action='disable_2fa',
                    action_category='authentication',
                    ip_address=request.remote_addr
                )

                flash('Two-factor authentication disabled.', 'info')
                return redirect(url_for('dashboard.index'))
            else:
                flash('Invalid verification code.', 'danger')

    return render_template('auth/setup_2fa.html')


@auth_bp.route('/profile')
def profile():
    """User profile page"""
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))

    return render_template('auth/profile.html')
