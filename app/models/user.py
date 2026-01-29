"""
User Model
Zambia Police Service CyberTrace OSINT Platform

Handles user authentication, authorization, and profile management
"""

import uuid
from datetime import datetime, timedelta
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
from app import db


class User(UserMixin, db.Model):
    """User model for authentication and authorization"""

    __tablename__ = 'users'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # User Identification
    badge_number = db.Column(db.String(50), unique=True, nullable=False, index=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    email = db.Column(db.String(150), unique=True, nullable=False)

    # Authentication
    password_hash = db.Column(db.String(255), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)  # For 2FA
    is_2fa_enabled = db.Column(db.Boolean, default=False)

    # Profile Information
    full_name = db.Column(db.String(150), nullable=False)
    rank = db.Column(db.String(50), nullable=False)
    department = db.Column(db.String(100), nullable=False)

    # Role-Based Access Control
    role = db.Column(
        db.Enum('admin', 'senior_investigator', 'investigator', 'analyst', name='user_roles'),
        nullable=False,
        default='investigator'
    )

    # Account Status
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_locked = db.Column(db.Boolean, default=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    # Session Management
    last_login = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(45), nullable=True)
    current_session_id = db.Column(db.String(255), nullable=True)

    # Terms and Conditions
    terms_accepted = db.Column(db.Boolean, default=False)
    terms_accepted_at = db.Column(db.DateTime, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    cases_lead = db.relationship('Case', back_populates='lead_investigator', foreign_keys='Case.lead_investigator_id')
    investigations = db.relationship('Investigation', back_populates='investigator', lazy='dynamic')
    evidence_collected = db.relationship('Evidence', back_populates='collector', lazy='dynamic')
    audit_logs = db.relationship('AuditLog', back_populates='user', lazy='dynamic')

    def __repr__(self):
        return f'<User {self.badge_number}: {self.full_name}>'

    def set_password(self, password):
        """
        Hash and set user password

        Args:
            password (str): Plain text password
        """
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        """
        Verify password against hash

        Args:
            password (str): Plain text password

        Returns:
            bool: True if password matches, False otherwise
        """
        return check_password_hash(self.password_hash, password)

    def generate_totp_secret(self):
        """Generate TOTP secret for 2FA"""
        self.totp_secret = pyotp.random_base32()
        return self.totp_secret

    def get_totp_uri(self, issuer='CyberTrace ZPS'):
        """
        Get TOTP URI for QR code generation

        Args:
            issuer (str): Issuer name for 2FA app

        Returns:
            str: TOTP URI
        """
        if not self.totp_secret:
            self.generate_totp_secret()

        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.email,
            issuer_name=issuer
        )

    def verify_totp(self, token):
        """
        Verify TOTP token for 2FA

        Args:
            token (str): 6-digit TOTP token

        Returns:
            bool: True if token is valid, False otherwise
        """
        if not self.totp_secret:
            return False

        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token, valid_window=1)  # Allow 1 time window variance

    def record_login_attempt(self, success, ip_address=None):
        """
        Record login attempt and handle account locking

        Args:
            success (bool): Whether login was successful
            ip_address (str): IP address of login attempt
        """
        if success:
            self.failed_login_attempts = 0
            self.is_locked = False
            self.locked_until = None
            self.last_login = datetime.utcnow()
            if ip_address:
                self.last_login_ip = ip_address
        else:
            self.failed_login_attempts += 1

            # Lock account after 5 failed attempts
            if self.failed_login_attempts >= 5:
                self.is_locked = True
                self.locked_until = datetime.utcnow() + timedelta(minutes=15)

        db.session.commit()

    def is_account_locked(self):
        """
        Check if account is locked

        Returns:
            bool: True if account is locked, False otherwise
        """
        if self.is_locked:
            # Check if lockout period has expired
            if self.locked_until and datetime.utcnow() > self.locked_until:
                self.is_locked = False
                self.failed_login_attempts = 0
                self.locked_until = None
                db.session.commit()
                return False
            return True
        return False

    def has_permission(self, permission):
        """
        Check if user has specific permission based on role

        Args:
            permission (str): Permission to check

        Returns:
            bool: True if user has permission, False otherwise
        """
        permissions_map = {
            'admin': [
                'view_all_cases',
                'create_case',
                'edit_case',
                'delete_case',
                'assign_case',
                'run_osint',
                'view_evidence',
                'upload_evidence',
                'generate_report',
                'manage_users',
                'view_audit_logs',
                'system_config'
            ],
            'senior_investigator': [
                'view_all_cases',
                'create_case',
                'edit_case',
                'assign_case',
                'run_osint',
                'view_evidence',
                'upload_evidence',
                'generate_report'
            ],
            'investigator': [
                'view_assigned_cases',
                'edit_assigned_case',
                'run_osint',
                'view_evidence',
                'upload_evidence',
                'generate_report'
            ],
            'analyst': [
                'view_assigned_cases',
                'run_osint',
                'view_evidence',
                'generate_report'
            ]
        }

        user_permissions = permissions_map.get(self.role, [])
        return permission in user_permissions

    def can_access_case(self, case):
        """
        Check if user can access a specific case

        Args:
            case: Case object

        Returns:
            bool: True if user can access case, False otherwise
        """
        # Admins and senior investigators can access all cases
        if self.role in ['admin', 'senior_investigator']:
            return True

        # Check if user is lead investigator
        if case.lead_investigator_id == self.id:
            return True

        # Check if user is assigned to case
        if self.id in case.assigned_officers:
            return True

        return False

    def accept_terms(self):
        """Mark that user has accepted terms and conditions"""
        self.terms_accepted = True
        self.terms_accepted_at = datetime.utcnow()
        db.session.commit()

    def to_dict(self):
        """
        Convert user object to dictionary

        Returns:
            dict: User data
        """
        return {
            'id': self.id,
            'badge_number': self.badge_number,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'rank': self.rank,
            'department': self.department,
            'role': self.role,
            'is_active': self.is_active,
            'is_2fa_enabled': self.is_2fa_enabled,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    @staticmethod
    def validate_password_strength(password):
        """
        Validate password strength

        Args:
            password (str): Password to validate

        Returns:
            tuple: (bool, str) - (is_valid, error_message)
        """
        if len(password) < 12:
            return False, "Password must be at least 12 characters long"

        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"

        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"

        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one number"

        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if not any(c in special_chars for c in password):
            return False, "Password must contain at least one special character"

        return True, "Password is strong"
