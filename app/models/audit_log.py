"""
Audit Log Model
Zambia Police Service CyberTrace OSINT Platform

Handles system audit logging and activity tracking
"""

import uuid
from datetime import datetime
from sqlalchemy import JSON
from app import db


class AuditLog(db.Model):
    """Audit log model for tracking all system activities"""

    __tablename__ = 'audit_logs'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # User Information
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True, index=True)
    # Nullable to allow logging of system events or failed login attempts

    username = db.Column(db.String(100), nullable=True)
    # Denormalized for quick access and to retain info if user is deleted

    badge_number = db.Column(db.String(50), nullable=True)
    # Denormalized for reporting

    # Action Details
    action = db.Column(db.String(100), nullable=False, index=True)
    # login, logout, search, export, create_case, edit_case, view_case, etc.

    action_category = db.Column(
        db.Enum('authentication', 'case_management', 'investigation', 'evidence',
                'user_management', 'system', 'export', name='action_categories'),
        nullable=False,
        index=True
    )

    # Resource Information
    resource_type = db.Column(db.String(50), nullable=True, index=True)
    # case, investigation, evidence, user, etc.

    resource_id = db.Column(db.String(36), nullable=True, index=True)
    # ID of the resource being acted upon

    resource_identifier = db.Column(db.String(255), nullable=True)
    # Human-readable identifier (case number, email, username, etc.)

    # Additional Details
    details = db.Column(JSON, nullable=True)
    # Additional context as JSON (search parameters, changes made, etc.)

    status = db.Column(
        db.Enum('success', 'failure', 'warning', name='log_status'),
        nullable=False,
        default='success'
    )

    error_message = db.Column(db.Text, nullable=True)
    # Error message if action failed

    # Request Information
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 compatible
    user_agent = db.Column(db.Text, nullable=True)
    request_method = db.Column(db.String(10), nullable=True)  # GET, POST, etc.
    request_path = db.Column(db.String(500), nullable=True)

    # Session Information
    session_id = db.Column(db.String(255), nullable=True)

    # Timestamp
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Relationships
    user = db.relationship('User', back_populates='audit_logs')

    def __repr__(self):
        return f'<AuditLog {self.action} by {self.username or "Unknown"} at {self.timestamp}>'

    @staticmethod
    def log_action(user_id, username, badge_number, action, action_category,
                   resource_type=None, resource_id=None, resource_identifier=None,
                   details=None, status='success', error_message=None,
                   ip_address=None, user_agent=None, request_method=None,
                   request_path=None, session_id=None):
        """
        Create audit log entry

        Args:
            user_id (str): User ID
            username (str): Username
            badge_number (str): Badge number
            action (str): Action performed
            action_category (str): Category of action
            resource_type (str): Type of resource
            resource_id (str): ID of resource
            resource_identifier (str): Human-readable identifier
            details (dict): Additional details
            status (str): Status of action
            error_message (str): Error message if failed
            ip_address (str): IP address
            user_agent (str): User agent string
            request_method (str): HTTP method
            request_path (str): Request path
            session_id (str): Session ID

        Returns:
            AuditLog: Created audit log entry
        """
        log_entry = AuditLog(
            user_id=user_id,
            username=username,
            badge_number=badge_number,
            action=action,
            action_category=action_category,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_identifier=resource_identifier,
            details=details,
            status=status,
            error_message=error_message,
            ip_address=ip_address,
            user_agent=user_agent,
            request_method=request_method,
            request_path=request_path,
            session_id=session_id
        )

        db.session.add(log_entry)
        db.session.commit()

        return log_entry

    @staticmethod
    def log_login(user, ip_address, user_agent, success=True, error_message=None):
        """
        Log login attempt

        Args:
            user: User object or username string
            ip_address (str): IP address
            user_agent (str): User agent
            success (bool): Whether login was successful
            error_message (str): Error message if failed
        """
        if isinstance(user, str):
            # Failed login with username only
            return AuditLog.log_action(
                user_id=None,
                username=user,
                badge_number=None,
                action='login_failed',
                action_category='authentication',
                status='failure',
                error_message=error_message,
                ip_address=ip_address,
                user_agent=user_agent
            )
        else:
            # Successful login with user object
            return AuditLog.log_action(
                user_id=user.id,
                username=user.username,
                badge_number=user.badge_number,
                action='login' if success else 'login_failed',
                action_category='authentication',
                status='success' if success else 'failure',
                error_message=error_message,
                ip_address=ip_address,
                user_agent=user_agent
            )

    @staticmethod
    def log_logout(user, ip_address, user_agent):
        """
        Log logout

        Args:
            user: User object
            ip_address (str): IP address
            user_agent (str): User agent
        """
        return AuditLog.log_action(
            user_id=user.id,
            username=user.username,
            badge_number=user.badge_number,
            action='logout',
            action_category='authentication',
            ip_address=ip_address,
            user_agent=user_agent
        )

    @staticmethod
    def log_investigation(user, investigation_type, target, case_id, case_number,
                         success=True, details=None, error_message=None, ip_address=None):
        """
        Log OSINT investigation

        Args:
            user: User object
            investigation_type (str): Type of investigation
            target (str): Target identifier
            case_id (str): Case ID
            case_number (str): Case number
            success (bool): Whether investigation succeeded
            details (dict): Investigation details
            error_message (str): Error message if failed
            ip_address (str): IP address
        """
        action_details = {
            'investigation_type': investigation_type,
            'target': target,
            'case_number': case_number
        }

        if details:
            action_details.update(details)

        return AuditLog.log_action(
            user_id=user.id,
            username=user.username,
            badge_number=user.badge_number,
            action=f'osint_{investigation_type}',
            action_category='investigation',
            resource_type='investigation',
            resource_id=case_id,
            resource_identifier=case_number,
            details=action_details,
            status='success' if success else 'failure',
            error_message=error_message,
            ip_address=ip_address
        )

    @staticmethod
    def log_case_access(user, case, action='view', ip_address=None):
        """
        Log case access

        Args:
            user: User object
            case: Case object
            action (str): Action performed (view, edit, create, delete)
            ip_address (str): IP address
        """
        return AuditLog.log_action(
            user_id=user.id,
            username=user.username,
            badge_number=user.badge_number,
            action=f'{action}_case',
            action_category='case_management',
            resource_type='case',
            resource_id=case.id,
            resource_identifier=case.case_number,
            ip_address=ip_address
        )

    @staticmethod
    def log_evidence_action(user, evidence, action, case_number, ip_address=None):
        """
        Log evidence action

        Args:
            user: User object
            evidence: Evidence object
            action (str): Action performed
            case_number (str): Case number
            ip_address (str): IP address
        """
        return AuditLog.log_action(
            user_id=user.id,
            username=user.username,
            badge_number=user.badge_number,
            action=f'{action}_evidence',
            action_category='evidence',
            resource_type='evidence',
            resource_id=evidence.id,
            resource_identifier=f"{case_number} - {evidence.evidence_type}",
            details={'case_number': case_number},
            ip_address=ip_address
        )

    @staticmethod
    def log_export(user, export_type, resource_type, resource_id, case_number=None, ip_address=None):
        """
        Log data export

        Args:
            user: User object
            export_type (str): Type of export (pdf, csv, json, etc.)
            resource_type (str): Type of resource
            resource_id (str): ID of resource
            case_number (str): Case number if applicable
            ip_address (str): IP address
        """
        return AuditLog.log_action(
            user_id=user.id,
            username=user.username,
            badge_number=user.badge_number,
            action=f'export_{export_type}',
            action_category='export',
            resource_type=resource_type,
            resource_id=resource_id,
            resource_identifier=case_number,
            details={'export_type': export_type},
            ip_address=ip_address
        )

    def to_dict(self):
        """
        Convert audit log to dictionary

        Returns:
            dict: Audit log data
        """
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.username,
            'badge_number': self.badge_number,
            'action': self.action,
            'action_category': self.action_category,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'resource_identifier': self.resource_identifier,
            'details': self.details,
            'status': self.status,
            'error_message': self.error_message,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'request_method': self.request_method,
            'request_path': self.request_path,
            'timestamp': self.timestamp.isoformat()
        }

    @staticmethod
    def get_action_categories():
        """Get list of action categories"""
        return [
            'authentication',
            'case_management',
            'investigation',
            'evidence',
            'user_management',
            'system',
            'export'
        ]

    @staticmethod
    def get_user_activity_summary(user_id, start_date=None, end_date=None):
        """
        Get summary of user activity

        Args:
            user_id (str): User ID
            start_date (datetime): Start date
            end_date (datetime): End date

        Returns:
            dict: Activity summary
        """
        query = AuditLog.query.filter_by(user_id=user_id)

        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)

        logs = query.all()

        summary = {
            'total_actions': len(logs),
            'by_category': {},
            'by_status': {'success': 0, 'failure': 0, 'warning': 0},
            'recent_actions': []
        }

        for log in logs:
            # Count by category
            category = log.action_category
            summary['by_category'][category] = summary['by_category'].get(category, 0) + 1

            # Count by status
            summary['by_status'][log.status] += 1

        # Get 10 most recent actions
        recent = sorted(logs, key=lambda x: x.timestamp, reverse=True)[:10]
        summary['recent_actions'] = [log.to_dict() for log in recent]

        return summary
