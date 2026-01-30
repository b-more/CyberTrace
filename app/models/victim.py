"""
Victim Models
Zambia Police Service CyberTrace OSINT Platform

Handles victim information, statements, and notification management
"""

import uuid
from datetime import datetime
from sqlalchemy import JSON
from app import db


class Victim(db.Model):
    """Model for tracking victims linked to cases"""

    __tablename__ = 'victims'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Foreign Keys
    case_id = db.Column(db.String(36), db.ForeignKey('cases.id'), nullable=False, index=True)

    # Victim Type
    victim_type = db.Column(db.String(20), nullable=False, default='individual')
    # individual, business

    # Personal Information
    full_name = db.Column(db.String(200), nullable=False)
    id_number = db.Column(db.String(50), nullable=True)  # NRC
    phone_number = db.Column(db.String(50), nullable=True)
    email = db.Column(db.String(200), nullable=True)
    address = db.Column(db.Text, nullable=True)
    province = db.Column(db.String(100), nullable=True)
    district = db.Column(db.String(100), nullable=True)
    occupation = db.Column(db.String(200), nullable=True)

    # Loss Information
    loss_amount = db.Column(db.Float, default=0)
    loss_currency = db.Column(db.String(3), nullable=False, default='ZMW')
    loss_type = db.Column(db.String(50), nullable=True)
    # cash, mobile_money, bank_transfer, crypto
    loss_description = db.Column(db.Text, nullable=True)
    date_of_incident = db.Column(db.Date, nullable=True)

    # Statement Status
    statement_status = db.Column(db.String(50), nullable=False, default='pending')
    # pending, recorded, verified

    # Communication Preferences
    wants_updates = db.Column(db.Boolean, default=True)

    # Additional Data
    notes = db.Column(db.Text, nullable=True)

    # Tracking
    created_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Victim {self.full_name} ({self.victim_type})>'

    def to_dict(self):
        """Convert victim object to dictionary"""
        return {
            'id': self.id,
            'case_id': self.case_id,
            'victim_type': self.victim_type,
            'full_name': self.full_name,
            'id_number': self.id_number,
            'phone_number': self.phone_number,
            'email': self.email,
            'address': self.address,
            'province': self.province,
            'district': self.district,
            'occupation': self.occupation,
            'loss_amount': self.loss_amount,
            'loss_currency': self.loss_currency,
            'loss_type': self.loss_type,
            'loss_description': self.loss_description,
            'date_of_incident': self.date_of_incident.isoformat() if self.date_of_incident else None,
            'statement_status': self.statement_status,
            'wants_updates': self.wants_updates,
            'notes': self.notes,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class VictimStatement(db.Model):
    """Model for victim statements and recordings"""

    __tablename__ = 'victim_statements'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Foreign Keys
    victim_id = db.Column(db.String(36), db.ForeignKey('victims.id'), nullable=False, index=True)
    case_id = db.Column(db.String(36), db.ForeignKey('cases.id'), nullable=False, index=True)
    recorded_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)

    # Statement Content
    statement_text = db.Column(db.Text, nullable=False)
    statement_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Format and File
    format = db.Column(db.String(20), nullable=False, default='written')
    # written, audio, video
    file_path = db.Column(db.String(500), nullable=True)
    file_hash = db.Column(db.String(64), nullable=True)

    # Verification
    is_verified = db.Column(db.Boolean, default=False)
    verified_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True)
    verified_at = db.Column(db.DateTime, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<VictimStatement {self.victim_id}: {self.statement_date}>'

    def to_dict(self):
        """Convert victim statement object to dictionary"""
        return {
            'id': self.id,
            'victim_id': self.victim_id,
            'case_id': self.case_id,
            'recorded_by': self.recorded_by,
            'statement_text': self.statement_text,
            'statement_date': self.statement_date.isoformat() if self.statement_date else None,
            'format': self.format,
            'file_path': self.file_path,
            'file_hash': self.file_hash,
            'is_verified': self.is_verified,
            'verified_by': self.verified_by,
            'verified_at': self.verified_at.isoformat() if self.verified_at else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class VictimNotification(db.Model):
    """Model for tracking notifications sent to victims"""

    __tablename__ = 'victim_notifications'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Foreign Keys
    victim_id = db.Column(db.String(36), db.ForeignKey('victims.id'), nullable=False, index=True)

    # Notification Details
    notification_type = db.Column(db.String(50), nullable=False)
    # case_update, arrest, court_date, closure
    message = db.Column(db.Text, nullable=False)

    # Delivery
    sent_via = db.Column(db.String(20), nullable=False)
    # sms, email, phone_call
    sent_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    sent_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<VictimNotification {self.notification_type}: {self.sent_via}>'

    def to_dict(self):
        """Convert victim notification object to dictionary"""
        return {
            'id': self.id,
            'victim_id': self.victim_id,
            'notification_type': self.notification_type,
            'message': self.message,
            'sent_via': self.sent_via,
            'sent_at': self.sent_at.isoformat() if self.sent_at else None,
            'sent_by': self.sent_by,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
