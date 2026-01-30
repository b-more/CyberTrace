"""
SIM Swap Event Model
Zambia Police Service CyberTrace OSINT Platform

Handles SIM swap detection and tracking for fraud investigations
"""

import uuid
from datetime import datetime
from sqlalchemy import JSON
from app import db


class SimSwapEvent(db.Model):
    """Model for tracking SIM swap events linked to investigations"""

    __tablename__ = 'sim_swap_events'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Foreign Keys
    case_id = db.Column(db.String(36), db.ForeignKey('cases.id'), nullable=False, index=True)
    investigation_id = db.Column(db.String(36), db.ForeignKey('investigations.id'), nullable=True)

    # SIM Swap Details
    phone_number = db.Column(db.String(50), nullable=False, index=True)
    carrier = db.Column(db.String(100), nullable=False)

    # SIM Identifiers
    old_iccid = db.Column(db.String(50), nullable=True)
    new_iccid = db.Column(db.String(50), nullable=True)
    old_imsi = db.Column(db.String(50), nullable=True)
    new_imsi = db.Column(db.String(50), nullable=True)

    # Event Details
    swap_date = db.Column(db.DateTime, nullable=False)
    swap_type = db.Column(db.String(50), nullable=False, default='suspicious')

    # Analysis
    associated_compromises = db.Column(JSON, nullable=True)
    detection_method = db.Column(db.String(100), nullable=True)
    carrier_data = db.Column(JSON, nullable=True)
    correlation_score = db.Column(db.Float, nullable=True)

    # Additional Data
    notes = db.Column(db.Text, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<SimSwapEvent {self.phone_number} ({self.carrier})>'

    def to_dict(self):
        """Convert SIM swap event object to dictionary"""
        return {
            'id': self.id,
            'case_id': self.case_id,
            'investigation_id': self.investigation_id,
            'phone_number': self.phone_number,
            'carrier': self.carrier,
            'old_iccid': self.old_iccid,
            'new_iccid': self.new_iccid,
            'old_imsi': self.old_imsi,
            'new_imsi': self.new_imsi,
            'swap_date': self.swap_date.isoformat() if self.swap_date else None,
            'swap_type': self.swap_type,
            'associated_compromises': self.associated_compromises,
            'detection_method': self.detection_method,
            'carrier_data': self.carrier_data,
            'correlation_score': self.correlation_score,
            'notes': self.notes,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
