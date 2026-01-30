"""
Correlation Models
Zambia Police Service CyberTrace OSINT Platform

Handles cross-case indicator correlation, matching, and threat actor profiling
"""

import uuid
from datetime import datetime
from sqlalchemy import JSON
from app import db


class CorrelationIndicator(db.Model):
    """Model for storing extracted indicators from investigations"""

    __tablename__ = 'correlation_indicators'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Foreign Keys
    case_id = db.Column(db.String(36), db.ForeignKey('cases.id'), nullable=False, index=True)
    investigation_id = db.Column(db.String(36), db.ForeignKey('investigations.id'), nullable=True)

    # Indicator Details
    indicator_type = db.Column(db.String(50), nullable=False)
    # phone, email, ip, domain, crypto_address, username, account_number
    indicator_value = db.Column(db.String(500), nullable=False)
    source_module = db.Column(db.String(100), nullable=False)
    extracted_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Additional Data
    extra_metadata = db.Column(JSON, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<CorrelationIndicator {self.indicator_type}: {self.indicator_value}>'

    def to_dict(self):
        """Convert correlation indicator object to dictionary"""
        return {
            'id': self.id,
            'case_id': self.case_id,
            'investigation_id': self.investigation_id,
            'indicator_type': self.indicator_type,
            'indicator_value': self.indicator_value,
            'source_module': self.source_module,
            'extracted_at': self.extracted_at.isoformat() if self.extracted_at else None,
            'extra_metadata': self.extra_metadata,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class CorrelationMatch(db.Model):
    """Model for tracking matches between correlation indicators"""

    __tablename__ = 'correlation_matches'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Foreign Keys - Matched Indicators
    indicator_id_a = db.Column(db.String(36), db.ForeignKey('correlation_indicators.id'), nullable=False, index=True)
    indicator_id_b = db.Column(db.String(36), db.ForeignKey('correlation_indicators.id'), nullable=False, index=True)

    # Foreign Keys - Associated Cases
    case_id_a = db.Column(db.String(36), db.ForeignKey('cases.id'), nullable=False)
    case_id_b = db.Column(db.String(36), db.ForeignKey('cases.id'), nullable=False)

    # Match Details
    match_type = db.Column(db.String(50), nullable=False)
    confidence = db.Column(db.Float, nullable=False)

    # Review Status
    reviewed = db.Column(db.Boolean, default=False)
    reviewed_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<CorrelationMatch {self.match_type}: {self.confidence}>'

    def to_dict(self):
        """Convert correlation match object to dictionary"""
        return {
            'id': self.id,
            'indicator_id_a': self.indicator_id_a,
            'indicator_id_b': self.indicator_id_b,
            'case_id_a': self.case_id_a,
            'case_id_b': self.case_id_b,
            'match_type': self.match_type,
            'confidence': self.confidence,
            'reviewed': self.reviewed,
            'reviewed_by': self.reviewed_by,
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None,
            'notes': self.notes,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class ThreatActorProfile(db.Model):
    """Model for tracking threat actor profiles across cases"""

    __tablename__ = 'threat_actor_profiles'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Profile Details
    name = db.Column(db.String(200), nullable=False)
    aliases = db.Column(JSON, nullable=True)
    description = db.Column(db.Text, nullable=True)

    # Associations
    associated_cases = db.Column(JSON, nullable=True)
    associated_indicators = db.Column(JSON, nullable=True)

    # Risk Assessment
    risk_level = db.Column(db.String(20), nullable=False, default='medium')

    # Activity Timeline
    first_seen = db.Column(db.DateTime, nullable=True)
    last_seen = db.Column(db.DateTime, nullable=True)

    # Tactics, Techniques, and Procedures
    ttps = db.Column(JSON, nullable=True)

    # Status
    status = db.Column(db.String(50), nullable=False, default='active')

    # Additional Data
    notes = db.Column(db.Text, nullable=True)

    # Tracking
    created_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<ThreatActorProfile {self.name} ({self.risk_level})>'

    def to_dict(self):
        """Convert threat actor profile object to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'aliases': self.aliases,
            'description': self.description,
            'associated_cases': self.associated_cases,
            'associated_indicators': self.associated_indicators,
            'risk_level': self.risk_level,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'ttps': self.ttps,
            'status': self.status,
            'notes': self.notes,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
