"""
ISP Request Models
Zambia Police Service CyberTrace OSINT Platform

Handles ISP/telco data requests, legal authority tracking, and response management
"""

import uuid
from datetime import datetime
from sqlalchemy import JSON
from app import db


class ISPRequest(db.Model):
    """Model for managing ISP and telco data requests"""

    __tablename__ = 'isp_requests'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Foreign Keys
    case_id = db.Column(db.String(36), db.ForeignKey('cases.id'), nullable=False, index=True)
    requested_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)

    # Provider Details
    provider_name = db.Column(db.String(200), nullable=False)
    request_type = db.Column(db.String(50), nullable=False)
    # subscriber_info, call_records, ip_logs, content_preservation, content_disclosure

    # Request Identification
    request_number = db.Column(db.String(50), unique=True, nullable=False)
    target_identifier = db.Column(db.String(255), nullable=False)

    # Legal Authority
    legal_authority = db.Column(db.String(200), nullable=False)
    warrant_number = db.Column(db.String(100), nullable=True)
    warrant_document_path = db.Column(db.String(500), nullable=True)

    # Date Range for Request
    date_range_start = db.Column(db.DateTime, nullable=True)
    date_range_end = db.Column(db.DateTime, nullable=True)

    # Request Details
    description = db.Column(db.Text, nullable=False)

    # Status Tracking
    status = db.Column(db.String(50), nullable=False, default='draft')
    # draft, submitted, acknowledged, fulfilled, rejected, expired

    # SLA and Timeline
    sla_deadline = db.Column(db.Date, nullable=True)
    submitted_at = db.Column(db.DateTime, nullable=True)
    fulfilled_at = db.Column(db.DateTime, nullable=True)

    # Response Details
    response_document_path = db.Column(db.String(500), nullable=True)
    response_hash = db.Column(db.String(64), nullable=True)

    # Additional Data
    notes = db.Column(db.Text, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<ISPRequest {self.request_number}: {self.provider_name}>'

    def to_dict(self):
        """Convert ISP request object to dictionary"""
        return {
            'id': self.id,
            'case_id': self.case_id,
            'requested_by': self.requested_by,
            'provider_name': self.provider_name,
            'request_type': self.request_type,
            'request_number': self.request_number,
            'target_identifier': self.target_identifier,
            'legal_authority': self.legal_authority,
            'warrant_number': self.warrant_number,
            'warrant_document_path': self.warrant_document_path,
            'date_range_start': self.date_range_start.isoformat() if self.date_range_start else None,
            'date_range_end': self.date_range_end.isoformat() if self.date_range_end else None,
            'description': self.description,
            'status': self.status,
            'sla_deadline': self.sla_deadline.isoformat() if self.sla_deadline else None,
            'submitted_at': self.submitted_at.isoformat() if self.submitted_at else None,
            'fulfilled_at': self.fulfilled_at.isoformat() if self.fulfilled_at else None,
            'response_document_path': self.response_document_path,
            'response_hash': self.response_hash,
            'notes': self.notes,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class RequestTemplate(db.Model):
    """Model for ISP request templates"""

    __tablename__ = 'request_templates'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Template Details
    name = db.Column(db.String(200), nullable=False)
    request_type = db.Column(db.String(50), nullable=False)
    template_content = db.Column(db.Text, nullable=False)
    legal_basis = db.Column(db.String(200), nullable=False)
    required_fields = db.Column(JSON, nullable=True)

    # Status
    is_active = db.Column(db.Boolean, default=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<RequestTemplate {self.name} ({self.request_type})>'

    def to_dict(self):
        """Convert request template object to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'request_type': self.request_type,
            'template_content': self.template_content,
            'legal_basis': self.legal_basis,
            'required_fields': self.required_fields,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
