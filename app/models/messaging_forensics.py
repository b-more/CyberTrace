"""
Messaging Forensics Models
Zambia Police Service CyberTrace OSINT Platform

Handles chat export analysis, message parsing, and contact extraction
"""

import uuid
from datetime import datetime
from sqlalchemy import JSON
from app import db


class MessagingExport(db.Model):
    """Model for managing imported messaging platform exports"""

    __tablename__ = 'messaging_exports'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Foreign Keys
    case_id = db.Column(db.String(36), db.ForeignKey('cases.id'), nullable=False, index=True)
    investigation_id = db.Column(db.String(36), db.ForeignKey('investigations.id'), nullable=True)

    # Export Details
    platform = db.Column(db.String(50), nullable=False)
    # whatsapp, telegram, signal
    filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    chat_type = db.Column(db.String(20), nullable=False)
    # individual, group
    participant_count = db.Column(db.Integer, nullable=False)
    message_count = db.Column(db.Integer, nullable=False, default=0)

    # Date Range
    date_range_start = db.Column(db.DateTime, nullable=True)
    date_range_end = db.Column(db.DateTime, nullable=True)

    # Extracted Data
    extracted_links = db.Column(JSON, nullable=True)
    extracted_phones = db.Column(JSON, nullable=True)
    extracted_data = db.Column(JSON, nullable=True)

    # Upload Information
    uploaded_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<MessagingExport {self.platform}: {self.filename}>'

    def to_dict(self):
        """Convert messaging export object to dictionary"""
        return {
            'id': self.id,
            'case_id': self.case_id,
            'investigation_id': self.investigation_id,
            'platform': self.platform,
            'filename': self.filename,
            'file_hash': self.file_hash,
            'chat_type': self.chat_type,
            'participant_count': self.participant_count,
            'message_count': self.message_count,
            'date_range_start': self.date_range_start.isoformat() if self.date_range_start else None,
            'date_range_end': self.date_range_end.isoformat() if self.date_range_end else None,
            'extracted_links': self.extracted_links,
            'extracted_phones': self.extracted_phones,
            'extracted_data': self.extracted_data,
            'uploaded_by': self.uploaded_by,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class ChatMessage(db.Model):
    """Model for individual parsed chat messages"""

    __tablename__ = 'chat_messages'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Foreign Keys
    export_id = db.Column(db.String(36), db.ForeignKey('messaging_exports.id'), nullable=False, index=True)

    # Message Details
    sender = db.Column(db.String(200), nullable=False)
    message_text = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False)

    # Media
    has_media = db.Column(db.Boolean, default=False)
    media_type = db.Column(db.String(50), nullable=True)

    # Flagging
    is_flagged = db.Column(db.Boolean, default=False)
    flag_reason = db.Column(db.String(200), nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<ChatMessage {self.sender}: {self.timestamp}>'

    def to_dict(self):
        """Convert chat message object to dictionary"""
        return {
            'id': self.id,
            'export_id': self.export_id,
            'sender': self.sender,
            'message_text': self.message_text,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'has_media': self.has_media,
            'media_type': self.media_type,
            'is_flagged': self.is_flagged,
            'flag_reason': self.flag_reason,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class MessagingContact(db.Model):
    """Model for contacts extracted from messaging exports"""

    __tablename__ = 'messaging_contacts'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Foreign Keys
    export_id = db.Column(db.String(36), db.ForeignKey('messaging_exports.id'), nullable=False, index=True)

    # Contact Details
    phone_number = db.Column(db.String(50), nullable=False)
    display_name = db.Column(db.String(200), nullable=False)
    message_count = db.Column(db.Integer, default=0)

    # Activity Range
    first_message = db.Column(db.DateTime, nullable=True)
    last_message = db.Column(db.DateTime, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<MessagingContact {self.display_name} ({self.phone_number})>'

    def to_dict(self):
        """Convert messaging contact object to dictionary"""
        return {
            'id': self.id,
            'export_id': self.export_id,
            'phone_number': self.phone_number,
            'display_name': self.display_name,
            'message_count': self.message_count,
            'first_message': self.first_message.isoformat() if self.first_message else None,
            'last_message': self.last_message.isoformat() if self.last_message else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
