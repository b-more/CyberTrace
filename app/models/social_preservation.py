"""
Social Media Preservation Models
Zambia Police Service CyberTrace OSINT Platform

Handles preservation and flagging of social media content for legal proceedings
"""

import uuid
from datetime import datetime
from sqlalchemy import JSON
from app import db


class PreservedContent(db.Model):
    """Model for preserved social media content captures"""

    __tablename__ = 'preserved_content'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Foreign Keys
    case_id = db.Column(db.String(36), db.ForeignKey('cases.id'), nullable=False, index=True)

    # Content Source
    url = db.Column(db.String(2000), nullable=False)
    platform = db.Column(db.String(50), nullable=False)
    capture_type = db.Column(db.String(50), nullable=False)
    # profile, post, page, group, comment

    # Capture Details
    captured_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Screenshot Preservation
    screenshot_path = db.Column(db.String(500), nullable=True)
    screenshot_hash = db.Column(db.String(64), nullable=True)

    # HTML Preservation
    html_content = db.Column(db.Text, nullable=True)
    html_hash = db.Column(db.String(64), nullable=True)

    # Extracted Content
    extracted_text = db.Column(db.Text, nullable=True)
    author_info = db.Column(JSON, nullable=True)
    engagement_data = db.Column(JSON, nullable=True)
    content_flags = db.Column(JSON, nullable=True)

    # Archive Reference
    wayback_url = db.Column(db.String(500), nullable=True)
    is_available = db.Column(db.Boolean, default=True)

    # Capture Tracking
    captured_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<PreservedContent {self.platform}: {self.url[:50]}>'

    def to_dict(self):
        """Convert preserved content object to dictionary"""
        return {
            'id': self.id,
            'case_id': self.case_id,
            'url': self.url,
            'platform': self.platform,
            'capture_type': self.capture_type,
            'captured_at': self.captured_at.isoformat() if self.captured_at else None,
            'screenshot_path': self.screenshot_path,
            'screenshot_hash': self.screenshot_hash,
            'html_content': self.html_content,
            'html_hash': self.html_hash,
            'extracted_text': self.extracted_text,
            'author_info': self.author_info,
            'engagement_data': self.engagement_data,
            'content_flags': self.content_flags,
            'wayback_url': self.wayback_url,
            'is_available': self.is_available,
            'captured_by': self.captured_by,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class ContentFlag(db.Model):
    """Model for flagging preserved content with legal classifications"""

    __tablename__ = 'content_flags'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Foreign Keys
    capture_id = db.Column(db.String(36), db.ForeignKey('preserved_content.id'), nullable=False, index=True)

    # Flag Details
    flag_type = db.Column(db.String(50), nullable=False)
    # hate_speech, defamation, harassment, threat, fraud, other
    legal_reference = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)

    # Content
    flagged_content = db.Column(db.Text, nullable=False)
    context = db.Column(db.Text, nullable=True)

    # Flagging Tracking
    flagged_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    flagged_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<ContentFlag {self.flag_type}: {self.severity}>'

    def to_dict(self):
        """Convert content flag object to dictionary"""
        return {
            'id': self.id,
            'capture_id': self.capture_id,
            'flag_type': self.flag_type,
            'legal_reference': self.legal_reference,
            'severity': self.severity,
            'flagged_content': self.flagged_content,
            'context': self.context,
            'flagged_by': self.flagged_by,
            'flagged_at': self.flagged_at.isoformat() if self.flagged_at else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
