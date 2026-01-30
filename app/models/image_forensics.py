"""
Image and Document Forensics Models
Zambia Police Service CyberTrace OSINT Platform

Handles forensic analysis of images and documents including EXIF, ELA, and metadata extraction
"""

import uuid
from datetime import datetime
from sqlalchemy import JSON
from app import db


class ForensicImage(db.Model):
    """Model for forensic image analysis and metadata extraction"""

    __tablename__ = 'forensic_images'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Foreign Keys
    case_id = db.Column(db.String(36), db.ForeignKey('cases.id'), nullable=False, index=True)
    investigation_id = db.Column(db.String(36), db.ForeignKey('investigations.id'), nullable=True)

    # File Information
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)

    # EXIF and GPS Data
    exif_data = db.Column(JSON, nullable=True)
    gps_latitude = db.Column(db.Float, nullable=True)
    gps_longitude = db.Column(db.Float, nullable=True)
    gps_location_name = db.Column(db.String(500), nullable=True)

    # Device Information
    device_make = db.Column(db.String(200), nullable=True)
    device_model = db.Column(db.String(200), nullable=True)
    capture_date = db.Column(db.DateTime, nullable=True)

    # Manipulation Analysis
    modification_history = db.Column(JSON, nullable=True)
    ela_result = db.Column(JSON, nullable=True)
    manipulation_detected = db.Column(db.Boolean, nullable=True)
    manipulation_confidence = db.Column(db.Float, nullable=True)

    # OCR and Reverse Search
    ocr_text = db.Column(db.Text, nullable=True)
    reverse_search_results = db.Column(JSON, nullable=True)

    # Risk Assessment
    risk_score = db.Column(db.Integer, default=0)

    # Analysis Tracking
    analyzed_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<ForensicImage {self.original_filename}>'

    def to_dict(self):
        """Convert forensic image object to dictionary"""
        return {
            'id': self.id,
            'case_id': self.case_id,
            'investigation_id': self.investigation_id,
            'original_filename': self.original_filename,
            'stored_filename': self.stored_filename,
            'file_hash': self.file_hash,
            'file_size': self.file_size,
            'mime_type': self.mime_type,
            'exif_data': self.exif_data,
            'gps_latitude': self.gps_latitude,
            'gps_longitude': self.gps_longitude,
            'gps_location_name': self.gps_location_name,
            'device_make': self.device_make,
            'device_model': self.device_model,
            'capture_date': self.capture_date.isoformat() if self.capture_date else None,
            'modification_history': self.modification_history,
            'ela_result': self.ela_result,
            'manipulation_detected': self.manipulation_detected,
            'manipulation_confidence': self.manipulation_confidence,
            'ocr_text': self.ocr_text,
            'reverse_search_results': self.reverse_search_results,
            'risk_score': self.risk_score,
            'analyzed_by': self.analyzed_by,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class ForensicDocument(db.Model):
    """Model for forensic document analysis and metadata extraction"""

    __tablename__ = 'forensic_documents'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Foreign Keys
    case_id = db.Column(db.String(36), db.ForeignKey('cases.id'), nullable=False, index=True)
    investigation_id = db.Column(db.String(36), db.ForeignKey('investigations.id'), nullable=True)

    # File Information
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)

    # Document Metadata
    doc_metadata = db.Column(JSON, nullable=True)
    author = db.Column(db.String(200), nullable=True)
    creator_tool = db.Column(db.String(200), nullable=True)
    creation_date = db.Column(db.DateTime, nullable=True)
    modification_date = db.Column(db.DateTime, nullable=True)
    page_count = db.Column(db.Integer, nullable=True)

    # Content Extraction
    extracted_text = db.Column(db.Text, nullable=True)
    embedded_objects = db.Column(JSON, nullable=True)

    # Risk Assessment
    risk_score = db.Column(db.Integer, default=0)

    # Analysis Tracking
    analyzed_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<ForensicDocument {self.original_filename}>'

    def to_dict(self):
        """Convert forensic document object to dictionary"""
        return {
            'id': self.id,
            'case_id': self.case_id,
            'investigation_id': self.investigation_id,
            'original_filename': self.original_filename,
            'stored_filename': self.stored_filename,
            'file_hash': self.file_hash,
            'file_size': self.file_size,
            'mime_type': self.mime_type,
            'doc_metadata': self.doc_metadata,
            'author': self.author,
            'creator_tool': self.creator_tool,
            'creation_date': self.creation_date.isoformat() if self.creation_date else None,
            'modification_date': self.modification_date.isoformat() if self.modification_date else None,
            'page_count': self.page_count,
            'extracted_text': self.extracted_text,
            'embedded_objects': self.embedded_objects,
            'risk_score': self.risk_score,
            'analyzed_by': self.analyzed_by,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
