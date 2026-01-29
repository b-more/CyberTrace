"""
Evidence Model
Zambia Police Service CyberTrace OSINT Platform

Handles digital evidence collection and chain of custody
"""

import uuid
import hashlib
import os
from datetime import datetime
from sqlalchemy import JSON
from app import db


class Evidence(db.Model):
    """Evidence model for tracking digital evidence"""

    __tablename__ = 'evidence'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Foreign Keys
    case_id = db.Column(db.String(36), db.ForeignKey('cases.id'), nullable=False, index=True)
    investigation_id = db.Column(db.String(36), db.ForeignKey('investigations.id'), nullable=True)

    # Evidence Details
    evidence_type = db.Column(db.String(100), nullable=False)
    # screenshot, document, log_file, email, social_media_post, etc.

    description = db.Column(db.Text, nullable=False)

    # File Information
    file_path = db.Column(db.String(500), nullable=True)
    file_name = db.Column(db.String(255), nullable=True)
    file_size = db.Column(db.BigInteger, nullable=True)  # Size in bytes
    file_hash = db.Column(db.String(64), nullable=True)  # SHA-256 hash
    mime_type = db.Column(db.String(100), nullable=True)

    # Evidence Metadata
    evidence_metadata = db.Column(JSON, nullable=True)
    # Store additional metadata (EXIF data, document properties, etc.)

    # Collection Information
    collected_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    collection_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    collection_method = db.Column(db.String(100), nullable=True)
    # manual_upload, automated_capture, api_extraction, etc.

    # Chain of Custody
    chain_of_custody = db.Column(JSON, default=list)
    # Array of custody events with timestamps and officers

    # Evidence Status
    status = db.Column(
        db.Enum('collected', 'verified', 'analyzed', 'archived', name='evidence_status'),
        nullable=False,
        default='collected'
    )

    # Legal Admissibility
    is_admissible = db.Column(db.Boolean, default=True)
    inadmissibility_reason = db.Column(db.Text, nullable=True)

    # Tags and Categories
    tags = db.Column(JSON, default=list)
    category = db.Column(db.String(100), nullable=True)

    # Notes
    notes = db.Column(db.Text, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    case = db.relationship('Case', back_populates='evidence')
    investigation = db.relationship('Investigation')
    collector = db.relationship('User', back_populates='evidence_collected',
                                foreign_keys=[collected_by])

    def __repr__(self):
        return f'<Evidence {self.evidence_type}: {self.file_name or self.id}>'

    def calculate_file_hash(self, file_path=None):
        """
        Calculate SHA-256 hash of evidence file

        Args:
            file_path (str): Path to file (uses self.file_path if not provided)

        Returns:
            str: SHA-256 hash of file
        """
        path = file_path or self.file_path

        if not path or not os.path.exists(path):
            return None

        sha256_hash = hashlib.sha256()

        with open(path, 'rb') as f:
            # Read file in chunks for memory efficiency
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        hash_value = sha256_hash.hexdigest()
        self.file_hash = hash_value
        return hash_value

    def verify_integrity(self):
        """
        Verify integrity of evidence file by checking hash

        Returns:
            bool: True if hash matches, False otherwise
        """
        if not self.file_hash or not self.file_path:
            return False

        current_hash = self.calculate_file_hash()
        return current_hash == self.file_hash

    def add_custody_event(self, officer_id, officer_name, action, notes=None):
        """
        Add chain of custody event

        Args:
            officer_id (str): ID of officer handling evidence
            officer_name (str): Name of officer
            action (str): Action performed (collected, transferred, analyzed, etc.)
            notes (str): Additional notes
        """
        if self.chain_of_custody is None:
            self.chain_of_custody = []

        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'officer_id': officer_id,
            'officer_name': officer_name,
            'action': action,
            'notes': notes
        }

        self.chain_of_custody.append(event)
        db.session.commit()

    def get_custody_history(self):
        """
        Get formatted chain of custody history

        Returns:
            list: List of custody events
        """
        return self.chain_of_custody or []

    def mark_inadmissible(self, reason):
        """
        Mark evidence as not admissible in court

        Args:
            reason (str): Reason for inadmissibility
        """
        self.is_admissible = False
        self.inadmissibility_reason = reason
        db.session.commit()

    def add_tag(self, tag):
        """
        Add a tag to evidence

        Args:
            tag (str): Tag to add
        """
        if self.tags is None:
            self.tags = []

        tag_lower = tag.lower().strip()
        if tag_lower not in self.tags:
            self.tags.append(tag_lower)
            db.session.commit()

    def remove_tag(self, tag):
        """
        Remove a tag from evidence

        Args:
            tag (str): Tag to remove
        """
        tag_lower = tag.lower().strip()
        if self.tags and tag_lower in self.tags:
            self.tags.remove(tag_lower)
            db.session.commit()

    def add_note(self, note, officer_name):
        """
        Add note to evidence

        Args:
            note (str): Note to add
            officer_name (str): Name of officer adding note
        """
        timestamp = datetime.utcnow().isoformat()
        new_note = f"[{timestamp}] {officer_name}: {note}"

        if self.notes:
            self.notes += f"\n{new_note}"
        else:
            self.notes = new_note

        db.session.commit()

    def get_file_size_human(self):
        """
        Get human-readable file size

        Returns:
            str: File size in human-readable format
        """
        if not self.file_size:
            return "Unknown"

        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if self.file_size < 1024.0:
                return f"{self.file_size:.2f} {unit}"
            self.file_size /= 1024.0

        return f"{self.file_size:.2f} PB"

    def to_dict(self, include_relationships=False):
        """
        Convert evidence object to dictionary

        Args:
            include_relationships (bool): Include related data

        Returns:
            dict: Evidence data
        """
        data = {
            'id': self.id,
            'case_id': self.case_id,
            'investigation_id': self.investigation_id,
            'evidence_type': self.evidence_type,
            'description': self.description,
            'file_name': self.file_name,
            'file_size': self.file_size,
            'file_size_human': self.get_file_size_human(),
            'file_hash': self.file_hash,
            'mime_type': self.mime_type,
            'collected_by': self.collected_by,
            'collection_date': self.collection_date.isoformat(),
            'collection_method': self.collection_method,
            'status': self.status,
            'is_admissible': self.is_admissible,
            'inadmissibility_reason': self.inadmissibility_reason,
            'tags': self.tags or [],
            'category': self.category,
            'custody_events_count': len(self.chain_of_custody or []),
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

        if include_relationships:
            data['collector'] = self.collector.to_dict()
            data['chain_of_custody'] = self.get_custody_history()
            data['evidence_metadata'] = self.evidence_metadata

        return data

    @staticmethod
    def get_evidence_types():
        """Get list of common evidence types"""
        return [
            'screenshot',
            'document',
            'log_file',
            'email',
            'social_media_post',
            'chat_transcript',
            'photo',
            'video',
            'audio',
            'database_export',
            'network_capture',
            'disk_image',
            'memory_dump',
            'other'
        ]

    @property
    def age_days(self):
        """
        Calculate age of evidence in days

        Returns:
            int: Days since collection
        """
        return (datetime.utcnow() - self.collection_date).days

    @property
    def custody_count(self):
        """
        Get count of custody events

        Returns:
            int: Number of custody events
        """
        return len(self.chain_of_custody or [])
