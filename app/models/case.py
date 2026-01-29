"""
Case Model
Zambia Police Service CyberTrace OSINT Platform

Handles criminal case management and tracking
"""

import uuid
from datetime import datetime
from sqlalchemy import JSON
from app import db


class Case(db.Model):
    """Case model for managing investigations"""

    __tablename__ = 'cases'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Case Identification
    case_number = db.Column(db.String(50), unique=True, nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)

    # Case Classification
    case_type = db.Column(
        db.Enum('fraud', 'cybercrime', 'identity_theft', 'financial_crime', 'other',
                name='case_types'),
        nullable=False,
        default='cybercrime'
    )

    priority = db.Column(
        db.Enum('low', 'medium', 'high', 'critical', name='priority_levels'),
        nullable=False,
        default='medium'
    )

    status = db.Column(
        db.Enum('open', 'investigating', 'pending', 'closed', 'archived', name='case_status'),
        nullable=False,
        default='open'
    )

    # Personnel Assignment
    lead_investigator_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    assigned_officers = db.Column(JSON, default=list)  # Array of user IDs

    # Legal Information
    warrant_number = db.Column(db.String(100), nullable=True)
    warrant_date = db.Column(db.Date, nullable=True)
    warrant_document_path = db.Column(db.String(500), nullable=True)

    # Important Dates
    opened_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    closed_date = db.Column(db.DateTime, nullable=True)

    # Additional Information
    notes = db.Column(db.Text, nullable=True)
    tags = db.Column(JSON, default=list)  # Array of tags for searching

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    lead_investigator = db.relationship('User', back_populates='cases_lead',
                                       foreign_keys=[lead_investigator_id])
    investigations = db.relationship('Investigation', back_populates='case',
                                    lazy='dynamic', cascade='all, delete-orphan')
    evidence = db.relationship('Evidence', back_populates='case',
                              lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Case {self.case_number}: {self.title}>'

    @staticmethod
    def generate_case_number(prefix='ZPS', year=None):
        """
        Generate unique case number

        Args:
            prefix (str): Case number prefix (default: ZPS)
            year (int): Year for case number (default: current year)

        Returns:
            str: Generated case number (e.g., ZPS-2025-0001)
        """
        if year is None:
            year = datetime.now().year

        # Find the highest case number for the current year
        last_case = Case.query.filter(
            Case.case_number.like(f'{prefix}-{year}-%')
        ).order_by(Case.case_number.desc()).first()

        if last_case:
            # Extract number from last case and increment
            last_number = int(last_case.case_number.split('-')[-1])
            new_number = last_number + 1
        else:
            new_number = 1

        return f'{prefix}-{year}-{new_number:04d}'

    def assign_officer(self, user_id):
        """
        Assign an officer to this case

        Args:
            user_id (str): User ID to assign
        """
        if self.assigned_officers is None:
            self.assigned_officers = []

        if user_id not in self.assigned_officers:
            self.assigned_officers.append(user_id)
            db.session.commit()

    def unassign_officer(self, user_id):
        """
        Remove an officer from this case

        Args:
            user_id (str): User ID to remove
        """
        if self.assigned_officers and user_id in self.assigned_officers:
            self.assigned_officers.remove(user_id)
            db.session.commit()

    def is_officer_assigned(self, user_id):
        """
        Check if officer is assigned to case

        Args:
            user_id (str): User ID to check

        Returns:
            bool: True if officer is assigned
        """
        return user_id in (self.assigned_officers or [])

    def close_case(self):
        """Mark case as closed"""
        self.status = 'closed'
        self.closed_date = datetime.utcnow()
        db.session.commit()

    def reopen_case(self):
        """Reopen a closed case"""
        self.status = 'investigating'
        self.closed_date = None
        db.session.commit()

    def archive_case(self):
        """Archive a case"""
        self.status = 'archived'
        db.session.commit()

    def add_tag(self, tag):
        """
        Add a tag to the case

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
        Remove a tag from the case

        Args:
            tag (str): Tag to remove
        """
        tag_lower = tag.lower().strip()
        if self.tags and tag_lower in self.tags:
            self.tags.remove(tag_lower)
            db.session.commit()

    def get_investigation_count(self):
        """Get total number of investigations for this case"""
        return self.investigations.count()

    def get_evidence_count(self):
        """Get total number of evidence items for this case"""
        return self.evidence.count()

    def get_timeline(self):
        """
        Get case timeline with all activities

        Returns:
            list: Timeline entries sorted by date
        """
        timeline = []

        # Add case creation
        timeline.append({
            'date': self.created_at,
            'type': 'case_created',
            'description': f'Case {self.case_number} opened'
        })

        # Add investigations
        for investigation in self.investigations:
            timeline.append({
                'date': investigation.created_at,
                'type': 'investigation',
                'description': f'{investigation.investigation_type} investigation conducted',
                'investigation_id': investigation.id
            })

        # Add evidence
        for evidence in self.evidence:
            timeline.append({
                'date': evidence.created_at,
                'type': 'evidence',
                'description': f'Evidence collected: {evidence.evidence_type}',
                'evidence_id': evidence.id
            })

        # Add case closure if closed
        if self.closed_date:
            timeline.append({
                'date': self.closed_date,
                'type': 'case_closed',
                'description': f'Case {self.case_number} closed'
            })

        # Sort by date
        timeline.sort(key=lambda x: x['date'], reverse=True)
        return timeline

    def to_dict(self, include_relationships=False):
        """
        Convert case object to dictionary

        Args:
            include_relationships (bool): Include related data

        Returns:
            dict: Case data
        """
        data = {
            'id': self.id,
            'case_number': self.case_number,
            'title': self.title,
            'description': self.description,
            'case_type': self.case_type,
            'priority': self.priority,
            'status': self.status,
            'lead_investigator_id': self.lead_investigator_id,
            'assigned_officers': self.assigned_officers or [],
            'warrant_number': self.warrant_number,
            'warrant_date': self.warrant_date.isoformat() if self.warrant_date else None,
            'opened_date': self.opened_date.isoformat(),
            'closed_date': self.closed_date.isoformat() if self.closed_date else None,
            'tags': self.tags or [],
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

        if include_relationships:
            data['lead_investigator'] = self.lead_investigator.to_dict()
            data['investigation_count'] = self.get_investigation_count()
            data['evidence_count'] = self.get_evidence_count()

        return data

    @property
    def days_open(self):
        """Calculate number of days case has been open"""
        end_date = self.closed_date if self.closed_date else datetime.utcnow()
        return (end_date - self.opened_date).days

    @property
    def is_overdue(self):
        """Check if case is overdue (open for more than 90 days)"""
        return self.status in ['open', 'investigating'] and self.days_open > 90
