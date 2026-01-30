"""
Investigation Model
Zambia Police Service CyberTrace OSINT Platform

Handles OSINT investigation records and results
"""

import uuid
import hashlib
import json
from datetime import datetime
from sqlalchemy import JSON
from app import db


class Investigation(db.Model):
    """Investigation model for storing OSINT search results"""

    __tablename__ = 'investigations'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Foreign Keys
    case_id = db.Column(db.String(36), db.ForeignKey('cases.id'), nullable=False, index=True)
    investigator_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)

    # Investigation Details
    investigation_type = db.Column(
        db.String(50),
        nullable=False,
        index=True
    )  # email, phone, social_media, domain, ip, crypto, etc.

    target_identifier = db.Column(db.String(255), nullable=False, index=True)
    # The email, phone, username, domain, IP, or crypto address being investigated

    tool_used = db.Column(db.String(100), nullable=True)
    # Specific tool used (holehe, sherlock, phoneinfoga, etc.)

    # Results
    raw_results = db.Column(JSON, nullable=True)
    # Raw results from OSINT tools

    processed_results = db.Column(JSON, nullable=True)
    # Processed and formatted results

    status = db.Column(
        db.Enum('pending', 'completed', 'failed', name='investigation_status'),
        nullable=False,
        default='pending'
    )

    error_message = db.Column(db.Text, nullable=True)
    # Error message if investigation failed

    # Evidence Integrity
    evidence_hash = db.Column(db.String(64), nullable=True)
    # SHA-256 hash of results for integrity verification

    # Additional Information
    notes = db.Column(db.Text, nullable=True)
    confidence_score = db.Column(db.Float, nullable=True)
    # Confidence score for results (0.0 to 1.0)

    # Execution Details
    execution_time = db.Column(db.Float, nullable=True)
    # Time taken to complete investigation in seconds

    api_calls_made = db.Column(db.Integer, default=0)
    # Number of API calls made during investigation

    # Timestamps
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    case = db.relationship('Case', back_populates='investigations')
    investigator = db.relationship('User', back_populates='investigations')

    def __repr__(self):
        return f'<Investigation {self.investigation_type}: {self.target_identifier}>'

    def generate_evidence_hash(self):
        """Generate SHA-256 hash of investigation results for integrity"""
        if self.processed_results:
            # Convert results to JSON string and hash
            results_str = json.dumps(self.processed_results, sort_keys=True)
            hash_obj = hashlib.sha256(results_str.encode('utf-8'))
            self.evidence_hash = hash_obj.hexdigest()
            return self.evidence_hash
        return None

    def verify_integrity(self):
        """
        Verify integrity of investigation results

        Returns:
            bool: True if hash matches, False otherwise
        """
        if not self.evidence_hash or not self.processed_results:
            return False

        results_str = json.dumps(self.processed_results, sort_keys=True)
        hash_obj = hashlib.sha256(results_str.encode('utf-8'))
        calculated_hash = hash_obj.hexdigest()

        return calculated_hash == self.evidence_hash

    def mark_completed(self, results, execution_time=None):
        """
        Mark investigation as completed

        Args:
            results (dict): Investigation results
            execution_time (float): Time taken in seconds
        """
        self.status = 'completed'
        self.processed_results = results
        self.completed_at = datetime.utcnow()

        if execution_time:
            self.execution_time = execution_time

        # Generate evidence hash
        self.generate_evidence_hash()

        db.session.commit()

    def mark_failed(self, error_message):
        """
        Mark investigation as failed

        Args:
            error_message (str): Error message
        """
        self.status = 'failed'
        self.error_message = error_message
        self.completed_at = datetime.utcnow()
        db.session.commit()

    def add_note(self, note):
        """
        Add or append note to investigation

        Args:
            note (str): Note to add
        """
        timestamp = datetime.utcnow().isoformat()
        new_note = f"[{timestamp}] {note}"

        if self.notes:
            self.notes += f"\n{new_note}"
        else:
            self.notes = new_note

        db.session.commit()

    def get_findings_count(self):
        """
        Get count of findings from investigation results

        Returns:
            int: Number of findings
        """
        if not self.processed_results:
            return 0

        # Count varies by investigation type
        if self.investigation_type == 'email':
            return len(self.processed_results.get('registered_on', []))
        elif self.investigation_type == 'social_media':
            return len(self.processed_results.get('found_on', []))
        elif self.investigation_type == 'phone':
            return 1 if self.processed_results.get('valid') else 0
        elif self.investigation_type == 'domain':
            subdomains = len(self.processed_results.get('subdomains', []))
            emails = len(self.processed_results.get('emails', []))
            return subdomains + emails
        else:
            return 1 if self.processed_results else 0

    def get_key_findings(self):
        """
        Extract key findings from results

        Returns:
            list: List of key finding strings
        """
        findings = []

        if not self.processed_results:
            return findings

        if self.investigation_type == 'email':
            registered = self.processed_results.get('registered_on', [])
            if registered:
                findings.append(f"Email found on {len(registered)} platforms")

            breaches = self.processed_results.get('breaches', [])
            if breaches:
                findings.append(f"Found in {len(breaches)} data breaches")

        elif self.investigation_type == 'phone':
            if self.processed_results.get('valid'):
                carrier = self.processed_results.get('carrier', 'Unknown')
                findings.append(f"Valid phone number - Carrier: {carrier}")

            online = self.processed_results.get('online_presence', {})
            platforms = [k for k, v in online.items() if v]
            if platforms:
                findings.append(f"Online presence: {', '.join(platforms)}")

        elif self.investigation_type == 'social_media':
            found_on = self.processed_results.get('found_on', [])
            if found_on:
                platforms = [item['platform'] for item in found_on if item.get('exists')]
                findings.append(f"Username found on: {', '.join(platforms)}")

        elif self.investigation_type == 'domain':
            subdomains = self.processed_results.get('subdomains', [])
            if subdomains:
                findings.append(f"Found {len(subdomains)} subdomains")

            emails = self.processed_results.get('emails', [])
            if emails:
                findings.append(f"Found {len(emails)} email addresses")

        elif self.investigation_type == 'crypto':
            balance = self.processed_results.get('balance')
            if balance:
                findings.append(f"Balance: {balance}")

            tx_count = self.processed_results.get('transaction_count')
            if tx_count:
                findings.append(f"{tx_count} transactions")

        elif self.investigation_type == 'financial':
            tx_count = self.processed_results.get('transaction_count', 0)
            if tx_count:
                findings.append(f"{tx_count} transactions analyzed")
            mule_count = self.processed_results.get('mule_accounts_detected', 0)
            if mule_count:
                findings.append(f"{mule_count} suspected mule accounts")
            total = self.processed_results.get('total_amount_traced')
            if total:
                findings.append(f"Total traced: ZMW {total:,.2f}")

        elif self.investigation_type == 'sim_swap':
            swap_count = self.processed_results.get('swap_count', 0)
            if swap_count:
                findings.append(f"{swap_count} SIM swap events detected")
            risk = self.processed_results.get('risk_level')
            if risk:
                findings.append(f"Risk level: {risk}")

        elif self.investigation_type == 'messaging':
            msg_count = self.processed_results.get('message_count', 0)
            if msg_count:
                findings.append(f"{msg_count} messages analyzed")
            links = self.processed_results.get('extracted_links', [])
            if links:
                findings.append(f"{len(links)} URLs extracted")
            phones = self.processed_results.get('extracted_phones', [])
            if phones:
                findings.append(f"{len(phones)} phone numbers extracted")

        elif self.investigation_type in ('image_forensics', 'document_forensics'):
            if self.processed_results.get('manipulation_detected'):
                findings.append("Potential manipulation detected")
            if self.processed_results.get('gps_coordinates'):
                findings.append("GPS coordinates found")
            device = self.processed_results.get('device_info')
            if device:
                findings.append(f"Device: {device}")

        elif self.investigation_type == 'social_preservation':
            platform = self.processed_results.get('platform')
            if platform:
                findings.append(f"Content preserved from {platform}")
            flags = self.processed_results.get('content_flags', [])
            if flags:
                findings.append(f"{len(flags)} content flags raised")

        return findings

    def to_dict(self, include_relationships=False):
        """
        Convert investigation object to dictionary

        Args:
            include_relationships (bool): Include related data

        Returns:
            dict: Investigation data
        """
        data = {
            'id': self.id,
            'case_id': self.case_id,
            'investigator_id': self.investigator_id,
            'investigation_type': self.investigation_type,
            'target_identifier': self.target_identifier,
            'tool_used': self.tool_used,
            'status': self.status,
            'error_message': self.error_message,
            'evidence_hash': self.evidence_hash,
            'notes': self.notes,
            'confidence_score': self.confidence_score,
            'execution_time': self.execution_time,
            'api_calls_made': self.api_calls_made,
            'timestamp': self.timestamp.isoformat(),
            'created_at': self.created_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'findings_count': self.get_findings_count(),
            'key_findings': self.get_key_findings()
        }

        if include_relationships:
            data['investigator'] = self.investigator.to_dict()
            data['processed_results'] = self.processed_results

        return data

    @staticmethod
    def get_investigation_types():
        """Get list of all investigation types"""
        return [
            'email',
            'phone',
            'social_media',
            'domain',
            'ip',
            'breach',
            'crypto',
            'metadata',
            'geolocation',
            'financial',
            'sim_swap',
            'messaging',
            'image_forensics',
            'document_forensics',
            'social_preservation',
            'correlation'
        ]

    @property
    def is_successful(self):
        """Check if investigation completed successfully"""
        return self.status == 'completed' and self.processed_results is not None

    @property
    def duration(self):
        """
        Calculate duration of investigation

        Returns:
            int: Duration in seconds, or None if not completed
        """
        if self.completed_at:
            return int((self.completed_at - self.created_at).total_seconds())
        return None
