"""
Threat Intelligence Model
Zambia Police Service CyberTrace OSINT Platform

Custom threat intelligence database for tracking malicious indicators
"""

import uuid
from datetime import datetime
from sqlalchemy import JSON, Index
from app import db


class ThreatIntel(db.Model):
    """Threat Intelligence model for tracking malicious indicators"""

    __tablename__ = 'threat_intel'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Threat Indicators (at least one must be present)
    phone_number = db.Column(db.String(50), nullable=True, index=True)
    email_address = db.Column(db.String(255), nullable=True, index=True)
    domain = db.Column(db.String(255), nullable=True, index=True)
    ip_address = db.Column(db.String(45), nullable=True, index=True)  # IPv6 support
    url = db.Column(db.Text, nullable=True)
    crypto_address = db.Column(db.String(255), nullable=True, index=True)
    username = db.Column(db.String(255), nullable=True, index=True)

    # Threat Classification
    threat_type = db.Column(
        db.Enum('scam', 'fraud', 'phishing', 'malware', 'botnet', 'spam',
                'identity_theft', 'ransomware', 'other', name='threat_types'),
        nullable=False,
        default='scam',
        index=True
    )

    threat_category = db.Column(db.String(100), nullable=True)
    # e.g., "Nigerian Prince Scam", "Banking Trojan", "Mobile Money Fraud"

    severity = db.Column(
        db.Enum('low', 'medium', 'high', 'critical', name='severity_levels'),
        nullable=False,
        default='medium',
        index=True
    )

    # Confidence & Validation
    confidence_score = db.Column(db.Integer, nullable=False, default=50)
    # 0-100 scale: 0-30=Low, 31-60=Medium, 61-85=High, 86-100=Verified

    status = db.Column(
        db.Enum('active', 'inactive', 'investigating', 'false_positive', name='threat_status'),
        nullable=False,
        default='active',
        index=True
    )

    verified = db.Column(db.Boolean, default=False, nullable=False)
    # True if verified by investigator or multiple reports

    # Source Information
    source = db.Column(
        db.Enum('case_investigation', 'public_report', 'partner_agency',
                'external_feed', 'automated_detection', name='threat_sources'),
        nullable=False,
        default='public_report'
    )

    source_details = db.Column(JSON, nullable=True)
    # e.g., {"case_number": "ZPS-2025-0001"} or {"reporter_name": "John Doe"}

    case_id = db.Column(db.String(36), db.ForeignKey('cases.id'), nullable=True, index=True)
    # Link to case if from investigation

    reported_by_user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True)
    # If reported by police officer

    # Threat Details
    description = db.Column(db.Text, nullable=True)
    # Human-readable description of the threat

    tags = db.Column(JSON, default=list)
    # Array of tags for searching: ["mobile_money", "MTN", "airtel"]

    affected_victims = db.Column(db.Integer, default=0)
    # Number of known victims

    financial_loss = db.Column(db.Float, default=0.0)
    # Total financial loss in ZMW

    # Activity Tracking
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    report_count = db.Column(db.Integer, default=1, nullable=False)
    # Number of times this indicator has been reported

    # External Intelligence
    external_references = db.Column(JSON, default=list)
    # Array of references to external threat intel sources
    # e.g., [{"source": "AlienVault OTX", "pulse_id": "abc123", "url": "..."}]

    # Geographic Information
    country_code = db.Column(db.String(2), nullable=True)  # ISO country code
    region = db.Column(db.String(100), nullable=True)  # Province/State
    city = db.Column(db.String(100), nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    case = db.relationship('Case', backref='threat_indicators', foreign_keys=[case_id])
    reported_by = db.relationship('User', backref='threat_reports', foreign_keys=[reported_by_user_id])

    # Indexes for performance
    __table_args__ = (
        Index('idx_threat_active', 'status', 'threat_type'),
        Index('idx_threat_severity', 'severity', 'verified'),
        Index('idx_threat_dates', 'first_seen', 'last_seen'),
    )

    def __repr__(self):
        indicator = (self.phone_number or self.email_address or self.domain or
                    self.ip_address or self.url or 'Unknown')
        return f'<ThreatIntel {self.threat_type}: {indicator}>'

    def get_primary_indicator(self):
        """Get the primary threat indicator"""
        if self.phone_number:
            return {'type': 'phone_number', 'value': self.phone_number}
        elif self.email_address:
            return {'type': 'email_address', 'value': self.email_address}
        elif self.domain:
            return {'type': 'domain', 'value': self.domain}
        elif self.ip_address:
            return {'type': 'ip_address', 'value': self.ip_address}
        elif self.url:
            return {'type': 'url', 'value': self.url}
        elif self.crypto_address:
            return {'type': 'crypto_address', 'value': self.crypto_address}
        elif self.username:
            return {'type': 'username', 'value': self.username}
        return {'type': 'unknown', 'value': None}

    def increment_report_count(self):
        """Increment report count and update last_seen"""
        self.report_count += 1
        self.last_seen = datetime.utcnow()

        # Auto-increase confidence with more reports
        if self.report_count >= 10:
            self.confidence_score = min(95, self.confidence_score + 5)
        elif self.report_count >= 5:
            self.confidence_score = min(85, self.confidence_score + 3)
        elif self.report_count >= 3:
            self.confidence_score = min(75, self.confidence_score + 2)

        db.session.commit()

    def mark_verified(self, verified_by_user_id):
        """Mark threat as verified by investigator"""
        self.verified = True
        self.confidence_score = min(100, self.confidence_score + 20)
        self.status = 'active'
        if not self.source_details:
            self.source_details = {}
        self.source_details['verified_by'] = verified_by_user_id
        self.source_details['verified_at'] = datetime.utcnow().isoformat()
        db.session.commit()

    def mark_false_positive(self, reason=None):
        """Mark threat as false positive"""
        self.status = 'false_positive'
        self.confidence_score = 0
        if reason and not self.source_details:
            self.source_details = {}
        if reason:
            self.source_details['false_positive_reason'] = reason
        db.session.commit()

    def add_external_reference(self, source_name, reference_data):
        """
        Add external threat intelligence reference

        Args:
            source_name (str): Name of external source (e.g., 'AlienVault OTX')
            reference_data (dict): Reference information
        """
        if self.external_references is None:
            self.external_references = []

        reference = {
            'source': source_name,
            'data': reference_data,
            'added_at': datetime.utcnow().isoformat()
        }

        self.external_references.append(reference)

        # Increase confidence if found in external sources
        self.confidence_score = min(100, self.confidence_score + 10)

        db.session.commit()

    def add_tag(self, tag):
        """
        Add a tag to the threat

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
        Remove a tag from the threat

        Args:
            tag (str): Tag to remove
        """
        tag_lower = tag.lower().strip()
        if self.tags and tag_lower in self.tags:
            self.tags.remove(tag_lower)
            db.session.commit()

    def get_risk_level(self):
        """
        Calculate risk level based on multiple factors

        Returns:
            str: Risk level (low, medium, high, critical)
        """
        risk_score = 0

        # Factor 1: Confidence score
        risk_score += self.confidence_score * 0.3

        # Factor 2: Report count
        if self.report_count >= 10:
            risk_score += 30
        elif self.report_count >= 5:
            risk_score += 20
        elif self.report_count >= 3:
            risk_score += 10

        # Factor 3: Severity
        severity_scores = {'low': 0, 'medium': 10, 'high': 20, 'critical': 30}
        risk_score += severity_scores.get(self.severity, 0)

        # Factor 4: Verified status
        if self.verified:
            risk_score += 20

        # Factor 5: Financial loss
        if self.financial_loss > 100000:  # > 100K ZMW
            risk_score += 20
        elif self.financial_loss > 50000:
            risk_score += 10
        elif self.financial_loss > 10000:
            risk_score += 5

        # Determine risk level
        if risk_score >= 80:
            return 'critical'
        elif risk_score >= 60:
            return 'high'
        elif risk_score >= 40:
            return 'medium'
        else:
            return 'low'

    def to_dict(self, include_relationships=False):
        """
        Convert threat intelligence object to dictionary

        Args:
            include_relationships (bool): Include related data

        Returns:
            dict: Threat intelligence data
        """
        primary_indicator = self.get_primary_indicator()

        data = {
            'id': self.id,
            'primary_indicator': primary_indicator,
            'phone_number': self.phone_number,
            'email_address': self.email_address,
            'domain': self.domain,
            'ip_address': self.ip_address,
            'url': self.url,
            'crypto_address': self.crypto_address,
            'username': self.username,
            'threat_type': self.threat_type,
            'threat_category': self.threat_category,
            'severity': self.severity,
            'confidence_score': self.confidence_score,
            'status': self.status,
            'verified': self.verified,
            'source': self.source,
            'source_details': self.source_details,
            'description': self.description,
            'tags': self.tags or [],
            'affected_victims': self.affected_victims,
            'financial_loss': self.financial_loss,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'report_count': self.report_count,
            'external_references': self.external_references or [],
            'country_code': self.country_code,
            'region': self.region,
            'city': self.city,
            'risk_level': self.get_risk_level(),
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

        if include_relationships:
            if self.case:
                data['case'] = {
                    'id': self.case.id,
                    'case_number': self.case.case_number,
                    'title': self.case.title
                }
            if self.reported_by:
                data['reported_by'] = {
                    'id': self.reported_by.id,
                    'username': self.reported_by.username,
                    'full_name': self.reported_by.full_name
                }

        return data

    @staticmethod
    def find_by_indicator(indicator_type, indicator_value):
        """
        Find threat intelligence by indicator

        Args:
            indicator_type (str): Type of indicator (phone_number, email_address, etc.)
            indicator_value (str): Value to search for

        Returns:
            list: List of ThreatIntel objects
        """
        query_filters = {
            'phone_number': ThreatIntel.phone_number,
            'email_address': ThreatIntel.email_address,
            'domain': ThreatIntel.domain,
            'ip_address': ThreatIntel.ip_address,
            'crypto_address': ThreatIntel.crypto_address,
            'username': ThreatIntel.username
        }

        if indicator_type in query_filters:
            return ThreatIntel.query.filter(
                query_filters[indicator_type] == indicator_value
            ).filter(
                ThreatIntel.status.in_(['active', 'investigating'])
            ).all()

        return []

    @staticmethod
    def get_statistics():
        """
        Get threat intelligence statistics

        Returns:
            dict: Statistics
        """
        return {
            'total_threats': ThreatIntel.query.count(),
            'active_threats': ThreatIntel.query.filter_by(status='active').count(),
            'verified_threats': ThreatIntel.query.filter_by(verified=True).count(),
            'critical_threats': ThreatIntel.query.filter_by(severity='critical').count(),
            'total_reports': db.session.query(db.func.sum(ThreatIntel.report_count)).scalar() or 0,
            'total_financial_loss': db.session.query(db.func.sum(ThreatIntel.financial_loss)).scalar() or 0,
            'threats_by_type': dict(
                db.session.query(ThreatIntel.threat_type, db.func.count(ThreatIntel.id))
                .filter(ThreatIntel.status == 'active')
                .group_by(ThreatIntel.threat_type)
                .all()
            )
        }

    @property
    def days_active(self):
        """Calculate number of days threat has been active"""
        return (self.last_seen - self.first_seen).days

    @property
    def is_recent(self):
        """Check if threat was seen recently (within 30 days)"""
        days_since_last_seen = (datetime.utcnow() - self.last_seen).days
        return days_since_last_seen <= 30
