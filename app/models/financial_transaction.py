"""
Financial Transaction Models
Zambia Police Service CyberTrace OSINT Platform

Handles financial transaction tracking, account analysis, and money flow mapping
"""

import uuid
from datetime import datetime
from sqlalchemy import JSON
from app import db


class FinancialTransaction(db.Model):
    """Model for tracking financial transactions in investigations"""

    __tablename__ = 'financial_transactions'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Foreign Keys
    case_id = db.Column(db.String(36), db.ForeignKey('cases.id'), nullable=False, index=True)
    investigation_id = db.Column(db.String(36), db.ForeignKey('investigations.id'), nullable=True)

    # Transaction Details
    transaction_type = db.Column(db.String(50), nullable=False)
    # mobile_money, bank_transfer, cash, crypto, other
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(10), nullable=False, default='ZMW')

    # Sender Information
    sender_account = db.Column(db.String(255), nullable=False)
    sender_name = db.Column(db.String(255), nullable=True)

    # Receiver Information
    receiver_account = db.Column(db.String(255), nullable=False)
    receiver_name = db.Column(db.String(255), nullable=True)

    # Provider and Reference
    provider = db.Column(db.String(100), nullable=False)
    reference_number = db.Column(db.String(255), nullable=False)
    transaction_date = db.Column(db.DateTime, nullable=False)

    # Analysis
    is_suspicious = db.Column(db.Boolean, default=False)
    mule_score = db.Column(db.Float, nullable=True)

    # Additional Data
    notes = db.Column(db.Text, nullable=True)
    raw_data = db.Column(JSON, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<FinancialTransaction {self.reference_number}: {self.amount} {self.currency}>'

    def to_dict(self):
        """Convert financial transaction object to dictionary"""
        return {
            'id': self.id,
            'case_id': self.case_id,
            'investigation_id': self.investigation_id,
            'transaction_type': self.transaction_type,
            'amount': self.amount,
            'currency': self.currency,
            'sender_account': self.sender_account,
            'sender_name': self.sender_name,
            'receiver_account': self.receiver_account,
            'receiver_name': self.receiver_name,
            'provider': self.provider,
            'reference_number': self.reference_number,
            'transaction_date': self.transaction_date.isoformat() if self.transaction_date else None,
            'is_suspicious': self.is_suspicious,
            'mule_score': self.mule_score,
            'notes': self.notes,
            'raw_data': self.raw_data,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class FinancialAccount(db.Model):
    """Model for tracking financial accounts linked to investigations"""

    __tablename__ = 'financial_accounts'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Foreign Keys
    case_id = db.Column(db.String(36), db.ForeignKey('cases.id'), nullable=False, index=True)

    # Account Details
    account_identifier = db.Column(db.String(255), nullable=False)
    account_type = db.Column(db.String(50), nullable=False)
    provider = db.Column(db.String(100), nullable=False)
    holder_name = db.Column(db.String(255), nullable=True)

    # Risk Analysis
    is_mule = db.Column(db.Boolean, default=False)
    risk_score = db.Column(db.Float, default=0)

    # Activity Summary
    transaction_count = db.Column(db.Integer, default=0)
    total_inflow = db.Column(db.Float, default=0)
    total_outflow = db.Column(db.Float, default=0)

    # Observation Period
    first_seen = db.Column(db.DateTime, nullable=True)
    last_seen = db.Column(db.DateTime, nullable=True)

    # Additional Data
    extra_metadata = db.Column(JSON, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<FinancialAccount {self.account_identifier} ({self.provider})>'

    def to_dict(self):
        """Convert financial account object to dictionary"""
        return {
            'id': self.id,
            'case_id': self.case_id,
            'account_identifier': self.account_identifier,
            'account_type': self.account_type,
            'provider': self.provider,
            'holder_name': self.holder_name,
            'is_mule': self.is_mule,
            'risk_score': self.risk_score,
            'transaction_count': self.transaction_count,
            'total_inflow': self.total_inflow,
            'total_outflow': self.total_outflow,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'extra_metadata': self.extra_metadata,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class TransactionFlow(db.Model):
    """Model for tracking aggregated transaction flows between accounts"""

    __tablename__ = 'transaction_flows'

    # Primary Key
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Foreign Keys
    case_id = db.Column(db.String(36), db.ForeignKey('cases.id'), nullable=False, index=True)
    source_account_id = db.Column(db.String(36), db.ForeignKey('financial_accounts.id'), nullable=False)
    destination_account_id = db.Column(db.String(36), db.ForeignKey('financial_accounts.id'), nullable=False)

    # Flow Summary
    total_amount = db.Column(db.Float, nullable=False)
    transaction_count = db.Column(db.Integer, nullable=False)
    first_transaction = db.Column(db.DateTime, nullable=True)
    last_transaction = db.Column(db.DateTime, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<TransactionFlow {self.source_account_id} -> {self.destination_account_id}: {self.total_amount}>'

    def to_dict(self):
        """Convert transaction flow object to dictionary"""
        return {
            'id': self.id,
            'case_id': self.case_id,
            'source_account_id': self.source_account_id,
            'destination_account_id': self.destination_account_id,
            'total_amount': self.total_amount,
            'transaction_count': self.transaction_count,
            'first_transaction': self.first_transaction.isoformat() if self.first_transaction else None,
            'last_transaction': self.last_transaction.isoformat() if self.last_transaction else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
