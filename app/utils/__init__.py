"""
Utility Modules
CyberTrace OSINT Platform - Zambia Police Service
"""

from app.utils.decorators import (
    login_required,
    permission_required,
    role_required,
    admin_required,
    terms_required,
    account_active_required,
    case_access_required
)

from app.utils.validators import (
    validate_email_address,
    validate_phone_number,
    validate_url,
    validate_domain,
    validate_ip_address,
    validate_username,
    validate_password_strength,
    validate_search_query,
    sanitize_input,
    sanitize_html
)

from app.utils.evidence_hasher import (
    calculate_file_hash,
    verify_file_integrity,
    get_file_metadata,
    generate_evidence_manifest
)

__all__ = [
    # Decorators
    'login_required',
    'permission_required',
    'role_required',
    'admin_required',
    'terms_required',
    'account_active_required',
    'case_access_required',

    # Validators
    'validate_email_address',
    'validate_phone_number',
    'validate_url',
    'validate_domain',
    'validate_ip_address',
    'validate_username',
    'validate_password_strength',
    'validate_search_query',
    'sanitize_input',
    'sanitize_html',

    # Evidence Hasher
    'calculate_file_hash',
    'verify_file_integrity',
    'get_file_metadata',
    'generate_evidence_manifest'
]
