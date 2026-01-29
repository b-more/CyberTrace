"""
Input Validators
CyberTrace OSINT Platform - Zambia Police Service

Input validation and sanitization functions
"""

import re
import validators as v
from email_validator import validate_email, EmailNotValidError
import phonenumbers
from werkzeug.utils import secure_filename
import bleach


def validate_email_address(email):
    """
    Validate email address format

    Args:
        email (str): Email address to validate

    Returns:
        tuple: (bool, str, str) - (is_valid, normalized_email, error_message)
    """
    try:
        # Validate and normalize email
        validation = validate_email(email, check_deliverability=False)
        return True, validation.normalized, None
    except EmailNotValidError as e:
        return False, email, str(e)


def validate_phone_number(phone, country_code='ZM'):
    """
    Validate phone number

    Args:
        phone (str): Phone number to validate
        country_code (str): Country code (default: ZM for Zambia)

    Returns:
        tuple: (bool, str, str) - (is_valid, formatted_number, error_message)
    """
    try:
        parsed = phonenumbers.parse(phone, country_code)
        if phonenumbers.is_valid_number(parsed):
            formatted = phonenumbers.format_number(
                parsed,
                phonenumbers.PhoneNumberFormat.INTERNATIONAL
            )
            return True, formatted, None
        else:
            return False, phone, "Invalid phone number"
    except phonenumbers.NumberParseException as e:
        return False, phone, str(e)


def validate_url(url):
    """
    Validate URL format

    Args:
        url (str): URL to validate

    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    if v.url(url):
        return True, None
    return False, "Invalid URL format"


def validate_domain(domain):
    """
    Validate domain name

    Args:
        domain (str): Domain to validate

    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    if v.domain(domain):
        return True, None
    return False, "Invalid domain name"


def validate_ip_address(ip):
    """
    Validate IP address (IPv4 or IPv6)

    Args:
        ip (str): IP address to validate

    Returns:
        tuple: (bool, str, str) - (is_valid, ip_version, error_message)
    """
    if v.ipv4(ip):
        return True, 'IPv4', None
    elif v.ipv6(ip):
        return True, 'IPv6', None
    return False, None, "Invalid IP address"


def validate_bitcoin_address(address):
    """
    Validate Bitcoin address format

    Args:
        address (str): Bitcoin address to validate

    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    # Bitcoin address regex (basic validation)
    pattern = r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$'
    if re.match(pattern, address):
        return True, None
    return False, "Invalid Bitcoin address format"


def validate_ethereum_address(address):
    """
    Validate Ethereum address format

    Args:
        address (str): Ethereum address to validate

    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    # Ethereum address regex
    pattern = r'^0x[a-fA-F0-9]{40}$'
    if re.match(pattern, address):
        return True, None
    return False, "Invalid Ethereum address format"


def validate_username(username):
    """
    Validate username format

    Args:
        username (str): Username to validate

    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    # Username: 3-50 characters, alphanumeric, underscore, hyphen
    pattern = r'^[a-zA-Z0-9_-]{3,50}$'
    if re.match(pattern, username):
        return True, None
    return False, "Username must be 3-50 characters (letters, numbers, _, -)"


def validate_badge_number(badge_number):
    """
    Validate ZPS badge number format

    Args:
        badge_number (str): Badge number to validate

    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    # Badge format: ZPS followed by 4-6 digits
    pattern = r'^ZPS\d{4,6}$'
    if re.match(pattern, badge_number.upper()):
        return True, None
    return False, "Badge number must be in format ZPS#### (e.g., ZPS0001)"


def validate_case_number(case_number):
    """
    Validate case number format

    Args:
        case_number (str): Case number to validate

    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    # Case format: ZPS-YYYY-XXXX
    pattern = r'^ZPS-\d{4}-\d{4}$'
    if re.match(pattern, case_number.upper()):
        return True, None
    return False, "Case number must be in format ZPS-YYYY-XXXX"


def validate_file_upload(filename, allowed_extensions=None):
    """
    Validate file upload

    Args:
        filename (str): Uploaded filename
        allowed_extensions (set): Set of allowed extensions

    Returns:
        tuple: (bool, str, str) - (is_valid, safe_filename, error_message)
    """
    if not filename:
        return False, None, "No filename provided"

    # Secure the filename
    safe_name = secure_filename(filename)

    if not safe_name:
        return False, None, "Invalid filename"

    # Check extension
    if allowed_extensions:
        ext = safe_name.rsplit('.', 1)[1].lower() if '.' in safe_name else ''
        if ext not in allowed_extensions:
            return False, None, f"File type .{ext} not allowed. Allowed: {', '.join(allowed_extensions)}"

    return True, safe_name, None


def sanitize_html(html_content):
    """
    Sanitize HTML content to prevent XSS

    Args:
        html_content (str): HTML content to sanitize

    Returns:
        str: Sanitized HTML
    """
    allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'ul', 'ol', 'li', 'a', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6']
    allowed_attributes = {'a': ['href', 'title']}

    return bleach.clean(
        html_content,
        tags=allowed_tags,
        attributes=allowed_attributes,
        strip=True
    )


def sanitize_input(text, max_length=None):
    """
    Sanitize text input

    Args:
        text (str): Text to sanitize
        max_length (int): Maximum allowed length

    Returns:
        str: Sanitized text
    """
    if not text:
        return ""

    # Strip whitespace
    text = text.strip()

    # Limit length
    if max_length and len(text) > max_length:
        text = text[:max_length]

    # Remove any HTML tags
    text = bleach.clean(text, tags=[], strip=True)

    return text


def validate_password_strength(password):
    """
    Validate password strength according to ZPS requirements

    Args:
        password (str): Password to validate

    Returns:
        tuple: (bool, list) - (is_valid, list_of_errors)
    """
    errors = []

    if len(password) < 12:
        errors.append("Password must be at least 12 characters long")

    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")

    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")

    if not re.search(r'\d', password):
        errors.append("Password must contain at least one number")

    if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
        errors.append("Password must contain at least one special character")

    # Check for common weak passwords
    weak_passwords = ['password', 'Password123!', 'Admin@123', '12345678', 'qwerty']
    if password in weak_passwords:
        errors.append("This password is too common. Please choose a stronger password")

    is_valid = len(errors) == 0
    return is_valid, errors


def validate_search_query(query, query_type):
    """
    Validate search query based on type

    Args:
        query (str): Search query
        query_type (str): Type of search (email, phone, username, domain, ip, crypto)

    Returns:
        tuple: (bool, str, str) - (is_valid, normalized_query, error_message)
    """
    query = query.strip()

    if not query:
        return False, None, "Search query cannot be empty"

    if query_type == 'email':
        return validate_email_address(query)
    elif query_type == 'phone':
        return validate_phone_number(query)
    elif query_type == 'username':
        is_valid, error = validate_username(query)
        return is_valid, query, error
    elif query_type == 'domain':
        is_valid, error = validate_domain(query)
        return is_valid, query, error
    elif query_type == 'ip':
        is_valid, version, error = validate_ip_address(query)
        return is_valid, query, error
    elif query_type == 'bitcoin':
        is_valid, error = validate_bitcoin_address(query)
        return is_valid, query, error
    elif query_type == 'ethereum':
        is_valid, error = validate_ethereum_address(query)
        return is_valid, query, error
    else:
        # Generic validation
        sanitized = sanitize_input(query, max_length=255)
        return True, sanitized, None


def validate_date_range(start_date, end_date):
    """
    Validate date range

    Args:
        start_date (datetime): Start date
        end_date (datetime): End date

    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    if start_date and end_date:
        if start_date > end_date:
            return False, "Start date must be before end date"

    return True, None


def validate_json_field(data, required_fields=None):
    """
    Validate JSON data structure

    Args:
        data (dict): JSON data to validate
        required_fields (list): List of required field names

    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    if not isinstance(data, dict):
        return False, "Invalid JSON structure"

    if required_fields:
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return False, f"Missing required fields: {', '.join(missing_fields)}"

    return True, None
