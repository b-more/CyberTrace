"""
CyberTrace Configuration Module
Zambia Police Service OSINT Investigation Platform
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '..', '.env'))


class Config:
    """Base configuration class"""

    # Flask Core Settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production-min-32-chars'
    FLASK_APP = os.environ.get('FLASK_APP') or 'run.py'

    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://cybertrace_user:secure_password@localhost:5432/cybertrace_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,
        'pool_recycle': 3600,
        'pool_pre_ping': True,
        'max_overflow': 20
    }

    # Redis Configuration
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'

    # Celery Configuration
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL') or 'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND') or 'redis://localhost:6379/0'
    CELERY_TASK_SERIALIZER = 'json'
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_TIMEZONE = 'Africa/Lusaka'
    CELERY_ENABLE_UTC = True

    # Session Configuration
    # Using Flask's default secure cookie-based sessions
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = timedelta(
        seconds=int(os.environ.get('PERMANENT_SESSION_LIFETIME', 1800))
    )

    # Security Settings
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = os.environ.get('SESSION_COOKIE_HTTPONLY', 'True').lower() == 'true'
    SESSION_COOKIE_SAMESITE = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
    WTF_CSRF_ENABLED = os.environ.get('WTF_CSRF_ENABLED', 'True').lower() == 'true'
    WTF_CSRF_TIME_LIMIT = None  # CSRF tokens don't expire
    MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 5))
    LOCKOUT_DURATION = int(os.environ.get('LOCKOUT_DURATION', 900))  # seconds

    # Password Requirements
    PASSWORD_MIN_LENGTH = 12
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_NUMBERS = True
    PASSWORD_REQUIRE_SPECIAL = True
    BCRYPT_LOG_ROUNDS = 12

    # File Upload Configuration
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 52428800))  # 50MB
    UPLOAD_FOLDER = os.path.join(basedir, '..', 'instance', 'uploads')
    EVIDENCE_FOLDER = os.path.join(basedir, '..', 'instance', 'evidence')
    ALLOWED_EXTENSIONS = set(os.environ.get(
        'ALLOWED_EXTENSIONS',
        'jpg,jpeg,png,pdf,docx,txt,csv,json,xlsx,zip'
    ).split(','))

    # Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.path.join(basedir, '..', os.environ.get('LOG_FILE', 'logs/cybertrace.log'))
    AUDIT_LOG_FILE = os.path.join(basedir, '..', os.environ.get('AUDIT_LOG_FILE', 'logs/audit.log'))
    OSINT_LOG_FILE = os.path.join(basedir, '..', os.environ.get('OSINT_LOG_FILE', 'logs/osint.log'))

    # API Keys
    HIBP_API_KEY = os.environ.get('HIBP_API_KEY', '')
    SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    NUMVERIFY_API_KEY = os.environ.get('NUMVERIFY_API_KEY', '')
    OPENCAGE_API_KEY = os.environ.get('OPENCAGE_API_KEY', '')
    BLOCKCYPHER_API_KEY = os.environ.get('BLOCKCYPHER_API_KEY', '')
    ETHERSCAN_API_KEY = os.environ.get('ETHERSCAN_API_KEY', '')
    DEHASHED_EMAIL = os.environ.get('DEHASHED_EMAIL', '')
    DEHASHED_API_KEY = os.environ.get('DEHASHED_API_KEY', '')
    INTELX_API_KEY = os.environ.get('INTELX_API_KEY', '')
    BSCSCAN_API_KEY = os.environ.get('BSCSCAN_API_KEY', '')
    TRONSCAN_API_KEY = os.environ.get('TRONSCAN_API_KEY', '')

    # Threat Intelligence API Keys (mostly free)
    ALIENVAULT_OTX_API_KEY = os.environ.get('ALIENVAULT_OTX_API_KEY', '')
    ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
    # Abuse.ch services are free without API key
    # Cisco Talos is free without API key (web scraping/public API)

    # Email Configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'False').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'cybertrace@zambiapolice.gov.zm')

    # Application Settings
    APP_NAME = os.environ.get('APP_NAME', 'CyberTrace')
    ORGANIZATION = os.environ.get('ORGANIZATION', 'Zambia Police Service')
    TIMEZONE = os.environ.get('TIMEZONE', 'Africa/Lusaka')
    CASE_NUMBER_PREFIX = os.environ.get('CASE_NUMBER_PREFIX', 'ZPS')
    CASE_NUMBER_YEAR_FORMAT = os.environ.get('CASE_NUMBER_YEAR_FORMAT', '%Y')

    # Rate Limiting
    RATELIMIT_STORAGE_URL = os.environ.get('RATELIMIT_STORAGE_URL', 'redis://localhost:6379/1')
    RATELIMIT_DEFAULT = os.environ.get('RATELIMIT_DEFAULT', '200 per day;50 per hour')
    RATELIMIT_ENABLED = True

    # Cache Configuration
    CACHE_TYPE = os.environ.get('CACHE_TYPE', 'redis')
    CACHE_REDIS_URL = os.environ.get('CACHE_REDIS_URL', 'redis://localhost:6379/2')
    CACHE_DEFAULT_TIMEOUT = int(os.environ.get('CACHE_DEFAULT_TIMEOUT', 300))

    # Two-Factor Authentication
    ENABLE_2FA = os.environ.get('ENABLE_2FA', 'False').lower() == 'true'
    TOTP_ISSUER = os.environ.get('TOTP_ISSUER', 'CyberTrace ZPS')

    # Report Generation
    REPORT_WATERMARK = os.environ.get('REPORT_WATERMARK', 'CONFIDENTIAL - ZAMBIA POLICE SERVICE')
    REPORT_LOGO_PATH = os.path.join(
        basedir,
        'static',
        'img',
        os.environ.get('REPORT_LOGO_PATH', 'zps_logo.png').split('/')[-1]
    )

    # Data Retention Policy (in days)
    CASE_ARCHIVE_AFTER_DAYS = int(os.environ.get('CASE_ARCHIVE_AFTER_DAYS', 2555))  # ~7 years
    CASE_DELETE_AFTER_DAYS = int(os.environ.get('CASE_DELETE_AFTER_DAYS', 3650))  # 10 years
    AUDIT_LOG_RETENTION_DAYS = int(os.environ.get('AUDIT_LOG_RETENTION_DAYS', 2555))  # ~7 years

    # External Tool Paths
    HOLEHE_PATH = os.environ.get('HOLEHE_PATH', '/usr/local/bin/holehe')
    H8MAIL_PATH = os.environ.get('H8MAIL_PATH', '/usr/local/bin/h8mail')
    SHERLOCK_PATH = os.environ.get('SHERLOCK_PATH', '/usr/local/bin/sherlock')
    THEHARVESTER_PATH = os.environ.get('THEHARVESTER_PATH', '/usr/local/bin/theHarvester')
    SUBLIST3R_PATH = os.environ.get('SUBLIST3R_PATH', '/usr/local/bin/sublist3r')
    PHONEINFOGA_PATH = os.environ.get('PHONEINFOGA_PATH', '/usr/local/bin/phoneinfoga')
    EXIFTOOL_PATH = os.environ.get('EXIFTOOL_PATH', '/usr/bin/exiftool')

    # Feature Flags
    ENABLE_EMAIL_OSINT = os.environ.get('ENABLE_EMAIL_OSINT', 'True').lower() == 'true'
    ENABLE_PHONE_OSINT = os.environ.get('ENABLE_PHONE_OSINT', 'True').lower() == 'true'
    ENABLE_SOCIAL_MEDIA_OSINT = os.environ.get('ENABLE_SOCIAL_MEDIA_OSINT', 'True').lower() == 'true'
    ENABLE_DOMAIN_IP_OSINT = os.environ.get('ENABLE_DOMAIN_IP_OSINT', 'True').lower() == 'true'
    ENABLE_BREACH_CHECKER = os.environ.get('ENABLE_BREACH_CHECKER', 'True').lower() == 'true'
    ENABLE_CRYPTO_TRACER = os.environ.get('ENABLE_CRYPTO_TRACER', 'True').lower() == 'true'
    ENABLE_METADATA_EXTRACTOR = os.environ.get('ENABLE_METADATA_EXTRACTOR', 'True').lower() == 'true'
    ENABLE_GEOLOCATION = os.environ.get('ENABLE_GEOLOCATION', 'True').lower() == 'true'
    ENABLE_ASYNC_TASKS = os.environ.get('ENABLE_ASYNC_TASKS', 'True').lower() == 'true'
    ENABLE_API_ACCESS = os.environ.get('ENABLE_API_ACCESS', 'True').lower() == 'true'
    ENABLE_THREAT_INTELLIGENCE = os.environ.get('ENABLE_THREAT_INTELLIGENCE', 'True').lower() == 'true'
    ENABLE_FINANCIAL_TRACER = os.environ.get('ENABLE_FINANCIAL_TRACER', 'True').lower() == 'true'
    ENABLE_SIM_SWAP_DETECTION = os.environ.get('ENABLE_SIM_SWAP_DETECTION', 'True').lower() == 'true'
    ENABLE_MESSAGING_FORENSICS = os.environ.get('ENABLE_MESSAGING_FORENSICS', 'True').lower() == 'true'
    ENABLE_IMAGE_FORENSICS = os.environ.get('ENABLE_IMAGE_FORENSICS', 'True').lower() == 'true'
    ENABLE_SOCIAL_PRESERVATION = os.environ.get('ENABLE_SOCIAL_PRESERVATION', 'True').lower() == 'true'
    ENABLE_CORRELATION_ENGINE = os.environ.get('ENABLE_CORRELATION_ENGINE', 'True').lower() == 'true'
    ENABLE_ISP_REQUESTS = os.environ.get('ENABLE_ISP_REQUESTS', 'True').lower() == 'true'
    ENABLE_VICTIM_MANAGEMENT = os.environ.get('ENABLE_VICTIM_MANAGEMENT', 'True').lower() == 'true'
    ENABLE_ANALYTICS_DASHBOARD = os.environ.get('ENABLE_ANALYTICS_DASHBOARD', 'True').lower() == 'true'

    # Legal and Compliance
    REQUIRE_WARRANT_INFO = os.environ.get('REQUIRE_WARRANT_INFO', 'True').lower() == 'true'
    ENABLE_AUDIT_LOGGING = os.environ.get('ENABLE_AUDIT_LOGGING', 'True').lower() == 'true'
    DATA_SOVEREIGNTY_MODE = os.environ.get('DATA_SOVEREIGNTY_MODE', 'True').lower() == 'true'

    # API Rate Limits (requests per minute for external APIs)
    API_RATE_LIMITS = {
        'hibp': 1,  # 1 request per 1.5 seconds
        'shodan': 1,
        'virustotal': 4,
        'numverify': 10,
        'opencage': 1,
        'blockcypher': 3,
        'etherscan': 5,
        'alienvault_otx': 10,  # 10 requests per second (very generous)
        'abuseipdb': 17,  # 1000 per day free tier
        'urlhaus': 60,  # No official limit, be respectful
        'threatfox': 60  # No official limit, be respectful
    }

    # Threat Intelligence Settings
    THREAT_INTEL_CACHE_TIMEOUT = int(os.environ.get('THREAT_INTEL_CACHE_TIMEOUT', 3600))  # 1 hour
    THREAT_INTEL_AUTO_CHECK = os.environ.get('THREAT_INTEL_AUTO_CHECK', 'True').lower() == 'true'
    THREAT_INTEL_MIN_CONFIDENCE = int(os.environ.get('THREAT_INTEL_MIN_CONFIDENCE', 50))
    THREAT_INTEL_PUBLIC_REPORTING = os.environ.get('THREAT_INTEL_PUBLIC_REPORTING', 'True').lower() == 'true'

    @staticmethod
    def init_app(app):
        """Initialize application with configuration"""
        # Create required directories
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(Config.EVIDENCE_FOLDER, exist_ok=True)
        os.makedirs(os.path.dirname(Config.LOG_FILE), exist_ok=True)


class DevelopmentConfig(Config):
    """Development environment configuration"""
    DEBUG = True
    TESTING = False
    FLASK_ENV = 'development'
    SESSION_COOKIE_SECURE = False


class ProductionConfig(Config):
    """Production environment configuration"""
    DEBUG = False
    TESTING = False
    FLASK_ENV = 'production'
    SESSION_COOKIE_SECURE = True

    # Stricter security in production
    WTF_CSRF_SSL_STRICT = True

    @classmethod
    def init_app(cls, app):
        Config.init_app(app)

        # Log to syslog in production
        import logging
        from logging.handlers import SysLogHandler
        syslog_handler = SysLogHandler()
        syslog_handler.setLevel(logging.WARNING)
        app.logger.addHandler(syslog_handler)


class TestingConfig(Config):
    """Testing environment configuration"""
    TESTING = True
    DEBUG = True
    FLASK_ENV = 'testing'

    # Use in-memory SQLite for tests
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

    # Disable CSRF in tests
    WTF_CSRF_ENABLED = False

    # Faster password hashing for tests
    BCRYPT_LOG_ROUNDS = 4


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config(config_name=None):
    """Get configuration object based on environment"""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    return config.get(config_name, config['default'])
