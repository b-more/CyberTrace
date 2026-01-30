"""
CyberTrace OSINT Platform
Zambia Police Service Investigations Team

Main application factory and initialization
"""

import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from redis import Redis

from app.config import get_config

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
migrate = Migrate()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)
cache = Cache()


def create_app(config_name=None):
    """
    Application factory pattern

    Args:
        config_name (str): Configuration name (development, production, testing)

    Returns:
        Flask: Configured Flask application instance
    """
    # Create Flask app instance
    app = Flask(__name__)

    # Load configuration
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')

    config_class = get_config(config_name)
    app.config.from_object(config_class)

    # Initialize configuration
    config_class.init_app(app)

    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)

    # Use simple cache if Redis is not available
    try:
        cache.init_app(app, config={
            'CACHE_TYPE': 'simple',
            'CACHE_DEFAULT_TIMEOUT': app.config['CACHE_DEFAULT_TIMEOUT']
        })
    except Exception as e:
        app.logger.warning(f'Cache initialization failed, using NullCache: {e}')
        cache.init_app(app, config={'CACHE_TYPE': 'null'})

    # Configure login manager
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    login_manager.session_protection = 'strong'

    # User loader callback
    @login_manager.user_loader
    def load_user(user_id):
        from app.models.user import User
        return User.query.get(user_id)

    # Register blueprints
    register_blueprints(app)

    # Configure logging
    configure_logging(app)

    # Register error handlers
    register_error_handlers(app)

    # Register context processors
    register_context_processors(app)

    # Register before/after request handlers
    register_request_handlers(app)

    # Log application startup
    app.logger.info(f'CyberTrace OSINT Platform starting in {config_name} mode')

    return app


def register_blueprints(app):
    """Register Flask blueprints"""
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.cases import cases_bp
    from app.routes.investigations import investigations_bp
    from app.routes.api import api_bp
    from app.routes.admin import admin_bp
    from app.routes.threat_intel import threat_intel_bp
    from app.routes.domain_ip import domain_ip_bp
    from app.routes.crypto import crypto_bp
    from app.routes.financial import financial_bp
    from app.routes.sim_swap import sim_swap_bp
    from app.routes.messaging import messaging_bp
    from app.routes.forensics import forensics_bp
    from app.routes.social_preservation import social_pres_bp
    from app.routes.correlation import correlation_bp
    from app.routes.isp_requests import isp_requests_bp
    from app.routes.victims import victims_bp
    from app.routes.analytics import analytics_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    app.register_blueprint(cases_bp, url_prefix='/cases')
    app.register_blueprint(investigations_bp, url_prefix='/investigations')
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(threat_intel_bp)
    app.register_blueprint(domain_ip_bp, url_prefix='/investigations')
    app.register_blueprint(crypto_bp, url_prefix='/investigations/crypto')
    app.register_blueprint(financial_bp, url_prefix='/investigations/financial')
    app.register_blueprint(sim_swap_bp, url_prefix='/investigations/sim-swap')
    app.register_blueprint(messaging_bp, url_prefix='/investigations/messaging')
    app.register_blueprint(forensics_bp, url_prefix='/investigations/forensics')
    app.register_blueprint(social_pres_bp, url_prefix='/investigations/social-preservation')
    app.register_blueprint(correlation_bp, url_prefix='/intelligence/correlation')
    app.register_blueprint(isp_requests_bp, url_prefix='/requests')
    app.register_blueprint(victims_bp, url_prefix='/victims')
    app.register_blueprint(analytics_bp, url_prefix='/analytics')

    # Register root route
    @app.route('/')
    def index():
        """Redirect root to login page"""
        from flask import redirect, url_for
        from flask_login import current_user

        # If user is authenticated, redirect to dashboard
        if current_user.is_authenticated:
            return redirect(url_for('dashboard.index'))
        # Otherwise redirect to login
        return redirect(url_for('auth.login'))


def configure_logging(app):
    """Configure application logging"""
    if not app.debug and not app.testing:
        # Ensure log directory exists
        log_dir = os.path.dirname(app.config['LOG_FILE'])
        os.makedirs(log_dir, exist_ok=True)

        # Application log
        file_handler = RotatingFileHandler(
            app.config['LOG_FILE'],
            maxBytes=10485760,  # 10MB
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
        ))
        file_handler.setLevel(getattr(logging, app.config['LOG_LEVEL']))
        app.logger.addHandler(file_handler)

        # Audit log (separate file)
        audit_handler = RotatingFileHandler(
            app.config['AUDIT_LOG_FILE'],
            maxBytes=10485760,  # 10MB
            backupCount=50  # Keep more audit logs
        )
        audit_handler.setFormatter(logging.Formatter(
            '[%(asctime)s] %(message)s'
        ))
        audit_handler.setLevel(logging.INFO)

        # Create audit logger
        audit_logger = logging.getLogger('audit')
        audit_logger.setLevel(logging.INFO)
        audit_logger.addHandler(audit_handler)

        # OSINT log (separate file)
        osint_handler = RotatingFileHandler(
            app.config['OSINT_LOG_FILE'],
            maxBytes=10485760,  # 10MB
            backupCount=20
        )
        osint_handler.setFormatter(logging.Formatter(
            '[%(asctime)s] %(levelname)s: %(message)s'
        ))
        osint_handler.setLevel(logging.INFO)

        # Create OSINT logger
        osint_logger = logging.getLogger('osint')
        osint_logger.setLevel(logging.INFO)
        osint_logger.addHandler(osint_handler)

        app.logger.setLevel(getattr(logging, app.config['LOG_LEVEL']))
        app.logger.info('CyberTrace logging configured')


def register_error_handlers(app):
    """Register error handlers"""

    @app.errorhandler(403)
    def forbidden(e):
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(e):
        db.session.rollback()
        app.logger.error(f'Internal server error: {str(e)}')
        return render_template('errors/500.html'), 500

    @app.errorhandler(413)
    def request_entity_too_large(e):
        return render_template('errors/413.html'), 413

    @app.errorhandler(429)
    def ratelimit_handler(e):
        return render_template('errors/429.html'), 429


def register_context_processors(app):
    """Register context processors for templates"""

    @app.context_processor
    def inject_app_info():
        return {
            'app_name': app.config['APP_NAME'],
            'organization': app.config['ORGANIZATION'],
            'enable_2fa': app.config['ENABLE_2FA']
        }

    @app.context_processor
    def inject_feature_flags():
        return {
            'features': {
                'email_osint': app.config['ENABLE_EMAIL_OSINT'],
                'phone_osint': app.config['ENABLE_PHONE_OSINT'],
                'social_media_osint': app.config['ENABLE_SOCIAL_MEDIA_OSINT'],
                'domain_ip_osint': app.config['ENABLE_DOMAIN_IP_OSINT'],
                'breach_checker': app.config['ENABLE_BREACH_CHECKER'],
                'crypto_tracer': app.config['ENABLE_CRYPTO_TRACER'],
                'metadata_extractor': app.config['ENABLE_METADATA_EXTRACTOR'],
                'geolocation': app.config['ENABLE_GEOLOCATION'],
                'financial_tracer': app.config['ENABLE_FINANCIAL_TRACER'],
                'sim_swap_detection': app.config['ENABLE_SIM_SWAP_DETECTION'],
                'messaging_forensics': app.config['ENABLE_MESSAGING_FORENSICS'],
                'image_forensics': app.config['ENABLE_IMAGE_FORENSICS'],
                'social_preservation': app.config['ENABLE_SOCIAL_PRESERVATION'],
                'correlation_engine': app.config['ENABLE_CORRELATION_ENGINE'],
                'isp_requests': app.config['ENABLE_ISP_REQUESTS'],
                'victim_management': app.config['ENABLE_VICTIM_MANAGEMENT'],
                'analytics_dashboard': app.config['ENABLE_ANALYTICS_DASHBOARD'],
            }
        }


def register_request_handlers(app):
    """Register before/after request handlers"""

    @app.before_request
    def log_request_info():
        """Log request information for audit purposes"""
        if app.config['ENABLE_AUDIT_LOGGING']:
            from flask_login import current_user
            audit_logger = logging.getLogger('audit')

            # Don't log static file requests
            if not request.path.startswith('/static'):
                user_info = f"User: {current_user.badge_number}" if current_user.is_authenticated else "User: Anonymous"
                audit_logger.info(
                    f"{user_info} | IP: {request.remote_addr} | "
                    f"Method: {request.method} | Path: {request.path}"
                )

    @app.after_request
    def security_headers(response):
        """Add security headers to all responses"""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        # Content Security Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://code.jquery.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://cdn.jsdelivr.net https://code.jquery.com;"
        )
        response.headers['Content-Security-Policy'] = csp

        return response


def init_db():
    """Initialize database - create all tables"""
    from app.models import user, case, investigation, evidence, audit_log, threat_intel
    from app.models import financial_transaction, sim_swap, messaging_forensics
    from app.models import image_forensics, social_preservation, correlation
    from app.models import isp_request, victim
    db.create_all()


def create_admin_user():
    """Create default admin user if none exists"""
    from app.models.user import User

    admin = User.query.filter_by(role='admin').first()
    if not admin:
        admin = User(
            badge_number='ZPS0001',
            username='admin',
            email='admin@zambiapolice.gov.zm',
            full_name='System Administrator',
            rank='Superintendent',
            department='Cybercrime Unit',
            role='admin',
            is_active=True
        )
        admin.set_password('Admin@123456')
        db.session.add(admin)
        db.session.commit()
        print("Admin user created successfully")
        print("Badge Number: ZPS0001")
        print("Password: Admin@123456")
        print("IMPORTANT: Change this password immediately after first login!")
